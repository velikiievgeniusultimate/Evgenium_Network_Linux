#!/bin/bash
# Build an autonomous x86_64 userspace IPsec runtime, without installing anything system-wide.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=${EVGENIUM_BUILD_DIR:-/tmp/evgenium-userspace-build}
jobs=${EVGENIUM_BUILD_JOBS:-8}
version=6.1.0-openssl3.5.9-musl1.2.6-1
mkdir -p "$work" "$repo/dist"
fetch() {
 local name=$1 url=$2 digest=$3
 if ! test -f "$work/$name"; then curl --fail --location --connect-timeout 15 --max-time 180 "$url" -o "$work/$name"; fi
 printf '%s  %s\n' "$digest" "$work/$name" | sha256sum -c -
}
fetch strongswan-6.1.0.tar.bz2 https://download.strongswan.org/strongswan-6.1.0.tar.bz2 fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4
fetch openssl-3.5.9.tar.gz https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
fetch musl-1.2.6.tar.gz https://musl.libc.org/releases/musl-1.2.6.tar.gz d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a
if ! test -x "$work/musl-static/bin/musl-gcc"; then
 tar -xzf "$work/musl-1.2.6.tar.gz" -C "$work"
 (cd "$work/musl-1.2.6"; ./configure --prefix="$work/musl-static"; make -j"$jobs"; make install)
fi
# Only Linux UAPI headers, never glibc headers, are shared with the musl toolchain.
for name in linux asm asm-generic; do
 test -e "$work/musl-static/include/$name" || ln -s "/usr/include/$name" "$work/musl-static/include/$name"
done
mkdir -p "$work/musl-sources"
if ! test -f "$work/openssl-musl/lib/libcrypto.a"; then
 tar -xzf "$work/openssl-3.5.9.tar.gz" -C "$work/musl-sources"
 (cd "$work/musl-sources/openssl-3.5.9";
  CC="$work/musl-static/bin/musl-gcc" ./Configure linux-x86_64 no-shared no-module no-tests --prefix="$work/openssl-musl" --libdir=lib
  make -j"$jobs" build_libs
  make install_dev)
fi
tar -xjf "$work/strongswan-6.1.0.tar.bz2" -C "$work/musl-sources"
(cd "$work/musl-sources/strongswan-6.1.0";
 ./configure --prefix=/opt/vpn-manager/ikev2-userspace --sysconfdir=/etc/vpn-manager/starfive --with-piddir=/run/evgenium-ikev2 \
 --disable-defaults --enable-ikev2 --enable-charon --enable-swanctl --enable-vici --enable-kernel-netlink --enable-kernel-libipsec --enable-libipsec \
 --enable-socket-default --enable-openssl --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-x509 --enable-pubkey --enable-constraints \
 --enable-revocation --enable-random --enable-nonce --enable-eap-identity --enable-eap-tls --enable-monolithic --enable-static --disable-shared \
 CC="$work/musl-static/bin/musl-gcc" CFLAGS='-O2 -fstack-protector-strong' \
 CPPFLAGS="-I$work/openssl-musl/include" LDFLAGS="-static -L$work/openssl-musl/lib"
 make -j"$jobs" LDFLAGS="-all-static -L$work/openssl-musl/lib")
python3 - "$work" "$repo" "$version" <<'PY'
from pathlib import Path
import sys,json,hashlib,tarfile,io,gzip,subprocess
work,repo=map(Path,sys.argv[1:3]);version=sys.argv[3]
source=work/'musl-sources/strongswan-6.1.0'
files={}
for name,path in [('charon',source/'src/charon/charon'),('swanctl',source/'src/swanctl/swanctl')]:
 subprocess.run(['strip',str(path)],check=True)
 headers=subprocess.check_output(['readelf','-l',str(path)],text=True)
 assert 'INTERP' not in headers,'runtime is not fully static'
 files[name]=path.read_bytes()
files['LICENSE.strongswan']=(source/'COPYING').read_bytes()
files['LICENSE.openssl']=(work/'musl-sources/openssl-3.5.9/LICENSE.txt').read_bytes()
files['LICENSE.musl']=(work/'musl-1.2.6/COPYRIGHT').read_bytes()
files['BUILD.json']=json.dumps({'version':version,'architecture':'x86_64','strongswan':'6.1.0','openssl':'3.5.9','musl':'1.2.6','static':True,'components_sha256':{n:hashlib.sha256(data).hexdigest() for n,data in files.items()},'source_release':'v0.2.23'},sort_keys=True).encode()
out=repo/'dist'/('starfive-userspace-x86_64-'+version+'.tar.gz')
with out.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as tf:
 for name,data in sorted(files.items()):
  info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755 if name in ('charon','swanctl') else 0o644
  tf.addfile(info,io.BytesIO(data))
(out.with_name(out.name+'.sha256')).write_text(hashlib.sha256(out.read_bytes()).hexdigest()+'  '+out.name+'\n')
print('RUNTIME',out,hashlib.sha256(out.read_bytes()).hexdigest())
PY
