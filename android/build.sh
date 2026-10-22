#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
: "${ANDROID_HOME:?Set ANDROID_HOME to an Android SDK with platform 36 and NDK 27.3.13750724}"
build_dir=${EVG_ANDROID_BUILD:-"$here/.build"}
mkdir -p "$build_dir"
fetch_git() {
  local url=$1 directory=$2 tag=$3 commit=$4
  if [[ ! -d "$directory/.git" ]]; then git clone --depth 1 --branch "$tag" "$url" "$directory"; fi
  [[ $(git -C "$directory" rev-parse HEAD) == "$commit" ]] || { echo 'Source revision mismatch' >&2; exit 1; }
}
fetch_git https://github.com/strongswan/strongswan.git "$build_dir/strongswan" android-2.6.2 5e410617d4c9d06cff5b860a26f51ee91aa73228
fetch_git https://github.com/openssl/openssl.git "$build_dir/openssl" openssl-3.5.9 45e844fa2a14ec92d146bd8f5778ac130b6625fb
archive="$build_dir/strongswan-6.0.3.tar.bz2"
if [[ ! -f "$archive" ]]; then curl -fL --retry 2 https://download.strongswan.org/strongswan-6.0.3.tar.bz2 -o "$archive"; fi
printf '%s  %s\n' 288f2111f5c9f6ec85fc08fa835bf39232f5c4044969bb4de7b4335163b1efa9 "$archive" | sha256sum -c -
if [[ ! -d "$build_dir/strongswan-6.0.3" ]]; then tar -xjf "$archive" -C "$build_dir"; fi
python3 "$here/prepare.py" "$build_dir/strongswan" --sdk "$ANDROID_HOME"
export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/27.3.13750724" OPENSSL_SRC="$build_dir/openssl" NO_DOCKER=1 MIN_SDK=26
export ABIS=${EVG_ANDROID_ABIS:-"arm64-v8a armeabi-v7a x86_64"}
missing_crypto=false
for abi in $ABIS; do
  [[ -f "$build_dir/strongswan/src/frontends/android/app/src/main/jni/openssl/$abi/libcrypto.a" ]] || missing_crypto=true
done
if $missing_crypto; then
 bash "$build_dir/strongswan/src/frontends/android/openssl/build.sh"
fi
cd "$build_dir/strongswan/src/frontends/android"
if [[ ${EVG_ANDROID_RELEASE:-0} == 1 ]]; then
  ./gradlew assembleRelease testReleaseUnitTest
  "$here/sign-release.sh" app/build/outputs/apk/release/app-release-unsigned.apk "$build_dir/Evgenium-Android.apk" "$ANDROID_HOME"
else
  ./gradlew assembleDebug testDebugUnitTest
fi
