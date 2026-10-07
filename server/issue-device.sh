#!/bin/bash
# Run as root on StarFive. Output is a secret per-device JSON, never commit it.
set -euo pipefail
umask 077
pki=/root/evgenium-ikev2-pki
identity="device-$(openssl rand -hex 12)"
folder="$pki/$identity"
mkdir -m 700 "$folder"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$folder/key.pem" 2>/dev/null
openssl req -new -key "$folder/key.pem" -subj "/CN=$identity" -out "$folder/client.csr"
cat > "$folder/client.ext" <<EOF
[client]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:$identity
EOF
openssl ca -batch -notext -config "$pki/ca.conf" -extensions client -extfile "$folder/client.ext" -in "$folder/client.csr" -out "$folder/cert.pem"
python3 - "$folder" "$identity" <<'PY'
import json,sys
from pathlib import Path
folder=Path(sys.argv[1])
p={'schema':1,'server':'109.194.67.159','identity':sys.argv[2],
   'ca':Path('/root/evgenium-ikev2-pki/ca.pem').read_text(),
   'certificate':(folder/'cert.pem').read_text(),'private_key':(folder/'key.pem').read_text()}
(folder/'profile.json').write_text(json.dumps(p,indent=2)+'\n')
PY
printf '%s\n' "$folder/profile.json"
