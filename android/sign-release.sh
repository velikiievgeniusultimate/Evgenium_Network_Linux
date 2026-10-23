#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: sign-release.sh unsigned.apk signed.apk AndroidSDK' >&2; exit 2; }
: "${EVG_SIGNING_DIR:?Set EVG_SIGNING_DIR to the private signing directory}"
key_dir=$EVG_SIGNING_DIR
tools="$3/build-tools/36.0.0"
tmp=$(mktemp --suffix=.apk)
trap 'rm -f "$tmp"' EXIT
"$tools/zipalign" -P 16 -f 4 "$1" "$tmp"
"$tools/apksigner" sign --ks "$key_dir/release.p12" --ks-key-alias evgenium --ks-pass "file:$key_dir/store-password.txt" --out "$2" "$tmp"
"$tools/apksigner" verify "$2"
"$tools/zipalign" -c -P 16 4 "$2"
