wireguard.js is an unmodified copy of the official WireGuard tools browser key generator.
Upstream: https://git.zx2c4.com/wireguard-tools/
Mirror commit: a998407747005ea7e4e0258d96f105c97241e1d3
Path: contrib/keygen-html/wireguard.js
SHA-256: 197707c31758bb457031011ef7cb960f95481f8fc1228db62841333561dfd2cf
License: GPL-2.0; copyright Jason A. Donenfeld. See COPYING.wireguard.

The script uses crypto.getRandomValues and its upstream Curve25519 implementation.
It does not require experimental WebCrypto X25519 browser support or a CDN.
Private keys stay in browser memory and in the downloaded WireGuard configuration.
