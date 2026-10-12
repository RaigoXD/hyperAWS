# Vendored third-party code

| File | Source | SHA-256 |
|---|---|---|
| `three.module.min.js` | npm `three@0.170.0` → `build/three.module.min.js` | `08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7` |
| `LICENSE-three.txt` | npm `three@0.170.0` → `LICENSE` (MIT) | `4c40a1ef62450b857c3b2aaf294936304cd552d965fbcd9d32d4c5bcf4ba4454` |

Tarball integrity (as published on registry.npmjs.org): `sha512-FQK+LEpYc0fBD+J8g6oSEyyNzjp+Q7Ks1C568WWaoMRLW+TkNNWmenWeGgJjV105Gd+p/2ql1ZcjYvNiPZBhuQ==`.
Imported 2026-10-10 with `npm pack three@0.170.0 --ignore-scripts` and
`python3 tools/vendor_three.py import three-0.170.0.tgz` (reads only the two files above).

The files are kept byte-for-byte. `analyzer/vendor.py` pins their hashes; the build (`report.py`) refuses to
inline them if anything changed, and `audit-readonly` flags any unpinned file in this folder. At build time the
ES module is wrapped into a lazily-called classic-script factory (`window.AWSA_THREE_FACTORY`).

Why r170: it is the last release whose module build is a single self-contained file (r171 split it into
`three.core.js` + `three.module.js`). Upgrading requires changing the pins and re-running the import.
