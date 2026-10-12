#!/usr/bin/env python3
"""Vendor three.js into viewer/vendor/ from an npm tarball you downloaded yourself. Makes NO network requests.

  npm pack three@0.170.0 --ignore-scripts          # in an empty scratch folder; npm checks the registry's sha512
  python3 tools/vendor_three.py import three-0.170.0.tgz
  python3 tools/vendor_three.py verify             # re-hash the vendored files against the pins

Only two members are read from the tarball, with ``tarfile.extractfile`` (never ``extractall``):
``package/build/three.module.min.js`` and ``package/LICENSE``; each must be a regular file (not a link). The tarball is
checked against the npm integrity pinned in ``analyzer/vendor.py`` and both files, in memory, against their pinned
SHA-256 before anything is written. Each file then replaces its old copy atomically (never through a link planted at
the name), and the README that records the pins is written last.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import sys
import tarfile
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzer import vendor  # noqa: E402

MEMBERS = {"package/build/three.module.min.js": vendor.THREE_FILE, "package/LICENSE": vendor.THREE_LICENSE}


def _npm_integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def _write_atomic(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` via a new file in the same folder: a symlink at the name is replaced, never
    followed, and a failed write leaves the old file."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)            # repository files, readable like the rest of the viewer
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_members(tgz_bytes: bytes) -> dict[str, bytes] | str:
    """{dest name: bytes} of the two members, each a regular file matching its pin, or why not (nothing is written).
    The archive is read from the bytes whose integrity was checked, not opened again from disk."""
    pins = {vendor.THREE_FILE: vendor.THREE_SHA256, vendor.THREE_LICENSE: vendor.THREE_LICENSE_SHA256}
    out: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
            for member, dest in MEMBERS.items():
                try:
                    info = tf.getmember(member)
                except KeyError:
                    return f"{member} is not in the tarball"
                if not info.isfile():           # a symlink, hard link, device ... is never followed or written
                    return f"{member} is not a regular file"
                data = tf.extractfile(info).read()
                got = hashlib.sha256(data).hexdigest()
                if got != pins[dest]:
                    return f"{member} has SHA-256 {got}, not the pinned {pins[dest]}"
                out[dest] = data
    except (tarfile.TarError, OSError, EOFError) as e:
        return f"cannot read the tarball ({type(e).__name__}: {e})"
    return out


def cmd_import(tgz: Path) -> int:
    tgz_bytes = Path(tgz).read_bytes()
    got = _npm_integrity(tgz_bytes)
    if got != vendor.THREE_NPM_INTEGRITY:
        print(f"refusing: tarball integrity {got} != pinned {vendor.THREE_NPM_INTEGRITY}", file=sys.stderr)
        return 1
    files = _read_members(tgz_bytes)
    if isinstance(files, str):
        print(f"refusing: {files}; nothing was written", file=sys.stderr)
        return 1
    vendor.VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    for dest, data in files.items():
        _write_atomic(vendor.VENDOR_DIR / dest, data)
    _write_atomic(vendor.VENDOR_DIR / "README.md", (  # last: it records pins the files above now match
        f"# Vendored third-party code\n\n"
        f"| File | Source | SHA-256 |\n|---|---|---|\n"
        f"| `{vendor.THREE_FILE}` | npm `three@{vendor.THREE_VERSION}` → `build/three.module.min.js` | `{vendor.THREE_SHA256}` |\n"
        f"| `{vendor.THREE_LICENSE}` | npm `three@{vendor.THREE_VERSION}` → `LICENSE` (MIT) | `{vendor.THREE_LICENSE_SHA256}` |\n\n"
        f"Tarball integrity (as published on registry.npmjs.org): `{vendor.THREE_NPM_INTEGRITY}`.\n"
        f"Imported {date.today().isoformat()} with `npm pack three@{vendor.THREE_VERSION} --ignore-scripts` and\n"
        f"`python3 tools/vendor_three.py import three-{vendor.THREE_VERSION}.tgz` (reads only the two files above).\n\n"
        f"The files are kept byte-for-byte. `analyzer/vendor.py` pins their hashes; the build (`report.py`) refuses to\n"
        f"inline them if anything changed, and `audit-readonly` flags any unpinned file in this folder. At build time the\n"
        f"ES module is wrapped into a lazily-called classic-script factory (`window.AWSA_THREE_FACTORY`).\n\n"
        f"Why r170: it is the last release whose module build is a single self-contained file (r171 split it into\n"
        f"`three.core.js` + `three.module.js`). Upgrading requires changing the pins and re-running the import.\n"
    ).encode("utf-8"))
    return cmd_verify()


def cmd_verify() -> int:
    bad = 0
    for rel, sha in vendor.pinned_files().items():
        if sha is None:                 # documentation, not code
            continue
        p = vendor.VENDOR_DIR / rel
        got = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "missing"
        ok = got == sha
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {rel}  {got}")
    if not bad:
        vendor.three_factory_js()       # also runs every structural check of the transform
        print("ok  transform checks")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    imp = sub.add_parser("import", help="import from a local npm tarball")
    imp.add_argument("tgz", type=Path)
    sub.add_parser("verify", help="re-hash the vendored files")
    a = ap.parse_args()
    return cmd_import(a.tgz) if a.cmd == "import" else cmd_verify()


if __name__ == "__main__":
    raise SystemExit(main())
