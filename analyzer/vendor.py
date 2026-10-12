"""The one piece of third-party code in the report: three.js r170 (MIT), used only by the "3D map" tab.

The file is kept byte-for-byte in ``viewer/vendor/`` and pinned here. ``three_factory_js()`` turns the ES module into
a classic-script *factory* so it can live inside the report's single inline ``<script>`` and is only evaluated when the
3D tab is opened. Every structural assumption of that transform is checked over the whole file, so a different file can
never be inlined silently. Its scripted requests are blocked at runtime anyway: the page's Content-Security-Policy sets
``connect-src 'none'`` (three.js contains loaders that use fetch; the viewer never calls them), and the factory shadows
the request primitives. The CSP does not block top-level navigation; the viewer's own code is audited for that.
"""

from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = ROOT / "viewer" / "vendor"

THREE_VERSION = "0.170.0"
THREE_FILE = "three.module.min.js"
THREE_LICENSE = "LICENSE-three.txt"
THREE_SHA256 = "08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7"
THREE_LICENSE_SHA256 = "4c40a1ef62450b857c3b2aaf294936304cd552d965fbcd9d32d4c5bcf4ba4454"
THREE_NPM_INTEGRITY = ("sha512-FQK+LEpYc0fBD+J8g6oSEyyNzjp+Q7Ks1C568WWaoMRLW+TkNNWmenWeGgJjV105Gd+p/2ql1ZcjYvNiPZBhuQ==")

BEGIN = f"/*@vendor-begin three@{THREE_VERSION}*/"
END = "/*@vendor-end three*/"
# Names shadowed inside the factory so that even a stray call inside three.js cannot reach the network
# (belt and braces: the CSP already blocks it).
SHADOWED = ("fetch", "XMLHttpRequest", "WebSocket", "EventSource", "Worker", "SharedWorker", "importScripts")

HTML_SENSITIVE = re.compile(r"(?i)</script|<script|<!--")
_IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")


class VendorError(RuntimeError):
    pass


def pinned_files() -> dict[str, str]:
    """Every file allowed under viewer/vendor/ with its SHA-256 (the audit flags anything else)."""
    return {THREE_FILE: THREE_SHA256, THREE_LICENSE: THREE_LICENSE_SHA256, "README.md": None}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=2)
def three_factory_js(vendor_dir: Path | None = None) -> str:
    """The vendored module as ``window.AWSA_THREE_FACTORY = function () { ...; return {exports} }``."""
    path = (vendor_dir or VENDOR_DIR) / THREE_FILE
    if not path.is_file():
        raise VendorError(f"{path} is missing: run tools/vendor_three.py import <three-{THREE_VERSION}.tgz>")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != THREE_SHA256:
        raise VendorError(f"{path} does not match the pinned SHA-256 (refusing to inline modified third-party code)")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as e:
        raise VendorError(f"{path} is not pure ASCII") from e
    if "import.meta" in text or re.search(r"\bimport\s*\(", text) or re.search(r"(?:^|[;}])\s*import\s*[\w{*\"']", text):
        raise VendorError("three.js build imports other modules; only a self-contained build can be inlined")
    if HTML_SENSITIVE.search(text):
        raise VendorError("three.js build contains '<script' / '</script' / '<!--', which would break the inline <script>")
    if len(re.findall(r"\bexport\b", text)) != 1:
        raise VendorError("expected exactly one export statement in the three.js build")
    m = re.search(r"export\s*\{([^}]*)\}\s*;?\s*$", text)
    if not m:
        raise VendorError("the export statement is not the last statement of the three.js build")
    pairs = []
    for item in m.group(1).split(","):
        parts = item.split()
        if len(parts) == 1:
            local = name = parts[0]
        elif len(parts) == 3 and parts[1] == "as":
            local, name = parts[0], parts[2]
        else:
            raise VendorError(f"unexpected export entry {item!r}")
        if not (_IDENT.match(local) and _IDENT.match(name)):
            raise VendorError(f"unexpected export identifier in {item!r}")
        pairs.append((name, local))
    body = text[:m.start()]
    for n in SHADOWED:
        if re.search(rf"\b(?:let|const|class|var|function)\s+{n}\b", body):
            raise VendorError(f"three.js declares {n}; cannot shadow it")
    shadow = "var " + ",".join(f"{n}=void 0" for n in SHADOWED) + ";"
    exports = ",".join(f"{name}:{local}" for name, local in pairs)
    return (f"{BEGIN}\nwindow.AWSA_THREE_FACTORY=function(){{\"use strict\";{shadow}\n{body}\n"
            f"return{{{exports}}};}};\n{END}")
