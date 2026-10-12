"""Stage 3: build one self-contained, offline HTML report (no backend, no network).

The page carries a Content-Security-Policy that allows exactly one script (by its SHA-256) and blocks scripted requests
and sub-resource loads (``connect-src 'none'``, ``default-src 'none'`` ...), so those are enforced by the browser, not
only by review. No CSP directive blocks a top-level navigation (a link or ``location`` change), so the viewer's code is
also checked statically for navigation sinks and absolute URLs (``python3 -m analyzer audit-readonly``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path

from . import vendor
from .fsutil import write_private

ROOT = Path(__file__).resolve().parent.parent
VIEWER = ROOT / "viewer"
JS_ORDER = ["util.js", "data.js", "charts.js", "drawer.js", "overview.js", "inventory.js", "graph.js",
            "city-catalog.js", "city-model.js", "city-camera.js", "city-scene.js", "city3d.js",
            "waste.js", "cost.js", "tags.js", "scan.js", "app.js"]
# require-trusted-types-for + trusted-types 'none': every HTML/script sink (innerHTML, insertAdjacentHTML, document.write,
# script.src ...) throws, so "untrusted text only ever goes through textContent" is enforced by the browser, not only by
# convention. Neither the viewer nor the vendored three.js uses such a sink (verified in headless Chromium on every tab,
# including the 3D map); browsers without Trusted Types ignore the two directives.
CSP = ("default-src 'none'; script-src '{script_hash}'; style-src 'unsafe-inline'; img-src data: blob:; "
       "connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; worker-src 'none'; "
       "frame-src 'none'; child-src 'none'; manifest-src 'none'; form-action 'none'; base-uri 'none'; "
       "require-trusted-types-for 'script'; trusted-types 'none'")


class BuildError(RuntimeError):
    pass


def script_hash(script_text: str) -> str:
    """CSP source expression for an inline script whose text (between the tags) is ``script_text``."""
    return "sha256-" + base64.b64encode(hashlib.sha256(script_text.encode("utf-8")).digest()).decode()


def finite(value):
    """A copy of ``value`` with every NaN/Infinity float replaced by None (JSON has no such numbers)."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: finite(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [finite(v) for v in value]
    return value


_SURROGATE = re.compile(r"[\ud800-\udfff]")


def json_text(data, **kw) -> str:
    """Strict JSON that every parser accepts: NaN/Infinity become null (Python's default would write ``NaN``, which
    the browser's JSON.parse rejects), and lone surrogates are written as \\uXXXX escapes (they cannot be encoded
    as UTF-8, so a raw one would abort the write)."""
    text = json.dumps(finite(data), allow_nan=False, ensure_ascii=False, **kw)
    return _SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group()), text)   # surrogates only occur inside strings


def _embed_json(data: dict | None) -> str:
    """JSON that is safe inside <script type="application/json">.

    Only valid JSON escapes are used (\\/ and \\uXXXX), so JSON.parse reads back the exact original text.
    """
    text = json_text(data, separators=(",", ":"))
    text = text.replace("<!--", "<\\u0021--")
    return re.sub(r"(?i)<(/?)(s)(cript)", lambda m: "<" + ("\\/" if m.group(1) else "") + "\\u%04x" % ord(m.group(2)) + m.group(3), text)


def build_html(analysis: dict | None = None, *, viewer_dir: Path | None = None) -> str:
    """Inline CSS + JS (+ the data) into viewer/index.html. ``analysis=None`` builds an empty viewer
    that can load any analysis.json by drag & drop."""
    vd = viewer_dir or VIEWER
    html = (vd / "index.html").read_text(encoding="utf-8")
    css = (vd / "styles.css").read_text(encoding="utf-8")
    parts = [vendor.three_factory_js(vd / "vendor" if viewer_dir else None)]
    parts += [f"/* ---- {n} ---- */\n" + (vd / "js" / n).read_text(encoding="utf-8") for n in JS_ORDER]
    js = "\n".join(parts)
    if vendor.HTML_SENSITIVE.search(js) or "</style" in css.lower():
        raise BuildError("viewer code contains '<script', '</script' or '<!--', which would break the inline page")
    script = f"\n{js}\n"
    for marker, value in (("<!--@csp-->", f'<meta http-equiv="Content-Security-Policy" content="{CSP.format(script_hash=script_hash(script))}">'),
                          ("<!--@css-->", f"<style>\n{css}\n</style>"),
                          ("<!--@js-->", f"<script>{script}</script>"),
                          ("<!--@data-->", f'<script id="aws-data" type="application/json">{_embed_json(analysis)}</script>')):
        if marker not in html:
            raise ValueError(f"viewer/index.html is missing the {marker} marker")
        html = html.replace(marker, value)
    return html


def write_report(analysis: dict | None, out: Path) -> Path:
    write_private(out, build_html(analysis))
    return out


_CSP_META = re.compile(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">')
_HASH_SOURCE = re.compile(r"'sha256-[A-Za-z0-9+/=]+'")


def stale_reports(out_dir: Path) -> list[Path]:
    """Report pages in ``out_dir`` (``report*.html``, ``viewer.html``) built by an older viewer: without the
    Content-Security-Policy meta tag, or with a policy other than today's (apart from the script hash). Only regular
    files owned by you are looked at, and only their first 64 KiB (the tag is at the top of <head>)."""
    current = CSP.format(script_hash="sha256-")
    uid = os.getuid()
    stale = []
    for p in sorted(Path(out_dir).glob("*.html")):
        if not (p.name.startswith("report") or p.name == "viewer.html"):
            continue
        try:
            st = os.lstat(p)
            if not (stat.S_ISREG(st.st_mode) and st.st_uid == uid):
                continue
            with open(p, encoding="utf-8", errors="replace") as f:
                head = f.read(65536)
        except OSError:
            continue
        m = _CSP_META.search(head)
        if not m or _HASH_SOURCE.sub("'sha256-'", m.group(1)) != current:
            stale.append(p)
    return stale


_STAMP = re.compile(r"^(scan|analysis)-(.+)\.json$")


def latest(out_dir: Path, prefix: str) -> Path | None:
    """Newest ``<prefix>-*.json`` in ``out_dir``. Only regular files owned by you count: a symlink or a file someone
    else placed there is never picked up as input."""
    uid = os.getuid()
    found = []
    for p in Path(out_dir).glob(f"{prefix}-*.json"):
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid == uid:
            found.append((st.st_mtime, p.name, p))
    return max(found)[2] if found else None
