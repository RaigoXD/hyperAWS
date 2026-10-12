"""The one vendored library (three.js r170): pinned bytes, a checked module -> classic-script transform, and a syntax
check of the whole inline script the report ships (one syntax error would break every tab)."""

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from analyzer import report, vendor

NODE = shutil.which("node")


class TestVendor(unittest.TestCase):
    def test_files_match_their_pins(self):
        for rel, sha in vendor.pinned_files().items():
            p = vendor.VENDOR_DIR / rel
            self.assertTrue(p.is_file(), rel)
            if sha:
                self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), sha, rel)

    def test_transform_is_deterministic_and_inert(self):
        a = vendor.three_factory_js()
        vendor.three_factory_js.cache_clear()
        b = vendor.three_factory_js()
        self.assertEqual(a, b)
        self.assertTrue(a.startswith(vendor.BEGIN) and a.endswith(vendor.END))
        self.assertNotRegex(a, r"(?i)</script|<script|<!--")
        self.assertNotIn("export{", a.replace(" ", ""))
        for name in vendor.SHADOWED:
            self.assertIn(f"{name}=void 0", a)          # network globals are shadowed inside the factory

    def test_a_modified_file_is_refused(self):
        d = Path(tempfile.mkdtemp())
        data = (vendor.VENDOR_DIR / vendor.THREE_FILE).read_bytes()
        (d / vendor.THREE_FILE).write_bytes(data.replace(b'const t="170"', b'const t="171"', 1))
        with self.assertRaises(vendor.VendorError):
            vendor.three_factory_js(d)

    @unittest.skipUnless(NODE, "node is not installed")
    def test_whole_inline_script_parses_and_three_evaluates(self):
        import re
        html = report.build_html(None)
        app = re.search(r"<script>(.*?)</script>", html, flags=re.S).group(1)
        prog = ("const vm=require('vm');let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{"
                "new vm.Script(s,{filename:'report.js'});"                                         # the whole bundle parses
                "const m=s.slice(s.indexOf('/*@vendor-begin'),s.indexOf('/*@vendor-end three*/'));"
                "globalThis.window=globalThis;new vm.Script(m).runInThisContext();"
                "const T=window.AWSA_THREE_FACTORY();"
                "process.stdout.write(JSON.stringify([T.REVISION,typeof T.WebGLRenderer,typeof T.InstancedMesh]))})")
        out = subprocess.run([NODE, "-e", prog], input=app, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        self.assertEqual(out.stdout, '["170","function","function"]')


if __name__ == "__main__":
    unittest.main()
