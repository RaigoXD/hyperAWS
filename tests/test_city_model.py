"""The 3D map's pure model (viewer/js/city-model.js), exercised in Node on the demo account and on an account shaped like
a real one (one workload + 16 regions with only the default network). Skipped when Node.js is not installed."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from analyzer.analysis.config import load_config
from analyzer.analysis.engine import analyze
from analyzer.awscli import AwsCli
from analyzer.demo import demo_executor
from analyzer.scan import run_scan
from tests.test_pipeline import quiet

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "node is not installed")
class TestCityModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executor, _ = demo_executor()
        scan = run_scan(["demo"], quiet(), cli=AwsCli("demo", executor=executor, aws_bin="aws"))
        cls.analysis = analyze(json.loads(json.dumps(scan)), load_config())

    def test_model_invariants(self):
        out = subprocess.run([NODE, str(ROOT / "tests" / "js" / "city_model.test.js")], input=json.dumps(self.analysis),
                             capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        res = json.loads(out.stdout)
        self.assertEqual(res["failures"], [], f"{res['count']} invariant(s) broken; stats: {res['stats']}")
        self.assertGreater(res["stats"]["demo_project"]["buildings"], 50)
        self.assertGreater(res["stats"]["demo_project"]["cars"], 0)


if __name__ == "__main__":
    unittest.main()
