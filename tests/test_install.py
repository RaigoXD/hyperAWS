"""Packaging: the Claude Code plugin/marketplace manifests, the skill location and where an installed copy keeps data."""

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from analyzer import fsutil

ROOT = Path(__file__).resolve().parent.parent


class TestPackaging(unittest.TestCase):
    def test_manifests_are_valid_and_point_at_this_repo(self):
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(plugin["name"], "aws-analyzer")
        entry = next(p for p in market["plugins"] if p["name"] == plugin["name"])
        self.assertEqual(entry["source"], "./")
        self.assertEqual(entry["version"], plugin["version"])

    def test_skill_lives_in_skills_folder_with_frontmatter(self):
        text = (ROOT / "skills" / "aws-analyzer" / "SKILL.md").read_text()
        self.assertTrue(text.startswith("---\nname: aws-analyzer\ndescription: "))
        self.assertFalse((ROOT / "SKILL.md").exists(), "one SKILL.md only, under skills/")
        # the skill finds the code two folders up from its real location
        self.assertTrue((ROOT / "skills" / "aws-analyzer" / ".." / ".." / "analyzer" / "__main__.py").resolve().is_file())


class TestDataHome(unittest.TestCase):
    def test_env_override_wins(self):
        with mock.patch.dict(os.environ, {"AWS_ANALYZER_HOME": "~/somewhere"}):
            self.assertEqual(fsutil.data_home(), Path("~/somewhere").expanduser())

    def test_plugin_install_keeps_data_out_of_the_cache(self):
        fake = Path.home() / ".claude" / "plugins" / "cache" / "aws-analyzer" / "aws-analyzer" / "1.0.0"
        with mock.patch.dict(os.environ, {"AWS_ANALYZER_HOME": ""}), mock.patch.object(fsutil, "ROOT", fake):
            self.assertEqual(fsutil.data_home(), Path.home() / "aws-analyzer")

    def test_cloned_repo_keeps_data_next_to_the_code(self):
        with mock.patch.dict(os.environ, {"AWS_ANALYZER_HOME": ""}):
            self.assertEqual(fsutil.data_home(), ROOT)


if __name__ == "__main__":
    unittest.main()
