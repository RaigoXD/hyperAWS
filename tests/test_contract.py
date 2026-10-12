"""Collector <-> analysis contract: every attrs/metrics key a rule reads must be produced by a collector.

A typo here fails silently in production (the rule just never fires), so it is checked statically.
"""

import ast
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "analyzer"
READERS = [*sorted((PKG / "analysis").glob("rules_*.py")), PKG / "analysis" / "cost.py", PKG / "analysis" / "links.py"]
WRITERS = sorted((PKG / "collectors").glob("*.py")) + [PKG / "analysis" / "links.py", PKG / "metrics.py", PKG / "scan.py"]


def _is_field(node, name):
    return isinstance(node, ast.Attribute) and node.attr == name


def _str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def produced_keys():
    attrs, metrics = set(), set()
    for path in WRITERS:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "attrs" and isinstance(node.value, ast.Dict):
                attrs |= {_str(k) for k in node.value.keys if _str(k)}
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Subscript) and _is_field(t.value, "attrs") and _str(t.slice):
                        attrs.add(_str(t.slice))
            elif isinstance(node, ast.Call) and _is_field(node.func, "new"):
                pass
        if path.name == "metrics.py":
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("Spec", "_s3") and node.args and _str(node.args[0]):
                    metrics.add(_str(node.args[0]))
    # S3 sizes are written under dynamic names bytes_<class> (see metrics._s3 calls) and a few derived keys
    metrics |= {"objects", "bytes_standard", "_days"}
    return attrs, metrics


def consumed_keys():
    """(file, line, kind, key) for every literal key read from an `.attrs` or `.metrics` mapping (or an alias of one)."""
    out = []
    for path in READERS:
        tree = ast.parse(path.read_text())
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.Lambda))] + [tree]:
            aliases = {}
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    for kind in ("attrs", "metrics"):
                        if _is_field(node.value, kind):
                            aliases[node.targets[0].id] = kind
            for node in ast.walk(fn):
                tgt = key = None
                if isinstance(node, ast.Call) and _is_field(node.func, "get") and node.args:
                    tgt, key = node.func.value, _str(node.args[0])
                elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
                    tgt, key = node.value, _str(node.slice)
                if not key:
                    continue
                kind = ("attrs" if _is_field(tgt, "attrs") else "metrics" if _is_field(tgt, "metrics") else
                        aliases.get(tgt.id) if isinstance(tgt, ast.Name) else None)
                if kind:
                    out.append((path.name, node.lineno, kind, key))
    return sorted(set(out))


class TestContract(unittest.TestCase):
    def test_every_key_a_rule_reads_is_produced_by_a_collector(self):
        attrs, metrics = produced_keys()
        missing = [f"{f}:{line} reads {kind}[{key!r}] that no collector produces"
                   for f, line, kind, key in consumed_keys()
                   if key not in (attrs if kind == "attrs" else metrics) and not (kind == "metrics" and key.startswith("bytes_"))]
        self.assertEqual(missing, [], "\n" + "\n".join(missing))

    def test_the_checker_actually_sees_keys(self):
        attrs, metrics = produced_keys()
        self.assertGreater(len(attrs), 100)
        self.assertIn("instance_type", attrs)
        self.assertIn("cpu_avg", metrics)
        self.assertGreater(len(consumed_keys()), 60)


if __name__ == "__main__":
    unittest.main()
