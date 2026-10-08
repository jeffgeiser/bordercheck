import contextlib
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("demo_stack", os.path.join(HERE, "..", "examples", "demo", "demo_stack.py"))


class DemoTests(unittest.TestCase):
    def test_demo_stack_fails_with_the_documented_findings(self):
        demo = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(demo)
        with tempfile.TemporaryDirectory() as d, open(os.devnull, "w") as null, contextlib.redirect_stdout(null):
            rc = demo.main(os.path.join(d, "demo"))
            runs = os.path.join(d, "demo", "runs")
            with open(os.path.join(runs, os.listdir(runs)[0], "summary.json")) as f:
                summary = json.load(f)
        self.assertEqual(rc, 1)
        heads = [f["headline"] for f in summary["findings"]]
        self.assertIn("Customer data is stored outside the border.", heads)
        self.assertIn("The answers looked clean. The data behind them wasn't.", heads)
        self.assertIn("Hosted log analytics masked some identifiers but not others.", heads)


if __name__ == "__main__":
    unittest.main()
