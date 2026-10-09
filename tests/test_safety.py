"""The fault phase must always restore the model once the start command was agreed to (#6),
and a clean result from an outside-border store must be backed by evidence it saw the run (#5)."""
import contextlib
import json
import os
import tempfile
import unittest
from unittest import mock

from bordercheck import cli, report, send
from test_bordercheck import Quiet, serve


class Gateway(Quiet):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"model": "local"}')


def write_config(d, url, start, stop):
    path = os.path.join(d, "bordercheck.toml")
    with open(path, "w") as f:
        f.write(f"""environment = "lab"
output_dir = {json.dumps(os.path.join(d, "runs"))}
requests_per_phase = 1
scan_delay_seconds = 0
[border]
allowed_locations = ["DE"]
[target]
url = "{url}"
prompt = "ref {{{{canary}}}}"
body = '{{"user": "{{{{request_id}}}}", "messages": [{{"role": "user", "content": "{{{{prompt}}}}"}}]}}'
pause_seconds = 0
# Record who answered: without served-by fields or an egress source, an answered fault
# phase is inconclusive (PR #4), which would mask the outside-border checks these tests isolate.
record_fields = ["model"]
[fault]
start = {json.dumps(start)}
stop = {json.dumps(stop)}
settle_seconds = 0
""")
    return path


def run_all(cfg, *extra):
    with open(os.devnull, "w") as null, contextlib.redirect_stdout(null):
        return cli.main(["-c", cfg, "all", *extra])


class FaultPhaseTests(unittest.TestCase):
    def test_failed_start_still_runs_stop_and_the_run_reports(self):
        with tempfile.TemporaryDirectory() as d, serve(Gateway) as url:
            marker = os.path.join(d, "model-down")
            cfg = write_config(d, url, f"touch {marker} && false", f"rm -f {marker}")
            rc = run_all(cfg, "--yes")
            self.assertFalse(os.path.exists(marker), "stop ran after the failed start")
            self.assertIn(rc, (0, 1, 3), "the run went on to scan and report")
            run_dir = os.path.join(d, "runs", os.listdir(os.path.join(d, "runs"))[0])
            self.assertTrue(os.path.exists(os.path.join(run_dir, "report.md")))

    def test_interrupt_during_fault_restores_without_asking_again(self):
        with tempfile.TemporaryDirectory() as d, serve(Gateway) as url:
            marker = os.path.join(d, "model-down")
            cfg = write_config(d, url, f"touch {marker}", f"rm -f {marker}")
            real_send = send.send_phase

            def interrupted(cfg_, run, phase, *a, **k):
                if phase == "fault":
                    raise KeyboardInterrupt
                return real_send(cfg_, run, phase, *a, **k)

            with mock.patch("builtins.input", return_value="yes") as answer, \
                    mock.patch.object(send, "send_phase", interrupted):
                rc = run_all(cfg)
            self.assertEqual(rc, 130)
            self.assertFalse(os.path.exists(marker), "stop ran after Ctrl-C")
            self.assertEqual(answer.call_count, 1, "asked once, for the start command only")

    def test_declined_start_runs_neither_command(self):
        with tempfile.TemporaryDirectory() as d, serve(Gateway) as url:
            started, stopped = os.path.join(d, "started"), os.path.join(d, "stopped")
            cfg = write_config(d, url, f"touch {started}", f"touch {stopped}")
            with mock.patch("builtins.input", return_value="no"):
                run_all(cfg)
            self.assertFalse(os.path.exists(started))
            self.assertFalse(os.path.exists(stopped))


class LoggingGateway(Quiet):
    """Logs each request body to app.log (inside the border) and only its request id to ids.log."""
    root = None

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with open(os.path.join(self.root, "app.log"), "ab") as f:
            f.write(body + b"\n")
        with open(os.path.join(self.root, "ids.log"), "a") as f:
            f.write(json.loads(body)["user"] + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"model": "local"}')


def source(name, location, extra):
    return f'\n[[sources]]\nname = "{name}"\nlayer = "logs"\nlocation = "{location}"\n{extra}\n'


class OutsideBorderCoverageTests(unittest.TestCase):
    """#5: a clean result from a store outside the border needs evidence it saw the run."""

    def run_with(self, outside):
        with tempfile.TemporaryDirectory() as d:
            handler = type("G", (LoggingGateway,), {"root": d})
            os.makedirs(os.path.join(d, "empty"))
            with serve(handler) as url:
                cfg = write_config(d, url, "true", "true")
                with open(cfg, "a") as f:
                    f.write(source("App logs", "DE", f'type = "path"\npath = {json.dumps(os.path.join(d, "app.log"))}\n'
                                   "positive_control = true"))
                    f.write(outside.replace("ROOT", d))
                rc = run_all(cfg, "--yes")
            run_dir = os.path.join(d, "runs", os.listdir(os.path.join(d, "runs"))[0])
            with open(os.path.join(run_dir, "summary.json")) as f:
                summary = json.load(f)
            with open(os.path.join(run_dir, "report.md")) as f:
                text = f.read()
            with open(os.path.join(run_dir, "summary.html")) as f:
                html = f.read()
        return rc, summary, text, html

    def test_empty_outside_directory_is_inconclusive(self):
        rc, summary, _, _ = self.run_with(source("US logs", "US", 'type = "path"\npath = "ROOT/empty"'))
        self.assertEqual((rc, summary["verdict"]), (3, "inconclusive"))
        self.assertIn("US logs (US) is outside the border but never saw this run's requests", summary["reasons"][0])

    def test_outside_command_with_no_output_is_inconclusive(self):
        rc, summary, _, _ = self.run_with(source("US export", "US", 'type = "command"\ncommand = "true"'))
        self.assertEqual(summary["verdict"], "inconclusive")

    def test_outside_store_that_saw_the_run_but_kept_no_identifiers_can_pass(self):
        rc, summary, _, _ = self.run_with(source("US ids", "US", 'type = "path"\npath = "ROOT/ids.log"'))
        self.assertEqual((rc, summary["verdict"]), (0, "pass"))

    def test_opt_out_passes_but_is_listed_as_unverified(self):
        rc, summary, text, html = self.run_with(
            source("US metrics", "US", 'type = "path"\npath = "ROOT/empty"\nexpect_request_ids = false'))
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["unverified"], ["US metrics (US)"])
        self.assertIn("Unverified: US metrics (US)", text)
        self.assertIn("US metrics (US): outside the border and can't show it saw this run", html)

    def test_verdict_alone(self):
        clean_but_blind = {"name": "US", "location": "US", "inside": False, "identifiers": False, "errors": 0,
                           "saw_request_ids": False, "targets_scanned": 0, "positive_control": False,
                           "egress": False, "expect_request_ids": True}
        control = dict(clean_but_blind, name="DE", location="DE", inside=True, identifiers=True,
                       positive_control=True, targets_scanned=1)
        result, reasons = report.verdict([control, clean_but_blind], [], [], {})
        self.assertEqual(result, "inconclusive")


if __name__ == "__main__":
    unittest.main()
