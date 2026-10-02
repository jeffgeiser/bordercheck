import contextlib
import json
import os
import re
import tempfile
import threading
import time
import unittest
import zipfile

from bordercheck import canary, cli, evidence, onepager, report, scan
from test_bordercheck import Quiet, serve


def quiet_main(argv):
    with open(os.devnull, "w") as null, contextlib.redirect_stdout(null):
        return cli.main(argv)


class IdentifierTests(unittest.TestCase):
    def test_iban_checksum_is_valid_and_bank_code_cannot_be_real(self):
        for _ in range(50):
            iban = canary.new_record()["iban"]
            self.assertEqual(int(iban[4:] + "1314" + iban[2:4]) % 97, 1)   # ISO 13616
            self.assertEqual(iban[4], "9")                                  # no German clearing area 9

    def test_reserved_email_and_phone(self):
        rec = canary.new_record()
        self.assertTrue(rec["email"].endswith("@example.com"))
        self.assertRegex(rec["phone"], r"^\+49 69 90009\d{3}$")
        self.assertIn(rec["canary"][5:].replace("-", "").lower(), rec["email"])

    def test_formats_are_found_as_logged(self):
        rec = canary.new_record()
        phone = rec["phone"].replace(" ", "")
        grouped = " ".join(rec["iban"][i:i + 4] for i in range(0, len(rec["iban"]), 4))
        text = f"to={rec['email'].replace('@', '%40')} tel=0{phone[3:]} iban={grouped}".encode()
        hits, _ = scan.scan_stream([text], canary.needles(rec, "run-x"), [])
        self.assertEqual({h["kind"] for h in hits}, {"email", "phone", "iban"})


class WindowTests(unittest.TestCase):
    def test_placeholders_are_iso_and_shell_safe(self):
        run = {"run_id": "run-20260101-000000-abcd", "created": time.time() - 600}
        w = scan.window(run, skew=60)
        self.assertRegex(w["run_started"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertGreaterEqual(int(w["run_minutes"]), 11)
        for v in w.values():
            self.assertRegex(v, r"^[A-Za-z0-9:-]+$")

    def test_command_and_url_placeholders_are_rendered(self):
        seen = []

        class Api(Quiet):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(200)
                self.end_headers()

        with serve(Api) as url:
            cfg = {"watch_destinations": [], "sources": [
                {"name": "c", "type": "command", "command": "echo since={{run_started}}", "layer": "logs", "location": "DE"},
                {"name": "h", "type": "http", "url": url + "/t?from={{run_started}}", "layer": "logs", "location": "DE"}]}
            values = {"run_started": "2026-01-01T00:00:00Z"}
            with open(os.devnull, "w") as null, contextlib.redirect_stdout(null):
                res = scan.scan_sources(cfg, [("canary", "canary", b"since=2026-01-01T00:00:00Z")], values)
        self.assertEqual(len(res[0]["hits"]), 1)
        self.assertEqual(seen, ["/t?from=2026-01-01T00:00:00Z"])

    def test_pages_are_followed_until_the_last(self):
        pages = []

        class Api(Quiet):
            def do_GET(self):
                page = int(re.search(r"page=(\d+)", self.path).group(1))
                pages.append(page)
                data = [{"input": "CNRY-TEST-0001"}] if page == 3 else [{"input": "other"}]
                out = json.dumps({"data": data, "meta": {"page": page, "totalPages": 3}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(out)

        with serve(Api) as url:
            cfg = {"watch_destinations": [], "sources": [
                {"name": "lf", "type": "http", "url": url + "/traces?page={{page}}", "layer": "logs", "location": "DE"}]}
            with open(os.devnull, "w") as null, contextlib.redirect_stdout(null):
                res = scan.scan_sources(cfg, [("canary", "canary", b"CNRY-TEST-0001")])[0]
        self.assertEqual(pages, [1, 2, 3])
        self.assertEqual(res["targets_scanned"], 3)
        self.assertEqual(len(res["hits"]), 1)


class Stack:
    """A mock LiteLLM-style gateway: local model normally, a public API on long prompts, bursts,
    or while a fault file exists. Writes what it logs to app.log and egress.log."""

    def __init__(self, d, redact_email=False):
        self.d, self.fault = d, os.path.join(d, "fault")
        self.app_log, self.egress_log = os.path.join(d, "app.log"), os.path.join(d, "egress.log")
        self.lock, self.in_flight = threading.Lock(), 0
        stack = self

        class Gateway(Quiet):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                with stack.lock:
                    stack.in_flight += 1
                    busy = stack.in_flight > 3
                time.sleep(0.05)
                public = os.path.exists(stack.fault) or len(body) > 20000 or busy
                logged = re.sub(rb"[a-z0-9.]+@example\.com", b"<EMAIL>", body) if redact_email else body
                with stack.lock:
                    stack.in_flight -= 1
                    with open(stack.app_log, "ab") as f:
                        f.write(logged + b"\n")
                    if public:
                        with open(stack.egress_log, "a") as f:
                            f.write("CONNECT api.openai.com:443 200\n")
                out = json.dumps({"model": "gpt-4o-mini" if public else "local-qwen"}).encode()
                self.send_response(200)
                self.send_header("x-litellm-model-api-base",
                                 "https://api.openai.com/v1" if public else "http://vllm.lab.internal:8000/v1")
                self.end_headers()
                self.wfile.write(out)

        self.handler = Gateway

    def config(self, url, extra="", fault=True):
        path = os.path.join(self.d, "bordercheck.toml")
        fault_section = f'[fault]\nstart = "touch {self.fault}"\nstop = "rm -f {self.fault}"\nsettle_seconds = 0\n' if fault else ""
        with open(path, "w") as f:
            f.write(f"""
environment = "lab"
output_dir = "{self.d}/runs"
requests_per_phase = 2
scan_delay_seconds = 0
[border]
allowed_locations = ["DE"]
[target]
url = "{url}"
prompt = "ref {{{{canary}}}} acct {{{{account}}}} mail {{{{email}}}} iban {{{{iban}}}}"
body = '{{"user": "{{{{request_id}}}}", "messages": [{{"role": "user", "content": "{{{{prompt}}}}"}}]}}'
record_headers = ["x-litellm-model-api-base"]
pause_seconds = 0
{fault_section}
{extra}
[[sources]]
name = "App logs"
type = "path"
path = "{self.app_log}"
layer = "logs"
location = "DE"
positive_control = true
""")
        return path

    def runs(self):
        return sorted(os.listdir(os.path.join(self.d, "runs")))

    def summary(self, run_id):
        with open(os.path.join(self.d, "runs", run_id, "summary.json")) as f:
            return json.load(f)


class ProbeTests(unittest.TestCase):
    def test_context_window_and_rate_limit_failovers_fail_with_nothing_down(self):
        with tempfile.TemporaryDirectory() as d:
            stack = Stack(d)
            with serve(stack.handler) as url:
                cfg = stack.config(url, fault=False, extra="""
[probes.context_window]
pad_tokens = 8000
requests = 2
[probes.rate_limit]
requests = 12
concurrency = 8
""")
                rc = quiet_main(["-c", cfg, "all", "--yes"])
            s = stack.summary(stack.runs()[0])
        self.assertEqual(rc, 1)
        self.assertEqual(s["phases"]["baseline"]["public_hosts"], [])
        self.assertEqual(s["phases"]["probe:context_window"]["public_hosts"], ["api.openai.com"])
        self.assertEqual(s["phases"]["probe:rate_limit"]["public_hosts"], ["api.openai.com"])
        self.assertTrue(any(r.startswith("Long prompt") for r in s["reasons"]))

    def test_allowed_destinations_cover_served_by_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            stack = Stack(d)
            with serve(stack.handler) as url:
                cfg = stack.config(url)
                with open(cfg) as f:
                    text = f.read().replace('allowed_locations = ["DE"]',
                                            'allowed_locations = ["DE"]\nallowed_destinations = ["api.openai.com"]')
                with open(cfg, "w") as f:
                    f.write(text)
                rc = quiet_main(["-c", cfg, "all", "--yes"])
            s = stack.summary(stack.runs()[0])
        self.assertEqual(s["phases"]["fault"]["allowed_hosts"], ["api.openai.com"])
        self.assertEqual(s["verdict"], "pass")
        self.assertEqual(rc, 0)


class EvidenceTests(unittest.TestCase):
    def test_redaction_table_bundle_verify_diff_and_rescan(self):
        with tempfile.TemporaryDirectory() as d:
            # First run: the app logs everything. Second: it masks email addresses.
            for redact_email in (False, True):
                stack = Stack(d, redact_email=redact_email)
                with serve(stack.handler) as url:
                    cfg = stack.config(url, fault=False)
                    self.assertEqual(quiet_main(["-c", cfg, "all", "--yes"]), 0)
                time.sleep(1.1)   # run ids are per second
            first, second = stack.runs()
            s1, s2 = stack.summary(first), stack.summary(second)
            kept = lambda s: s["sources"][0]["kinds_found"]  # noqa: E731
            self.assertIn("email", kept(s1))
            self.assertNotIn("email", kept(s2))
            report_md = open(os.path.join(d, "runs", second, "report.md")).read()
            self.assertIn("Which identifier formats each store kept", report_md)

            # Masking more is an improvement; the reverse is a regression.
            self.assertEqual(quiet_main(["-c", cfg, "diff", "--run", second, "--against", first]), 0)
            self.assertEqual(quiet_main(["-c", cfg, "diff", "--run", first, "--against", second]), 1)

            # Evidence bundle verifies, and tampering is detected.
            self.assertEqual(quiet_main(["-c", cfg, "evidence", "--run", second, "--include-config"]), 0)
            bundle = os.path.join(d, "runs", f"{second}-evidence.zip")
            self.assertEqual(os.stat(bundle).st_mode & 0o777, 0o600)
            self.assertEqual(evidence.verify(bundle), [])
            self.assertEqual(quiet_main(["verify", bundle]), 0)
            tampered = os.path.join(d, "tampered.zip")
            with zipfile.ZipFile(bundle) as src, zipfile.ZipFile(tampered, "w") as dst:
                for item in src.namelist():
                    data = src.read(item)
                    dst.writestr(item, data.replace(b'"pass"', b'"fail"') if item == "summary.json" else data)
            self.assertIn("summary.json: contents don't match the manifest", evidence.verify(tampered))

            # Retention: the log still holds the customer, then it's rotated away.
            self.assertEqual(quiet_main(["-c", cfg, "rescan", "--run", second, "--expect-gone"]), 1)
            open(stack.app_log, "w").close()
            self.assertEqual(quiet_main(["-c", cfg, "rescan", "--run", second, "--expect-gone"]), 0)


class OnePagerTests(unittest.TestCase):
    def test_values_from_responses_are_escaped(self):
        cfg = {"border": {"allowed_locations": ["DE"]}, "watch_destinations": []}
        run = {"run_id": "run-20260101-000000-abcd", "environment": "lab", "created": 0, "events": [],
               "record": canary.new_record(),
               "requests": [{"phase": "baseline", "status": 200, "seconds": 0.1, "fields": {},
                             "headers": {"x-backend": "<script>alert(1)</script>"}}]}
        _text, summary = report.build(cfg, run, [])
        page = onepager.html(summary, frameworks=True)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Regulation (EU) 2022/2554", page)


if __name__ == "__main__":
    unittest.main()
