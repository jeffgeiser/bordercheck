import base64
import contextlib
import gzip
import http.server
import json
import os
import tempfile
import threading
import unittest

from canarykit import canary, cli, config, report, runs, scan, send


@contextlib.contextmanager
def serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        srv.server_close()


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


def scan_one(src, needles=(("canary", "canary", b"CNRY-TEST-0001"),)):
    src = dict({"name": "s", "layer": "logs", "location": "DE"}, **src)
    return scan.scan_sources({"watch_destinations": [], "sources": [src]}, list(needles))[0]


class CanaryTests(unittest.TestCase):
    def test_base64_found_at_every_alignment(self):
        rec = canary.new_record()
        cores = [n[2] for n in canary.needles(rec, "run-x") if "base64" in n[1]]
        for prefix in (b"", b"a", b"ab", b"abc", b"abcd"):
            encoded = base64.b64encode(prefix + rec["canary"].encode() + b" trailing text")
            self.assertTrue(any(c in encoded for c in cores), prefix)

    def test_values_are_unique(self):
        a, b = canary.new_record(), canary.new_record()
        self.assertNotEqual(a["canary"], b["canary"])
        self.assertTrue(a["synthetic"])


class ScanTests(unittest.TestCase):
    def test_match_across_chunk_boundary_reports_correct_line(self):
        needle = b"CNRY-ABCD-EFGH"
        data = b"x\n" * 10 + b"y" * (scan.CHUNK - 25) + needle + b"\nend"
        chunks = [data[i:i + scan.CHUNK] for i in range(0, len(data), scan.CHUNK)]
        hits, _ = scan.scan_stream(chunks, [("canary", "canary", needle)], [])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 11)
        self.assertEqual(hits[0]["offset"], data.find(needle))

    def test_watch_wildcards(self):
        rx = scan._watch_regex("bedrock-runtime.*.amazonaws.com")
        self.assertTrue(rx.search(b"CONNECT bedrock-runtime.eu-central-1.amazonaws.com:443"))
        self.assertFalse(rx.search(b"CONNECT s3.amazonaws.com:443"))

    def test_missing_path_is_an_error_not_clean(self):
        cfg = {"watch_destinations": [], "sources": [
            {"name": "gone", "type": "path", "path": "/nonexistent/xyz", "layer": "logs", "location": "DE"}]}
        res = scan.scan_sources(cfg, [("canary", "canary", b"CNRY")])
        self.assertTrue(res[0]["errors"])


    def test_watch_matches_whole_hostnames_only(self):
        rx = scan._watch_regex("api.openai.com")
        self.assertTrue(rx.search(b"CONNECT api.openai.com:443"))
        self.assertFalse(rx.search(b"CONNECT myapi.openai.com:443"))


class SourceSafetyTests(unittest.TestCase):
    def test_env_values_are_not_spliced_into_commands(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "pwned")
            os.environ["CK_TEST_VALUE"] = f"CNRY-TEST-0001'; touch {marker}; echo '"
            res = scan_one({"type": "command", "command": 'printf %s "${CK_TEST_VALUE}"'})
            self.assertFalse(os.path.exists(marker))
            self.assertEqual(len(res["hits"]), 1)

    def test_command_stderr_is_not_stored(self):
        res = scan_one({"type": "command", "command": "echo CNRY-TEST-0001; echo CNRY-TEST-0001 secret >&2; exit 3"})
        self.assertIn("exited 3", res["errors"][0])
        self.assertNotIn("CNRY", json.dumps(res["errors"]))
        self.assertEqual(len(res["hits"]), 1, "hits before the failure are kept")

    def test_bad_gzip_error_does_not_quote_file_contents(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "x.gz"), "wb") as f:
                f.write(b"CNRY-TEST-0001 not gzip")
            res = scan_one({"type": "path", "path": d})
        self.assertTrue(res["errors"])
        self.assertNotIn("CNRY", json.dumps(res))

    def test_gzip_files_are_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            with gzip.open(os.path.join(d, "x.log.gz"), "wb") as f:
                f.write(b"hello CNRY-TEST-0001\n")
            self.assertEqual(len(scan_one({"type": "path", "path": d})["hits"]), 1)

    def test_redirects_are_not_followed_with_credentials(self):
        seen = []

        class Sink(Quiet):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

        with serve(Sink) as sink:
            class Redirect(Quiet):
                def do_GET(self):
                    self.send_response(302)
                    self.send_header("Location", sink + "/")
                    self.end_headers()

            with serve(Redirect) as url:
                res = scan_one({"type": "http", "url": url, "headers": {"Authorization": "Bearer s3cret"}})
        self.assertEqual(seen, [])
        self.assertIn("HTTP 302", res["errors"][0])


class SendTests(unittest.TestCase):
    def test_records_served_by_but_not_the_body(self):
        class Gateway(Quiet):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                prompt = json.loads(body)["messages"][0]["content"]
                out = json.dumps({"model": "local-qwen", "choices": [{"message": {"content": prompt}}]}).encode()
                self.send_response(200)
                self.send_header("x-litellm-model-api-base", "http://vllm.lab.internal:8000/v1")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        rec = canary.new_record()
        run = {"run_id": "run-20260101-000000-abcd", "record": rec, "requests": []}
        with serve(Gateway) as url:
            cfg = {"requests_per_phase": 2, "request_id_header": "X-Canary-Request-Id", "target": {
                "url": url, "prompt": "ref {{canary}}", "pause_seconds": 0,
                "body": '{"messages": [{"role": "user", "content": "{{prompt}}"}]}',
                "record_fields": ["model", "choices"], "record_headers": ["x-litellm-model-api-base"]}}
            send.send_phase(cfg, run, "baseline")
        r = run["requests"][0]
        self.assertEqual(r["status"], 200)
        self.assertTrue(r["canary_in_response"])
        self.assertEqual(r["fields"]["model"], "local-qwen")
        self.assertEqual(r["fields"]["choices"], "[list not recorded]")
        self.assertNotIn(rec["canary"], json.dumps(run["requests"]))


class ReportTests(unittest.TestCase):
    def test_allowed_destinations_are_not_reported_as_leaving_the_border(self):
        cfg = {"border": {"allowed_locations": ["DE"], "allowed_destinations": ["bedrock-runtime.eu-central-1.amazonaws.com"]},
               "watch_destinations": config.DEFAULT_WATCH}
        run = {"run_id": "run-20260101-000000-abcd", "environment": "lab", "created": 0, "events": [],
               "record": {"canary": "CNRY-TEST-0001", "account": "99"}, "requests": []}
        hits = [{"kind": "egress", "label": "egress", "destination": d, "where": "x"}
                for d in ("bedrock-runtime.eu-central-1.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com")]
        scan_res = [{"name": "Egress", "layer": "logs", "location": "DE", "egress": True, "hits": hits,
                     "errors": [], "targets_scanned": 1, "truncated": []}]
        text, summary = report.build(cfg, run, scan_res)
        self.assertEqual(summary["egress_outside_border"], ["bedrock-runtime.us-east-1.amazonaws.com"])
        self.assertIn("allowed_destinations", text)


class VerdictTests(unittest.TestCase):
    def _src(self, name, location="DE", hit=False, control=False, errors=()):
        hits = [{"kind": "canary", "label": "canary", "where": "x"}] if hit else []
        return {"name": name, "layer": "logs", "location": location, "egress": False, "hits": hits,
                "positive_control": control, "errors": list(errors), "targets_scanned": 1, "truncated": []}

    def _verdict(self, scan_res, allowed=("DE",)):
        cfg = {"border": {"allowed_locations": list(allowed)}, "watch_destinations": []}
        run = {"run_id": "run-20260101-000000-abcd", "environment": "lab", "created": 0, "events": [],
               "record": {"canary": "CNRY-TEST-0001", "account": "99"}, "requests": []}
        return report.build(cfg, run, scan_res)[1]

    def test_pass_needs_a_positive_control_that_found_the_customer(self):
        self.assertEqual(self._verdict([self._src("logs", hit=True, control=True), self._src("cache")])["verdict"], "pass")
        self.assertEqual(self._verdict([self._src("cache")])["verdict"], "inconclusive")
        self.assertEqual(self._verdict([self._src("logs", control=True)])["verdict"], "inconclusive")

    def test_source_errors_make_a_clean_result_inconclusive(self):
        res = self._verdict([self._src("logs", hit=True, control=True), self._src("cache", errors=["HTTP 401"])])
        self.assertEqual(res["verdict"], "inconclusive")

    def test_identifiers_outside_the_border_fail_even_without_a_control(self):
        res = self._verdict([self._src("US analytics", location="US", hit=True)])
        self.assertEqual(res["verdict"], "fail")
        self.assertEqual(report.EXIT_CODES[res["verdict"]], 1)


class RunTests(unittest.TestCase):
    def test_run_ids_cannot_escape_the_output_dir(self):
        with self.assertRaises(runs.RunIdError):
            runs.run_dir({"output_dir": "runs"}, "../../etc")


class ConfigTests(unittest.TestCase):
    def _write(self, env):
        f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        f.write(f'environment = "{env}"\n[border]\nallowed_locations=["DE"]\n'
                '[target]\nurl="http://x"\nbody="{{{{prompt}}}}"\nprompt="hi"\n')
        f.close()
        return f.name

    def test_refuses_production(self):
        path = self._write("production")
        with self.assertRaises(config.ConfigError):
            config.load(path)
        self.assertEqual(config.load(path, allow_production=True)["environment"], "production")
        os.unlink(path)

    def test_refuses_credentials_over_plain_http(self):
        path = self._write("staging")
        with open(path, "a") as f:
            f.write('headers = { Authorization = "Bearer x" }\n')
        with open(path) as f:
            text = f.read()
        for url, ok in (("http://gateway.lab", False), ("http://localhost:4000", True), ("https://gateway.lab", True)):
            with open(path, "w") as f:
                f.write(text.replace('url="http://x"', f'url="{url}"'))
            if ok:
                config.load(path)
            else:
                with self.assertRaises(config.ConfigError):
                    config.load(path)
        os.unlink(path)

    def test_missing_env_var_is_an_error(self):
        os.environ.pop("CK_DEFINITELY_UNSET", None)
        with self.assertRaises(config.ConfigError):
            config.expand_env("Bearer ${CK_DEFINITELY_UNSET}")


class EndToEndTests(unittest.TestCase):
    """A mock stack: a gateway that fails over to a public API while a fault file exists."""

    def test_all_finds_failover_and_redacts(self):
        with tempfile.TemporaryDirectory() as d:
            fault_file = os.path.join(d, "fault")
            app_log, egress_log = os.path.join(d, "app.log"), os.path.join(d, "egress.log")

            class Gateway(Quiet):
                def do_POST(self):
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                    down = os.path.exists(fault_file)
                    with open(app_log, "ab") as f:
                        f.write(body + b"\n")
                    if down:
                        with open(egress_log, "a") as f:
                            f.write("CONNECT api.openai.com:443 200\n")
                    out = json.dumps({"model": "gpt-4o-mini" if down else "local-qwen"}).encode()
                    self.send_response(200)
                    self.send_header("x-litellm-model-api-base",
                                     "https://api.openai.com/v1" if down else "http://vllm.lab.internal:8000/v1")
                    self.end_headers()
                    self.wfile.write(out)

            with serve(Gateway) as url:
                cfg_path = os.path.join(d, "canarykit.toml")
                with open(cfg_path, "w") as f:
                    f.write(f"""
environment = "lab"
output_dir = "{d}/runs"
requests_per_phase = 2
scan_delay_seconds = 0
[border]
allowed_locations = ["DE"]
[target]
url = "{url}"
prompt = "ref {{{{canary}}}} acct {{{{account}}}}"
body = '{{"user": "{{{{request_id}}}}", "messages": [{{"role": "user", "content": "{{{{prompt}}}}"}}]}}'
record_fields = ["model"]
record_headers = ["x-litellm-model-api-base"]
pause_seconds = 0
[fault]
start = "touch {fault_file}"
stop = "rm -f {fault_file}"
settle_seconds = 0
[[sources]]
name = "App logs"
type = "path"
path = "{app_log}"
layer = "logs"
location = "DE"
[[sources]]
name = "Egress proxy"
type = "path"
path = "{egress_log}"
layer = "logs"
location = "DE"
egress = true
""")
                with open(os.devnull, "w") as null, contextlib.redirect_stdout(null):
                    rc = cli.main(["-c", cfg_path, "all", "--yes", "--redact"])
            self.assertEqual(rc, 1, "egress to a public API during the fault is a fail")
            self.assertFalse(os.path.exists(fault_file), "fault stop ran")
            run_id = os.listdir(os.path.join(d, "runs"))[0]
            run_path = os.path.join(d, "runs", run_id)
            with open(os.path.join(run_path, "summary.json")) as f:
                summary = json.load(f)
            with open(os.path.join(run_path, "report.md")) as f:
                text = f.read()
            self.assertEqual([p["name"] for p in summary["places"]], ["App logs"])
            self.assertEqual(summary["egress_destinations"], {"Egress proxy": {"api.openai.com": 2}})
            self.assertEqual(summary["phases"]["fault"]["answered"], 2)
            self.assertEqual(summary["verdict"], "fail")
            self.assertIn("## Verdict: FAIL", text)
            self.assertIn("https://api.openai.com", text)
            self.assertNotIn("vllm.lab.internal", text)
            self.assertNotIn(d, text)
            self.assertEqual(os.stat(run_path).st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
