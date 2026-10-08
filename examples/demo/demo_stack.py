"""Run bordercheck against a simulated AI stack, with no setup. Standard library only.

    python examples/demo/demo_stack.py              # writes ./demo-runs/, prints the verdict
    python examples/demo/demo_stack.py --pace 0.3   # slower output, for screen recordings

The simulated stack is a stand-in for a typical self-hosted setup:

- a LiteLLM-style gateway that answers with a local model, and falls back to a public API when
  the prompt is too long for the local model or the local model is down (the fault)
- an app that masks customer names in its answers
- gateway logs that keep only request ids
- tracing that stores whole requests base64-encoded
- a hosted log analytics service in the US, which masks email but nothing else
- a semantic cache that keeps prompts
- a vector store that holds unrelated documents
- an egress proxy log

Nothing leaves your machine: the gateway listens on localhost and the "public API" is only a
hostname written to the egress log. Expect a FAIL with exit code 1.
"""
import argparse
import base64
import json
import os
import re
import shlex
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from bordercheck import cli  # noqa: E402

STORES = ("gateway.log", "tracing.jsonl", "log-analytics.jsonl", "cache.txt", "vectors.txt", "egress.log")


def gateway(stack):
    lock = threading.Lock()

    def path(name):
        return os.path.join(stack, name)

    class Gateway(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            req = json.loads(body)
            prompt = req["messages"][0]["content"]
            public = os.path.exists(path("fault")) or len(body) > 20000
            with lock:
                with open(path("gateway.log"), "a") as f:
                    f.write(f"{time.strftime('%H:%M:%S')} user={req['user']} route={'openai' if public else 'local'}\n")
                with open(path("tracing.jsonl"), "a") as f:
                    f.write(json.dumps({"traceId": req["user"], "payload": base64.b64encode(body).decode()}) + "\n")
                with open(path("log-analytics.jsonl"), "a") as f:
                    masked = re.sub(r"\S+@example\.com", "<EMAIL>", prompt[:400])
                    f.write(json.dumps({"user": req["user"], "input": masked}) + "\n")
                with open(path("cache.txt"), "a") as f:
                    f.write("llm:cache:" + prompt[:400] + "\n")
                if public:
                    with open(path("egress.log"), "a") as f:
                        f.write(f"{time.strftime('%H:%M:%S')} CONNECT api.openai.com:443 200\n")
            answer = "[CUSTOMER_NAME] applied for a mortgage of EUR 650,000."
            out = json.dumps({"model": "gpt-4o-mini" if public else "qwen2.5-32b-instruct",
                              "choices": [{"message": {"content": answer}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("x-litellm-model-api-base",
                             "https://api.openai.com/v1" if public else "http://vllm.internal:8000/v1")
            self.end_headers()
            self.wfile.write(out)

    return Gateway


def config(stack, url, pace=0.0):
    """Write the config. Paths are relative to the current folder when the stack is inside it,
    so nothing the run prints (commands, report paths) shows the home directory."""
    q = shlex.quote
    if stack.startswith(os.getcwd() + os.sep):
        stack = os.path.relpath(stack)
    fault = os.path.join(stack, "fault")

    def source(name, file, layer, location, extra=""):
        return (f'\n[[sources]]\nname = "{name}"\ntype = "path"\npath = {json.dumps(os.path.join(stack, file))}\n'
                f'layer = "{layer}"\nlocation = "{location}"\n{extra}')

    text = f'''environment = "demo"
output_dir = {json.dumps(os.path.join(stack, "runs"))}
requests_per_phase = 5
scan_delay_seconds = 0

[border]
name = "Germany"
allowed_locations = ["DE"]

[target]
url = "{url}"
prompt = "Customer {{{{name}}}} (ref {{{{canary}}}}, account {{{{account}}}}, IBAN {{{{iban}}}}, email {{{{email}}}}, phone {{{{phone}}}}) applied for a {{{{product}}}} of {{{{amount}}}}. Summarize it."
body = '{{"model": "default", "user": "{{{{request_id}}}}", "messages": [{{"role": "user", "content": "{{{{prompt}}}}"}}]}}'
record_fields = ["model"]
record_headers = ["x-litellm-model-api-base"]
pause_seconds = {pace}

[fault]
start = {json.dumps("touch " + q(fault))}
stop = {json.dumps("rm -f " + q(fault))}
settle_seconds = {pace * 3}

[probes.context_window]
pad_tokens = 8000
requests = 3

[report]
regulatory_appendix = true
'''
    text += source("Gateway logs", "gateway.log", "logs", "DE")
    text += source("Tracing events", "tracing.jsonl", "logs", "DE", "positive_control = true\n")
    text += source("Hosted log analytics", "log-analytics.jsonl", "logs", "US")
    text += source("Semantic cache", "cache.txt", "model_state", "DE")
    text += source("Vector store", "vectors.txt", "model_state", "DE")
    text += source("Egress proxy", "egress.log", "logs", "DE", "egress = true\n")
    path = os.path.join(stack, "bordercheck.toml")
    with open(path, "w") as f:
        f.write(text)
    return path


def slow_scan(seconds):
    """Pause before each source is scanned, so the progress lines can be read on a recording.
    Demo only: a real run should never be slowed down on purpose."""
    from bordercheck import scan
    original = scan._iter_targets

    def paced(src, values=None):
        time.sleep(seconds)
        yield from original(src, values)

    scan._iter_targets = paced


def main(out_dir="demo-runs", extra_args=(), pace=0.0):
    stack = os.path.abspath(out_dir)
    shutil.rmtree(stack, ignore_errors=True)
    os.makedirs(stack)
    for name in STORES:
        open(os.path.join(stack, name), "w").close()
    with open(os.path.join(stack, "vectors.txt"), "w") as f:
        f.write("doc-0412 Mortgage policy: loan-to-value limits for owner-occupied property.\n")

    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway(stack))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = config(stack, f"http://127.0.0.1:{server.server_port}/v1/chat/completions", pace)
        if pace:
            slow_scan(pace * 3)
        rc = cli.main(["-c", cfg, "all", "--yes", *extra_args])
    finally:
        server.shutdown()
        server.server_close()
    run = sorted(os.listdir(os.path.join(stack, "runs")))[-1]
    summary = os.path.join(stack, "runs", run, "summary.html")
    shown = os.path.relpath(summary) if summary.startswith(os.getcwd() + os.sep) else summary
    print(f"\nopen {shown} for the one-page summary")
    return rc


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Run bordercheck against a simulated AI stack on localhost.")
    p.add_argument("out_dir", nargs="?", default="demo-runs", help="where to write the stack and runs (default demo-runs)")
    p.add_argument("--pace", type=float, default=0.0, metavar="SECONDS",
                   help="pause between requests (and 3x that between sources), for screen recordings; try 0.3")
    p.add_argument("--redact", action="store_true", help="write a shareable report (no paths or URLs)")
    args = p.parse_args()
    sys.exit(main(args.out_dir, ["--redact"] if args.redact else [], args.pace))
