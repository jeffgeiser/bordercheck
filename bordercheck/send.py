"""Send requests carrying the canary through your normal entry point and record who answered.

Only metadata is kept: status, timing, the "served by" fields you choose, and whether the
canary came back in the response. Response bodies are not stored.

Besides the baseline and fault phases, probes check the failovers that happen with nothing down:
a prompt longer than the local model's context window, a burst that hits a rate limit, and a
prompt the local model or a guardrail rejects. Gateways can send each of those to a cloud model.
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request

from . import net
from .config import expand_env

MAX_RESPONSE_BYTES = 10 << 20
MAX_RECORDED_CHARS = 200

FILLER = "Note {i}: routine correspondence on file, no action needed. "


def render(template, values):
    out = template
    for key, val in values.items():
        out = out.replace("{{" + key + "}}", str(val))
    return out


def render_body(template, values):
    """Like render, but JSON-escapes values so a prompt can't break the request body."""
    escaped = {k: json.dumps(str(v))[1:-1] for k, v in values.items()}
    return render(template, escaped)


def get_path(obj, dotted):
    for part in dotted.split("."):
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def _recordable(val):
    """Served-by values are meant to be short labels. Anything else could be response content."""
    if val is None or isinstance(val, (bool, int, float)):
        return val
    if not isinstance(val, str):
        return f"[{type(val).__name__} not recorded]"
    return val if len(val) <= MAX_RECORDED_CHARS else val[:MAX_RECORDED_CHARS] + "…"


def padding(tokens):
    """Neutral filler of roughly `tokens` tokens (about 4 characters each), with no identifiers."""
    out, i, size = [], 0, 0
    while size < tokens * 4:
        line = FILLER.format(i=i)
        out.append(line)
        size += len(line)
        i += 1
    return "".join(out)


def probe_settings(cfg, name):
    """(prompt template, requests, concurrency) for one configured probe."""
    probe = cfg["probes"][name]
    prompt = cfg["target"]["prompt"]
    if name == "context_window":
        prompt += "\n\nCase notes:\n" + padding(int(probe.get("pad_tokens", 40000)))
    elif name == "content_policy":
        prompt = probe["prompt"]
    concurrency = int(probe.get("concurrency", 20 if name == "rate_limit" else 1))
    return prompt, int(probe.get("requests", 60 if name == "rate_limit" else 3)), concurrency


def send_phase(cfg, run, phase, n=None, prompt=None, concurrency=1):
    """Send n requests labelled `phase`. prompt replaces [target] prompt (probes use this);
    concurrency > 1 sends them in parallel, with no pause, as the rate-limit probe does."""
    target = cfg["target"]
    n = n or cfg["requests_per_phase"]
    record = run["record"]
    headers = expand_env(dict(target.get("headers", {})))
    headers.setdefault("Content-Type", "application/json")
    http = net.opener(target["url"], target.get("ca_file"))
    timeout = float(target.get("timeout_seconds", 60))
    template = prompt or target["prompt"]
    slug = phase.replace(":", "-")

    def one(i):
        req_id = f"{run['run_id']}-{slug}-{i:03d}"
        values = dict(record, request_id=req_id, run_id=run["run_id"])
        body = render_body(target["body"], dict(values, prompt=render(template, values))).encode()
        req = urllib.request.Request(
            target["url"],
            data=body,
            method=target.get("method", "POST"),
            headers=dict(headers, **{cfg["request_id_header"]: req_id}),
        )
        entry = {"request_id": req_id, "phase": phase, "sent": time.time()}
        start = time.perf_counter()
        try:
            with http.open(req, timeout=timeout) as resp:
                raw, entry["response_truncated"] = net.read_capped(resp, MAX_RESPONSE_BYTES)
                entry["status"] = resp.status
                entry["headers"] = {h: _recordable(resp.headers.get(h)) for h in target.get("record_headers", [])}
        except urllib.error.HTTPError as e:
            with e:   # an error response is still an open connection
                raw, entry["response_truncated"] = net.read_capped(e, MAX_RESPONSE_BYTES)
                entry["status"] = e.code
                entry["headers"] = {h: _recordable(e.headers.get(h)) for h in target.get("record_headers", [])}
        except Exception as e:  # timeouts, refused connections, TLS errors
            raw = b""
            entry["status"] = None
            entry["error"] = type(e).__name__
        entry["seconds"] = round(time.perf_counter() - start, 3)
        entry["response_bytes"] = len(raw)
        entry["canary_in_response"] = record["canary"].encode() in raw
        entry["account_in_response"] = record["account"].encode() in raw
        fields = {}
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        for path in target.get("record_fields", []):
            val = get_path(parsed, path) if parsed is not None else None
            fields[path] = _recordable(val)
        entry["fields"] = fields
        ok = entry["status"] is not None and 200 <= entry["status"] < 300
        print(f"  {req_id}  status={entry['status']}  {entry['seconds']}s  {fields if fields else ''}"
              f"{'' if ok else '  ' + entry.get('error', '')}")
        if concurrency == 1:
            time.sleep(float(target.get("pause_seconds", 0.2)))
        return entry

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        results = list(pool.map(one, range(n)))
    run["requests"].extend(results)
    return results
