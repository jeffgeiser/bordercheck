"""Send requests carrying the canary through your normal entry point and record who answered.

Only metadata is kept: status, timing, the "served by" fields you choose, and whether the
canary came back in the response. Response bodies are not stored.
"""
import json
import time
import urllib.error
import urllib.request

from . import net
from .config import expand_env

MAX_RESPONSE_BYTES = 10 << 20
MAX_RECORDED_CHARS = 200


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


def send_phase(cfg, run, phase, n=None):
    target = cfg["target"]
    n = n or cfg["requests_per_phase"]
    record = run["record"]
    headers = expand_env(dict(target.get("headers", {})))
    headers.setdefault("Content-Type", "application/json")
    http = net.opener(target["url"], target.get("ca_file"))
    timeout = float(target.get("timeout_seconds", 60))

    results = []
    for i in range(n):
        req_id = f"{run['run_id']}-{phase}-{i:03d}"
        values = dict(record, request_id=req_id, run_id=run["run_id"])
        prompt = render(target["prompt"], values)
        body = render_body(target["body"], dict(values, prompt=prompt)).encode()
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
        results.append(entry)
        ok = entry["status"] is not None and 200 <= entry["status"] < 300
        print(f"  {req_id}  status={entry['status']}  {entry['seconds']}s  {fields if fields else ''}"
              f"{'' if ok else '  ' + entry.get('error', '')}")
        time.sleep(float(target.get("pause_seconds", 0.2)))
    run["requests"].extend(results)
    return results
