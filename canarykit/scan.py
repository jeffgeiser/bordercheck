"""Read-only search of the stores you list for the canary, the account number and harness request ids.

Hits record where (source, file, line or byte offset) and which pattern matched. The matching
content itself is never copied into the results.
"""
import gzip
import os
import re
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request

from . import net
from .config import expand_env, require_env

CHUNK = 1 << 20
OVERLAP = 512
MAX_HITS_PER_PATTERN = 50


def _watch_regex(pattern):
    parts = [re.escape(p) for p in pattern.lower().split("*")]
    # Whole hostnames only: "api.openai.com" shouldn't match inside "myapi.openai.com".
    return re.compile(("(?<![a-z0-9-])" + "[a-z0-9-]*".join(parts) + "(?![a-z0-9-])").encode(), re.IGNORECASE)


def scan_stream(chunks, needles, watch):
    """Search a stream of byte chunks. Overlapping windows catch matches that span chunk edges."""
    hits, seen, counts = [], set(), {}
    tail, tail_lines, total = b"", 0, 0
    for chunk in chunks:
        buf = tail + chunk
        buf_start = total - len(tail)

        def add(kind, label, idx, extra=None):
            key = (label, buf_start + idx)
            if key in seen or counts.get(label, 0) >= MAX_HITS_PER_PATTERN:
                return
            seen.add(key)
            counts[label] = counts.get(label, 0) + 1
            hit = {"kind": kind, "label": label, "offset": buf_start + idx,
                   "line": tail_lines + buf.count(b"\n", 0, idx) + 1}
            if extra:
                hit.update(extra)
            hits.append(hit)

        for kind, label, pattern in needles:
            i = buf.find(pattern)
            while i != -1:
                add(kind, label, i)
                i = buf.find(pattern, i + 1)
        for name, rx in watch:
            for m in rx.finditer(buf):
                add("egress", f"egress: {name}", m.start(), {"destination": m.group(0).decode(errors="replace")})

        total += len(chunk)
        keep = min(len(buf), OVERLAP)
        tail_lines += buf.count(b"\n", 0, len(buf) - keep)
        tail = buf[len(buf) - keep:]
    truncated = [label for label, c in counts.items() if c >= MAX_HITS_PER_PATTERN]
    return hits, truncated


def _file_chunks(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                return
            yield block


def _bytes_chunks(data):
    for i in range(0, len(data), CHUNK):
        yield data[i:i + CHUNK]


class SourceError(Exception):
    """An error whose message is safe to store: it never includes data read from the source."""


def _command_chunks(command, timeout):
    """Stream a shell command's stdout. stderr is shown on the terminal, never stored."""
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=err)
        killed = threading.Event()
        timer = threading.Timer(timeout, lambda: (killed.set(), proc.kill()))
        timer.start()
        try:
            while True:
                block = proc.stdout.read(CHUNK)
                if not block:
                    break
                yield block
        finally:
            timer.cancel()
            proc.stdout.close()
            code = proc.wait()
        if code != 0:
            err.seek(0)
            detail = err.read(2000).decode(errors="replace").strip()
            if detail:
                print("\n    stderr: " + detail.replace("\n", "\n    ") + "\n   ", end="")
            if killed.is_set():
                raise SourceError(f"command killed after {timeout:.0f}s timeout")
            raise SourceError(f"command exited {code} (stderr shown on the terminal, not stored)")


def _http_chunks(url, headers, ca_file, timeout):
    req = urllib.request.Request(expand_env(url), headers=headers)
    try:
        with net.opener(req.full_url, ca_file).open(req, timeout=timeout) as resp:
            while True:
                block = resp.read(CHUNK)
                if not block:
                    return
                yield block
    except urllib.error.HTTPError as e:
        raise SourceError(f"HTTP {e.code}" + (" (redirects are not followed)" if 300 <= e.code < 400 else ""))


def _iter_targets(src):
    """Yield (where, chunk iterator) pairs for one configured source.

    `where` comes from the config as written (before ${VAR} expansion), so it never holds secrets.
    """
    kind = src["type"]
    if kind == "path":
        for root in [src["path"]] if isinstance(src["path"], str) else src["path"]:
            root = os.path.expanduser(root)
            if not os.path.exists(root):
                raise SourceError(f"{root} does not exist")
            if os.path.isfile(root):
                yield root, _file_chunks(root)
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in sorted(files):
                    full = os.path.join(dirpath, name)
                    yield full, _file_chunks(full)
    elif kind == "command":
        command = require_env(src["command"])
        yield "command output", _command_chunks(command, float(src.get("timeout_seconds", 300)))
    elif kind == "http":
        urls = [src["url"]] if isinstance(src["url"], str) else src["url"]
        headers = expand_env(dict(src.get("headers", {})))
        for url in urls:
            yield url, _http_chunks(url, headers, src.get("ca_file"), float(src.get("timeout_seconds", 60)))


def _safe_error(e):
    """Describe an exception without copying data from the source into scan.json.

    Some library messages quote what they read (gzip quotes the first bytes of a bad file),
    so only messages we wrote, or the OS error text, are kept.
    """
    if isinstance(e, SourceError):
        return str(e)
    if isinstance(e, OSError) and e.strerror:
        return f"{type(e).__name__}: {e.strerror}"
    return type(e).__name__


def _guard(chunks, failures):
    """Pass chunks through, but turn a read failure into a recorded error so earlier hits are kept."""
    try:
        yield from chunks
    except (SourceError, OSError, EOFError) as e:
        failures.append(_safe_error(e))


def scan_sources(cfg, needles):
    watch = [(p, _watch_regex(p)) for p in cfg["watch_destinations"]]
    results = []
    for src in cfg.get("sources", []):
        entry = {k: src.get(k) for k in ("name", "type", "layer", "location")}
        entry["egress"] = bool(src.get("egress"))
        entry.update(hits=[], targets_scanned=0, errors=[], truncated=[])
        print(f"  scanning {src['name']} ...", end="", flush=True)
        try:
            for where, chunks in _iter_targets(src):
                failures = []
                hits, truncated = scan_stream(_guard(chunks, failures), needles, watch if src.get("egress") else [])
                if failures:
                    entry["errors"].extend(f"{where}: {f}" for f in failures)
                else:
                    entry["targets_scanned"] += 1
                for h in hits:
                    h["where"] = where
                entry["hits"].extend(hits)
                entry["truncated"].extend(f"{where}: {t}" for t in truncated)
        except Exception as e:
            entry["errors"].append(_safe_error(e))
        n = sum(1 for h in entry["hits"] if h["kind"] in ("canary", "account"))
        print(f" {entry['targets_scanned']} target(s), {n} canary/account hit(s)"
              f"{', ERRORS' if entry['errors'] else ''}")
        results.append(entry)
    return results
