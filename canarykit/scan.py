"""Read-only search of the stores you list for the canary, the account number and harness request ids.

Hits record where (source, file, line or byte offset) and which pattern matched. The matching
content itself is never copied into the results.
"""
import gzip
import os
import re
import ssl
import subprocess
import urllib.request

from .config import expand_env

CHUNK = 1 << 20
OVERLAP = 512
MAX_HITS_PER_PATTERN = 50


def _watch_regex(pattern):
    parts = [re.escape(p) for p in pattern.lower().split("*")]
    return re.compile("[a-z0-9-]*".join(parts).encode(), re.IGNORECASE)


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


def _iter_targets(src):
    """Yield (where, chunk iterator) pairs for one configured source."""
    kind = src["type"]
    if kind == "path":
        for root in [src["path"]] if isinstance(src["path"], str) else src["path"]:
            root = os.path.expanduser(root)
            if not os.path.exists(root):
                raise FileNotFoundError(f"{root} does not exist")
            if os.path.isfile(root):
                yield root, _file_chunks(root)
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in sorted(files):
                    full = os.path.join(dirpath, name)
                    yield full, _file_chunks(full)
    elif kind == "command":
        done = subprocess.run(expand_env(src["command"]), shell=True, capture_output=True,
                              timeout=float(src.get("timeout_seconds", 300)))
        if done.returncode != 0:
            raise RuntimeError(f"command exited {done.returncode}: {done.stderr.decode(errors='replace')[:300]}")
        yield "command output", _bytes_chunks(done.stdout)
    elif kind == "http":
        urls = [src["url"]] if isinstance(src["url"], str) else src["url"]
        headers = expand_env(dict(src.get("headers", {})))
        ctx = ssl.create_default_context(cafile=src.get("ca_file") or None)
        for url in urls:
            req = urllib.request.Request(expand_env(url), headers=headers)
            with urllib.request.urlopen(req, timeout=float(src.get("timeout_seconds", 60)),
                                        context=ctx if url.startswith("https") else None) as resp:
                yield url, _bytes_chunks(resp.read())


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
                try:
                    hits, truncated = scan_stream(chunks, needles, watch if src.get("egress") else [])
                except OSError as e:
                    entry["errors"].append(f"{where}: {e}")
                    continue
                entry["targets_scanned"] += 1
                for h in hits:
                    h["where"] = where
                entry["hits"].extend(hits)
                entry["truncated"].extend(f"{where}: {t}" for t in truncated)
        except Exception as e:
            entry["errors"].append(f"{type(e).__name__}: {e}")
        n = sum(1 for h in entry["hits"] if h["kind"] in ("canary", "account"))
        print(f" {entry['targets_scanned']} target(s), {n} canary/account hit(s)"
              f"{', ERRORS' if entry['errors'] else ''}")
        results.append(entry)
    return results
