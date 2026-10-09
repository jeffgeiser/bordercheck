"""Read-only search of the stores you list for the canary, the account number and harness request ids.

Hits record where (source, file, line or byte offset) and which pattern matched. The matching
content itself is never copied into the results.

Source commands, URLs and paths can use the run's time window, so a scan covers exactly the run
rather than "the last two hours": {{run_started}} and {{run_ended}} (ISO 8601 UTC, widened by
clock_skew_seconds), {{run_started_epoch}}, {{run_minutes}} (whole minutes since the run started,
for flags like --since=...m) and {{run_id}}. An http URL with {{page}} is fetched page by page.
"""
import bz2
import json
import lzma
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib

from . import net
from .canary import IDENTIFIER_KINDS
from .config import expand_env, require_env
from .send import render

CHUNK = 1 << 20
OVERLAP = 512
MAX_HITS_PER_PATTERN = 50
MAX_PAGE_BYTES = 64 << 20


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def window(run, end=None, skew=120):
    """Placeholder values for the run's time window. Values are digits, letters, ':' and '-' only,
    so they're safe to put in a shell command."""
    start = run["created"] - skew
    end = (end or time.time()) + skew
    return {
        "run_id": run["run_id"],
        "run_started": _iso(start), "run_ended": _iso(end),
        "run_started_epoch": str(int(start)),
        "run_minutes": str(math.ceil((time.time() - start) / 60)),
    }


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
    with open(path, "rb") as f:
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
        e.close()   # an error response is still an open connection
        raise SourceError(f"HTTP {e.code}" + (" (redirects are not followed)" if 300 <= e.code < 400 else ""))


def _last_page(body, page):
    """True when a paged JSON response says there's nothing after `page` (Langfuse's meta.totalPages,
    or an empty `data` list). Anything that isn't JSON is treated as a single page."""
    try:
        doc = json.loads(body)
    except ValueError:
        return True
    if not isinstance(doc, dict):
        return True
    total = (doc.get("meta") or {}).get("totalPages") if isinstance(doc.get("meta"), dict) else None
    data = doc.get("data")
    return (isinstance(total, int) and page >= total) or (isinstance(data, list) and not data)


def _http_pages(url, headers, ca_file, timeout, max_pages):
    for page in range(1, max_pages + 1):
        req = urllib.request.Request(expand_env(url.replace("{{page}}", str(page))), headers=headers)
        try:
            with net.opener(req.full_url, ca_file).open(req, timeout=timeout) as resp:
                body, truncated = net.read_capped(resp, MAX_PAGE_BYTES)
        except urllib.error.HTTPError as e:
            e.close()
            raise SourceError(f"page {page}: HTTP {e.code}")
        yield page, body
        if truncated or _last_page(body, page):
            return
    print(f"\n    stopped at max_pages = {max_pages}; there may be more", end="")


# Compression is recognised from the data itself, not a file name: rotated logs, S3 objects and
# command output often carry no extension. Formats bordercheck can't decode are reported as
# errors, so a store full of them is never mistaken for a clean one.
GZIP, ZSTD, BZIP2, XZ = b"\x1f\x8b", b"\x28\xb5\x2f\xfd", b"BZh", b"\xfd7zXZ\x00"
UNREADABLE = [
    (b"PAR1", "Parquet"),
    (b"ORC", "ORC"),
    (b"Obj\x01", "Avro"),
    (b"\xff\x06\x00\x00sNaPpY", "Snappy-framed"),
    (b"\x04\x22\x4d\x18", "LZ4"),
    (b"PK\x03\x04", "ZIP"),
]


def _zstd_decompressor():
    try:
        from compression import zstd   # standard library from Python 3.14
    except ImportError:
        return None
    return zstd.ZstdDecompressor


def _stream(first, rest, new, magic, name):
    """Decompress a stream of chunks with an incremental decompressor. Handles concatenated
    members (rotated and appended gzip logs); stops at trailing bytes that aren't another member.
    Each call returns at most CHUNK bytes, so a small file that expands to gigabytes is searched
    piece by piece instead of being held in memory."""
    state = {"d": new(), "fed": False}

    def feed(data):
        while True:
            d = state["d"]
            try:
                out = d.decompress(data, CHUNK)
            except Exception:
                raise SourceError(f"{name} data is corrupt; searched up to that point")
            state["fed"] = True
            if out:
                yield out
            if d.eof:
                data = d.unused_data
                if not data.startswith(magic):
                    return
                state["d"], state["fed"] = new(), False
            elif hasattr(d, "unconsumed_tail"):   # zlib keeps input it hasn't decoded yet
                data = d.unconsumed_tail
                if not data:
                    return
            elif d.needs_input:                     # bz2, lzma, zstd buffer it internally
                return
            else:
                data = b""

    yield from feed(first)
    for chunk in rest:
        yield from feed(chunk)
    if state["fed"] and not state["d"].eof:
        raise SourceError(f"{name} data ended early; searched up to that point")


def _zstd_command(first, rest):
    """Decode zstd with the zstd command, for Pythons without compression.zstd."""
    proc = subprocess.Popen(["zstd", "-dcq"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    feeder_error = []

    def feed():
        try:
            proc.stdin.write(first)
            for chunk in rest:
                proc.stdin.write(chunk)
        except BrokenPipeError:
            pass
        except Exception as e:   # e.g. the source command failing; re-raised below
            feeder_error.append(e)
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    try:
        while True:
            block = proc.stdout.read(CHUNK)
            if not block:
                break
            yield block
    finally:
        proc.stdout.close()
        writer.join()
        code = proc.wait()
    if feeder_error:
        raise feeder_error[0]
    if code != 0:
        raise SourceError("zstd data is corrupt; searched up to that point")


def _decode(chunks):
    """Pass plain data through; decompress gzip, zstd, bzip2 and xz; refuse formats it can't read.

    The first 16 bytes decide. If the source fails while those are being read (a command that
    prints one line, then exits non-zero), what was read is still searched before the error is raised.
    """
    chunks = iter(chunks)
    first, pending = b"", None
    try:
        for chunk in chunks:
            first += chunk
            if len(first) >= 16:
                break
    except Exception as e:
        pending, chunks = e, iter(())
    try:
        yield from _by_format(first, chunks)
    except SourceError:
        if pending:
            raise pending   # the source's own failure explains a short stream better
        raise
    if pending:
        raise pending


def _by_format(first, chunks):
    if first.startswith(GZIP):
        yield from _stream(first, chunks, lambda: zlib.decompressobj(31), GZIP, "gzip")
    elif first.startswith(ZSTD):
        new = _zstd_decompressor()
        if new:
            yield from _stream(first, chunks, new, ZSTD, "zstd")
        elif shutil.which("zstd"):
            yield from _zstd_command(first, chunks)
        else:
            raise SourceError("zstd-compressed data found but no decoder: use Python 3.14+ or install the "
                              "zstd command; nothing here was searched")
    elif first.startswith(BZIP2):
        yield from _stream(first, chunks, bz2.BZ2Decompressor, BZIP2, "bzip2")
    elif first.startswith(XZ):
        yield from _stream(first, chunks, lzma.LZMADecompressor, XZ, "xz")
    else:
        for magic, name in UNREADABLE:
            if first.startswith(magic):
                raise SourceError(f"{name} data: bordercheck can't decode this format, so it wasn't searched")
        if first:
            yield first
        yield from chunks


def _iter_targets(src, values=None):
    """Yield (where, chunk iterator) pairs for one configured source.

    `where` comes from the config as written (before ${VAR} expansion), so it never holds secrets.
    """
    values = values or {}
    kind = src["type"]
    if kind == "path":
        for root in [src["path"]] if isinstance(src["path"], str) else src["path"]:
            root = os.path.expanduser(render(root, values))
            if not os.path.exists(root):
                raise SourceError(f"{root} does not exist")
            if os.path.isfile(root):
                yield root, _decode(_file_chunks(root))
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in sorted(files):
                    full = os.path.join(dirpath, name)
                    yield full, _decode(_file_chunks(full))
    elif kind == "command":
        command = require_env(render(src["command"], values))
        yield "command output", _decode(_command_chunks(command, float(src.get("timeout_seconds", 300))))
    elif kind == "http":
        urls = [src["url"]] if isinstance(src["url"], str) else src["url"]
        headers = expand_env(dict(src.get("headers", {})))
        timeout = float(src.get("timeout_seconds", 60))
        for url in urls:
            url = render(url, values)
            if "{{page}}" in url:
                for page, body in _http_pages(url, headers, src.get("ca_file"), timeout, int(src.get("max_pages", 20))):
                    yield url.replace("{{page}}", str(page)), _decode([body])
            else:
                yield url, _decode(_http_chunks(url, headers, src.get("ca_file"), timeout))


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


def scan_sources(cfg, needles, values=None):
    watch = [(p, _watch_regex(p)) for p in cfg["watch_destinations"]]
    results = []
    for src in cfg.get("sources", []):
        entry = {k: src.get(k) for k in ("name", "type", "layer", "location")}
        entry["egress"] = bool(src.get("egress"))
        entry["positive_control"] = bool(src.get("positive_control"))
        # Egress logs rarely record request ids; every other store should, if it's on the path.
        entry["expect_request_ids"] = bool(src.get("expect_request_ids", not entry["egress"]))
        entry.update(hits=[], targets_scanned=0, errors=[], truncated=[])
        print(f"  scanning {src['name']} ...", end="", flush=True)
        try:
            for where, chunks in _iter_targets(src, values):
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
        n = sum(1 for h in entry["hits"] if h["kind"] in IDENTIFIER_KINDS)
        print(f" {entry['targets_scanned']} target(s), {n} identifier hit(s)"
              f"{', ERRORS' if entry['errors'] else ''}"
              f"{'  (nothing to scan: check the path, query or time window)' if not entry['targets_scanned'] and not entry['errors'] else ''}")
        results.append(entry)
    return results
