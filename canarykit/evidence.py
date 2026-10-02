"""Evidence you can hand to an auditor, and comparisons over time.

- manifest.json: SHA-256 of every run file, the canarykit and Python versions, and a hash of the
  config (which holds no secrets). Written after every report.
- an evidence bundle: the run folder and manifest in one zip, whose own hash you can record in a
  ticket or sign (for example `cosign sign-blob` or `gpg --detach-sign`). `verify` rechecks it.
- diff: what changed between two runs, and whether that's a regression.
- retention: which stores still hold the customer when you scan again later.

A manifest makes changes detectable, not impossible: anyone who can edit the files can rewrite
it. Signing the bundle, or storing its hash somewhere they can't edit, is what makes it binding.
"""
import hashlib
import json
import os
import platform
import sys
import time
import zipfile

from . import __version__

MANIFEST = "manifest.json"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _run_files(run_path):
    return sorted(n for n in os.listdir(run_path)
                  if n != MANIFEST and not n.endswith((".tmp", ".zip")) and os.path.isfile(os.path.join(run_path, n)))


def manifest(run_path, config_path, run_id, verdict):
    return {
        "run_id": run_id,
        "verdict": verdict,
        "written_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "canarykit_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.system() + " " + platform.machine(),
        "config": {"file": os.path.basename(config_path), "sha256": sha256_file(config_path)},
        "files": {n: sha256_file(os.path.join(run_path, n)) for n in _run_files(run_path)},
    }


def bundle(run_path, out_path, include_config=None):
    """Zip the run folder (and optionally the config) with its manifest. Returns the zip's SHA-256."""
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f, zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as z:
        for name in _run_files(run_path) + [MANIFEST]:
            z.write(os.path.join(run_path, name), name)
        if include_config:
            z.write(include_config, "config/" + os.path.basename(include_config))
    return sha256_file(out_path)


def verify(zip_path):
    """[] if every file in the bundle matches its manifest, else a list of problems."""
    problems = []
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
        if MANIFEST not in names:
            return ["no manifest.json in the bundle"]
        doc = json.loads(z.read(MANIFEST))
        listed = doc["files"]
        for name, digest in listed.items():
            if name not in names:
                problems.append(f"{name}: listed in the manifest but missing")
            elif hashlib.sha256(z.read(name)).hexdigest() != digest:
                problems.append(f"{name}: contents don't match the manifest")
        configs = {n for n in names if n.startswith("config/")}
        for name in configs:
            if hashlib.sha256(z.read(name)).hexdigest() != doc["config"]["sha256"]:
                problems.append(f"{name}: doesn't match the config hash in the manifest")
        extra = names - set(listed) - {MANIFEST} - configs
        problems += [f"{name}: not listed in the manifest" for name in sorted(extra)]
    return problems


# ---------------------------------------------------------------------------
# Comparing runs
# ---------------------------------------------------------------------------

SEVERITY = {"pass": 0, "inconclusive": 1, "fail": 2}


def _served(summary):
    return {name: set(p["served_by"]) for name, p in summary["phases"].items()}


def diff(old, new):
    """(markdown, regressed) comparing two summary.json documents."""
    L = [f"# canarykit diff: {new['run_id']} against {old['run_id']}\n"]
    regressed = False

    L.append(f"- Verdict: {old['verdict'].upper()} -> **{new['verdict'].upper()}**")
    if SEVERITY[new["verdict"]] > SEVERITY[old["verdict"]]:
        regressed = True

    def change(label, before, after, worse_if_added=True):
        nonlocal regressed
        added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
        if added:
            L.append(f"- {label}, new: " + ", ".join(f"**{x}**" for x in added))
            regressed = regressed or worse_if_added
        if removed:
            L.append(f"- {label}, no longer seen: " + ", ".join(removed))

    def places(summary, inside):
        return [p["name"] for p in summary["places"] if p["inside"] == inside]

    change("Places outside the border holding identifiers", places(old, False), places(new, False))
    change("Places inside the border holding identifiers", places(old, True), places(new, True), worse_if_added=False)
    change("Egress to disallowed model APIs", old["egress_outside_border"], new["egress_outside_border"])
    change("Layers not checked", old["layers_not_checked"], new["layers_not_checked"])

    old_kinds = {s["name"]: set(s.get("kinds_found", [])) for s in old.get("sources", [])}
    for s in new.get("sources", []):
        newly = sorted(set(s.get("kinds_found", [])) - old_kinds.get(s["name"], set()))
        if s["name"] in old_kinds and newly:
            L.append(f"- **{s['name']}** now keeps: {', '.join(newly)} (redaction may have regressed)")
            regressed = True

    old_served, new_served = _served(old), _served(new)
    for phase in sorted(set(old_served) | set(new_served)):
        if old_served.get(phase) != new_served.get(phase):
            L.append(f"- {phase} served by: {', '.join(sorted(old_served.get(phase, []))) or '(not run)'} -> "
                     f"{', '.join(sorted(new_served.get(phase, []))) or '(not run)'}")
    if len(L) == 2:
        L.append("- No other changes.")
    L.append(f"\n**{'Regression' if regressed else 'No regression'}.**\n")
    return "\n".join(L), regressed


def retention(first_scan, later_scan, kinds, scanned_at, run_id):
    """(markdown, still_held) comparing the original scan with one made later."""
    def held(scan):
        return {s["name"]: sum(1 for h in s["hits"] if h["kind"] in kinds) for s in scan}
    before, after = held(first_scan), held(later_scan)
    errors = {s["name"]: bool(s["errors"]) for s in later_scan}
    L = [f"# canarykit retention check: {run_id}\n",
         f"Rescanned {time.strftime('%Y-%m-%d %H:%M', time.localtime())}, "
         f"{(time.time() - scanned_at) / 86400:.1f} days after the first scan.\n",
         "| Source | Identifier hits then | Now | Reading |", "|---|---|---|---|"]
    still = []
    for name in before:
        now = after.get(name)
        if errors.get(name) or now is None:
            reading = "couldn't rescan (errors)"
        elif before[name] and now:
            reading = "**still holds the customer**"
            still.append(name)
        elif before[name]:
            reading = "gone: expired, deleted or rotated"
        else:
            reading = "never held it"
        L.append(f"| {name} | {before[name]} | {'-' if now is None else now} | {reading} |")
    L.append("")
    return "\n".join(L), still

