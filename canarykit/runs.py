"""Each run is a folder with run.json (canary + request metadata), scan.json and report.md."""
import json
import os
import re
import secrets
import time

RUN_ID_RE = re.compile(r"^run-\d{8}-\d{6}-[0-9a-f]{4}$")


class RunIdError(ValueError):
    pass


def _open_private(path):
    """Run files hold internal hostnames and paths: readable by the owner only."""
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w")


def new_run(cfg, record):
    run_id = time.strftime("run-%Y%m%d-%H%M%S-") + secrets.token_hex(2)
    path = os.path.join(cfg["output_dir"], run_id)
    os.makedirs(cfg["output_dir"], mode=0o700, exist_ok=True)
    os.makedirs(path, mode=0o700, exist_ok=False)
    run = {
        "run_id": run_id,
        "environment": cfg["environment"],
        "border": cfg["border"],
        "created": time.time(),
        "record": record,
        "requests": [],
        "events": [],
    }
    save(cfg, run)
    with _open_private(os.path.join(path, "seed_record.json")) as f:
        json.dump(record, f, indent=2)
    return run


def run_dir(cfg, run_id):
    if not RUN_ID_RE.match(run_id):
        raise RunIdError(f"not a canarykit run id: {run_id!r}")
    return os.path.join(cfg["output_dir"], run_id)


def load(cfg, run_id):
    with open(os.path.join(run_dir(cfg, run_id), "run.json")) as f:
        return json.load(f)


def save(cfg, run):
    path = os.path.join(run_dir(cfg, run["run_id"]), "run.json")
    tmp = path + ".tmp"
    with _open_private(tmp) as f:
        json.dump(run, f, indent=2)
    os.replace(tmp, path)


def event(run, name, **extra):
    run["events"].append({"t": time.time(), "event": name, **extra})


def write(cfg, run_id, filename, text):
    with _open_private(os.path.join(run_dir(cfg, run_id), filename)) as f:
        f.write(text)
