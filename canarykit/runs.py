"""Each run is a folder with run.json (canary + request metadata), scan.json and report.md."""
import json
import os
import secrets
import time


def new_run(cfg, record):
    run_id = time.strftime("run-%Y%m%d-%H%M%S-") + secrets.token_hex(2)
    path = os.path.join(cfg["output_dir"], run_id)
    os.makedirs(path, exist_ok=False)
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
    with open(os.path.join(path, "seed_record.json"), "w") as f:
        json.dump(record, f, indent=2)
    return run


def run_dir(cfg, run_id):
    return os.path.join(cfg["output_dir"], run_id)


def load(cfg, run_id):
    with open(os.path.join(run_dir(cfg, run_id), "run.json")) as f:
        return json.load(f)


def save(cfg, run):
    path = os.path.join(run_dir(cfg, run["run_id"]), "run.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(run, f, indent=2)
    os.replace(tmp, path)


def event(run, name, **extra):
    run["events"].append({"t": time.time(), "event": name, **extra})


def write(cfg, run_id, filename, text):
    with open(os.path.join(run_dir(cfg, run_id), filename), "w") as f:
        f.write(text)
