"""Command line: new -> send baseline -> probes -> fault start -> send fault -> fault stop -> scan -> report.

`report` and `all` exit 0 for pass, 1 for fail (data crossed the border), 3 for inconclusive
(no working positive control, or a source had errors), 2 for config errors. `diff` and
`rescan --expect-gone` exit 1 on a regression; `verify` exits 1 if a bundle doesn't match.
"""
import argparse
import json
import os
import time

from . import canary, config, evidence, fault, onepager, report, runs, scan, send
from .term import paint


def _cfg(args):
    return config.load(args.config, allow_production=args.i_understand_this_is_production)


def cmd_new(args):
    cfg = _cfg(args)
    run = runs.new_run(cfg, canary.new_record())
    runs.event(run, "run created")
    runs.save(cfg, run)
    rec = run["record"]
    print(f"run id:   {run['run_id']}")
    print(f"customer: {rec['name']}, {rec['role']}, {rec['city']} (synthetic)")
    print(f"canary:   {rec['canary']}   account: {rec['account']}")
    print(f"seed file for your test data: {runs.run_dir(cfg, run['run_id'])}/seed_record.json")
    return run


def cmd_send(args):
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    runs.event(run, f"{args.phase} phase started")
    print(f"sending {args.n or cfg['requests_per_phase']} {args.phase} request(s) to {cfg['target']['url']}")
    send.send_phase(cfg, run, args.phase, args.n)
    runs.event(run, f"{args.phase} phase finished")
    runs.save(cfg, run)


def cmd_probe(args):
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    names = args.only or list(cfg["probes"])
    for name in names:
        if name not in cfg["probes"]:
            raise config.ConfigError(f"no [probes.{name}] section in the config")
        prompt, n, concurrency = send.probe_settings(cfg, name)
        phase = f"probe:{name}"
        print(f"\n[{phase}] {n} request(s), concurrency {concurrency}")
        runs.event(run, f"{phase} started")
        send.send_phase(cfg, run, phase, n, prompt=prompt, concurrency=concurrency)
        runs.event(run, f"{phase} finished")
        runs.save(cfg, run)


def _restore_hint(run_id):
    return f"`python -m bordercheck fault stop --run {run_id}`"


def _fault_step(cfg, run, action, command):
    """Run a confirmed fault command, log it, and wait for it to take effect. True if it exited 0."""
    ok = fault.execute(command)
    runs.event(run, f"fault {action}" + ("" if ok else " (command failed)"), detail=command)
    runs.save(cfg, run)
    settle = float((cfg.get("fault") or {}).get("settle_seconds", 15))
    if settle:
        print(f"  waiting {settle:.0f}s for the change to take effect")
        time.sleep(settle)
    return ok


def _fault_phase(args, cfg):
    """Start, send, stop. Once the start command is confirmed, stop always runs, without asking
    again, whatever happens in between: a failed start, a failed send, or Ctrl-C."""
    start, stop = cfg["fault"]["start"], cfg["fault"].get("stop")
    if not fault.confirm("start", start, args.yes):
        print("fault not started; skipping the fault phase")
        return
    if not stop:
        print("!! no [fault] stop command configured: restore the local model by hand after the run")
    run = runs.load(cfg, args.run)
    try:
        if _fault_step(cfg, run, "start", start):
            args.phase = "fault"
            cmd_send(args)
        else:
            print("!! the start command failed; it may have partly run, so the stop command runs anyway")
    finally:
        if stop:
            print(f"\n[fault stop] {stop}")
            try:
                restored = _fault_step(cfg, runs.load(cfg, args.run), "stop", stop)
            except KeyboardInterrupt:
                print(f"\n!! interrupted while restoring. Restore the local model by hand, or run {_restore_hint(args.run)}.")
                raise
            if not restored:
                print(f"\n!! the stop command did not complete. Restore the local model by hand, or run "
                      f"{_restore_hint(args.run)}.")


def cmd_fault(args):
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    command = (cfg.get("fault") or {}).get(args.action)
    if fault.run_command(args.action, command, dry_run=args.dry_run, assume_yes=args.yes):
        if not args.dry_run:
            runs.event(run, f"fault {args.action}", detail=command)
            runs.save(cfg, run)
        settle = float((cfg.get("fault") or {}).get("settle_seconds", 15))
        if not args.dry_run and settle:
            print(f"  waiting {settle:.0f}s for the change to take effect")
            time.sleep(settle)
        return True
    return False


def cmd_scan(args):
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    wait = float(cfg.get("scan_delay_seconds", 0))
    if wait:
        print(f"waiting {wait:.0f}s for logs and traces to flush")
        time.sleep(wait)
    skew = float(cfg.get("clock_skew_seconds", 120))
    results = scan.scan_sources(cfg, canary.needles(run["record"], run["run_id"]), scan.window(run, skew=skew))
    runs.write(cfg, args.run, "scan.json", json.dumps(results, indent=2))
    run["scanned_at"] = time.time()
    runs.event(run, "scan finished")
    runs.save(cfg, run)


def cmd_rescan(args):
    """Scan again later, over the original run window, to see which copies have expired."""
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    if "scanned_at" not in run:
        raise config.ConfigError(f"run {args.run} hasn't been scanned yet; run `scan` first")
    path = runs.run_dir(cfg, args.run)
    with open(os.path.join(path, "scan.json")) as f:
        first = json.load(f)
    skew = float(cfg.get("clock_skew_seconds", 120))
    later = scan.scan_sources(cfg, canary.needles(run["record"], run["run_id"]),
                              scan.window(run, end=run["scanned_at"], skew=skew))
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    runs.write(cfg, args.run, f"rescan-{stamp}.json", json.dumps(later, indent=2))
    text, still = evidence.retention(first, later, canary.IDENTIFIER_KINDS, run["scanned_at"], run["run_id"])
    runs.write(cfg, args.run, f"retention-{stamp}.md", text)
    print(text)
    return 1 if args.expect_gone and still else 0


def cmd_report(args):
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    with open(f"{runs.run_dir(cfg, args.run)}/scan.json") as f:
        results = json.load(f)
    text, summary = report.build(cfg, run, results, redact=args.redact)
    path = runs.run_dir(cfg, args.run)
    runs.write(cfg, args.run, "report.md", text)
    runs.write(cfg, args.run, "summary.json", json.dumps(summary, indent=2))
    appendix = bool((cfg.get("report") or {}).get("regulatory_appendix"))
    runs.write(cfg, args.run, "summary.html", onepager.html(summary, frameworks=appendix))
    runs.write(cfg, args.run, evidence.MANIFEST, json.dumps(
        evidence.manifest(path, args.config, args.run, summary["verdict"]), indent=2))
    print(f"report: {path}/report.md  (one-pager: summary.html)")
    color = {"pass": "1;32", "fail": "1;31", "inconclusive": "1;33"}[summary["verdict"]]
    print(f"verdict: {paint(summary['verdict'].upper(), color)}" + "".join(f"\n  - {r}" for r in summary["reasons"]))
    return report.EXIT_CODES[summary["verdict"]]


def cmd_evidence(args):
    cfg = _cfg(args)
    path = runs.run_dir(cfg, args.run)
    if not os.path.exists(os.path.join(path, "summary.json")):
        raise config.ConfigError(f"run {args.run} has no report yet; run `report` first")
    with open(os.path.join(path, "summary.json")) as f:
        verdict = json.load(f)["verdict"]
    # Refresh the manifest so it covers files written since the report (diffs, rescans).
    runs.write(cfg, args.run, evidence.MANIFEST,
               json.dumps(evidence.manifest(path, args.config, args.run, verdict), indent=2))
    out = os.path.join(cfg["output_dir"], f"{args.run}-evidence.zip")
    digest = evidence.bundle(path, out, include_config=args.config if args.include_config else None)
    print(f"evidence bundle: {out}\nsha256: {digest}\n"
          "Record this hash in your change or audit ticket, or sign the file, so it can't be swapped later.")


def cmd_verify(args):
    problems = evidence.verify(args.bundle)
    for p in problems:
        print(f"  {p}")
    print("bundle matches its manifest" if not problems else "bundle does NOT match its manifest")
    return 1 if problems else 0


def cmd_diff(args):
    cfg = _cfg(args)
    docs = []
    for run_id in (args.against, args.run):
        with open(os.path.join(runs.run_dir(cfg, run_id), "summary.json")) as f:
            docs.append(json.load(f))
    text, regressed = evidence.diff(*docs)
    runs.write(cfg, args.run, f"diff-vs-{args.against}.md", text)
    print(text)
    return 1 if regressed else 0


def cmd_all(args):
    run = cmd_new(args)
    args.run = run["run_id"]
    args.n = None
    if args.dry_run:
        cfg = _cfg(args)
        print(f"\n== dry run ==\nwould send {cfg['requests_per_phase']} baseline and "
              f"{cfg['requests_per_phase']} fault request(s) to {cfg['target']['url']}")
        for name in cfg["probes"]:
            _prompt, n, concurrency = send.probe_settings(cfg, name)
            print(f"would run probe {name}: {n} request(s), concurrency {concurrency}")
        for action in ("start", "stop"):
            command = (cfg.get("fault") or {}).get(action)
            if command:
                fault.run_command(action, command, dry_run=True)
            else:
                print(f"\n[fault {action}] not configured")
        print("\n== read-only scan, to confirm every source is reachable ==")
        cmd_scan(args)
        print("\ndry run finished: no requests sent, no fault commands run.")
        return
    print("\n== baseline ==")
    args.phase = "baseline"
    cmd_send(args)
    cfg = _cfg(args)
    if cfg["probes"]:
        # With the local model healthy: failovers that happen with nothing down.
        print("\n== probes ==")
        args.only = None
        cmd_probe(args)
    print("\n== fault ==")
    if not (cfg.get("fault") or {}).get("start"):
        print("no [fault] start command configured; skipping the fault phase")
    else:
        _fault_phase(args, cfg)
    print("\n== scan ==")
    cmd_scan(args)
    return cmd_report(args)


def main(argv=None):
    p = argparse.ArgumentParser(prog="bordercheck", description=__doc__)
    p.add_argument("-c", "--config", default="bordercheck.toml", help="path to your config (default bordercheck.toml)")
    p.add_argument("--i-understand-this-is-production", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("new", help="create a run with a fresh synthetic customer").set_defaults(fn=cmd_new)

    s = sub.add_parser("send", help="send requests carrying the canary")
    s.add_argument("--run", required=True)
    s.add_argument("--phase", default="baseline", help="label, usually 'baseline' or 'fault'")
    s.add_argument("-n", type=int, help="number of requests (default from config)")
    s.set_defaults(fn=cmd_send)

    pr = sub.add_parser("probe", help="run the [probes] that trigger failover with nothing down")
    pr.add_argument("--run", required=True)
    pr.add_argument("--only", action="append", choices=config.PROBES, help="run just this probe (repeatable)")
    pr.set_defaults(fn=cmd_probe)

    f = sub.add_parser("fault", help="run your configured start/stop command")
    f.add_argument("action", choices=["start", "stop"])
    f.add_argument("--run", required=True)
    f.add_argument("--dry-run", action="store_true", help="show the command without running it")
    f.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    f.set_defaults(fn=cmd_fault)

    sc = sub.add_parser("scan", help="search your sources (read-only)")
    sc.add_argument("--run", required=True)
    sc.set_defaults(fn=cmd_scan)

    r = sub.add_parser("report", help="write report.md and summary.json")
    r.add_argument("--run", required=True)
    r.add_argument("--redact", action="store_true",
                   help="leave out file paths, URLs and fault commands, for sharing outside the team")
    r.set_defaults(fn=cmd_report)

    rs = sub.add_parser("rescan", help="scan again later, to see which copies have expired")
    rs.add_argument("--run", required=True)
    rs.add_argument("--expect-gone", action="store_true", help="exit 1 if any store still holds the customer")
    rs.set_defaults(fn=cmd_rescan)

    d = sub.add_parser("diff", help="compare a run with an earlier one; exit 1 on a regression")
    d.add_argument("--run", required=True, help="the newer run")
    d.add_argument("--against", required=True, help="the earlier run")
    d.set_defaults(fn=cmd_diff)

    ev = sub.add_parser("evidence", help="bundle a run and its manifest into a zip for an auditor")
    ev.add_argument("--run", required=True)
    ev.add_argument("--include-config", action="store_true", help="add the config file (it holds no secrets)")
    ev.set_defaults(fn=cmd_evidence)

    v = sub.add_parser("verify", help="check an evidence bundle against its manifest")
    v.add_argument("bundle")
    v.set_defaults(fn=cmd_verify)

    a = sub.add_parser("all", help="new, baseline, probes, fault, scan and report in one go")
    a.add_argument("--dry-run", action="store_true", help="show fault commands without running them")
    a.add_argument("--yes", action="store_true", help="don't ask before running fault commands")
    a.add_argument("--redact", action="store_true", help="write a shareable report (see `report --redact`)")
    a.set_defaults(fn=cmd_all)

    args = p.parse_args(argv)
    try:
        rc = args.fn(args)
    except config.ConfigError as e:
        print(f"config error: {e}")
        return 2
    except runs.RunIdError as e:
        print(f"error: {e}")
        return 2
    except KeyboardInterrupt:
        run = f" --run {args.run}" if getattr(args, "run", None) else " --run <id>"
        print(f"\ninterrupted. If a fault was started, restore the local model with "
              f"`python -m bordercheck fault stop{run}`.")
        return 130
    return rc if isinstance(rc, int) and not isinstance(rc, bool) else 0
