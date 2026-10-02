"""Command line: new -> send baseline -> fault start -> send fault -> fault stop -> scan -> report."""
import argparse
import json
import time

from . import canary, config, fault, report, runs, scan, send


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
    results = scan.scan_sources(cfg, canary.needles(run["record"], run["run_id"]))
    runs.write(cfg, args.run, "scan.json", json.dumps(results, indent=2))
    runs.event(run, "scan finished")
    runs.save(cfg, run)


def cmd_report(args):
    cfg = _cfg(args)
    run = runs.load(cfg, args.run)
    with open(f"{runs.run_dir(cfg, args.run)}/scan.json") as f:
        results = json.load(f)
    text, summary = report.build(cfg, run, results, redact=args.redact)
    runs.write(cfg, args.run, "report.md", text)
    runs.write(cfg, args.run, "summary.json", json.dumps(summary, indent=2))
    print(f"report: {runs.run_dir(cfg, args.run)}/report.md")


def cmd_all(args):
    run = cmd_new(args)
    args.run = run["run_id"]
    args.n = None
    if args.dry_run:
        cfg = _cfg(args)
        print(f"\n== dry run ==\nwould send {cfg['requests_per_phase']} baseline and "
              f"{cfg['requests_per_phase']} fault request(s) to {cfg['target']['url']}")
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
    print("\n== fault ==")
    cfg = _cfg(args)
    if not (cfg.get("fault") or {}).get("start"):
        print("no [fault] start command configured; skipping the fault phase")
    else:
        args.action = "start"
        if cmd_fault(args):
            try:
                args.phase = "fault"
                cmd_send(args)
            finally:
                # Always try to restore, even if the fault phase failed or was interrupted.
                args.action = "stop"
                if not cmd_fault(args):
                    print(f"\n!! the stop command did not complete. Restore the local model by hand, or run "
                          f"`python -m canarykit fault stop --run {args.run}`.")
        else:
            print("fault not started; skipping the fault phase")
    print("\n== scan ==")
    cmd_scan(args)
    cmd_report(args)


def main(argv=None):
    p = argparse.ArgumentParser(prog="canarykit", description=__doc__)
    p.add_argument("-c", "--config", default="canarykit.toml", help="path to your config (default canarykit.toml)")
    p.add_argument("--i-understand-this-is-production", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("new", help="create a run with a fresh synthetic customer").set_defaults(fn=cmd_new)

    s = sub.add_parser("send", help="send requests carrying the canary")
    s.add_argument("--run", required=True)
    s.add_argument("--phase", default="baseline", help="label, usually 'baseline' or 'fault'")
    s.add_argument("-n", type=int, help="number of requests (default from config)")
    s.set_defaults(fn=cmd_send)

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

    a = sub.add_parser("all", help="new, baseline, fault, scan and report in one go")
    a.add_argument("--dry-run", action="store_true", help="show fault commands without running them")
    a.add_argument("--yes", action="store_true", help="don't ask before running fault commands")
    a.add_argument("--redact", action="store_true", help="write a shareable report (see `report --redact`)")
    a.set_defaults(fn=cmd_all)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except config.ConfigError as e:
        print(f"config error: {e}")
        return 2
    except runs.RunIdError as e:
        print(f"error: {e}")
        return 2
    except KeyboardInterrupt:
        run = f" --run {args.run}" if getattr(args, "run", None) else " --run <id>"
        print(f"\ninterrupted. If a fault was started, restore the local model with "
              f"`python -m canarykit fault stop{run}`.")
        return 130
    return 0
