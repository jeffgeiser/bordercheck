"""Run your own commands to take the local model away and bring it back.

canarykit doesn't know your stack, so it never decides how to break it. You write the
start/stop commands; canarykit shows them, asks first, and logs when they ran.
"""
import subprocess


def run_command(label, command, dry_run=False, assume_yes=False, timeout=300):
    if not command:
        raise SystemExit(f"no [fault] {label} command configured")
    print(f"\n[fault {label}] {command}")
    if dry_run:
        print("  dry run: not executed")
        return True
    if not assume_yes:
        try:
            answer = input("  run this command now? type 'yes' to continue: ").strip().lower()
        except EOFError:  # no terminal, e.g. in CI: never treat that as consent
            answer = ""
        if answer != "yes":
            print("  skipped")
            return False
    try:
        done = subprocess.run(command, shell=True, timeout=timeout, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        print(f"  command did not finish within {timeout}s")
        return False
    if done.stdout.strip():
        print("  " + done.stdout.strip().replace("\n", "\n  "))
    if done.returncode != 0:
        print(f"  command exited {done.returncode}: {done.stderr.strip()}")
        return False
    return True
