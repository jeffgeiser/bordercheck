"""Run your own commands to take the local model away and bring it back.

bordercheck doesn't know your stack, so it never decides how to break it. You write the
start/stop commands; bordercheck shows them, asks first, and logs when they ran.

Asking and running are separate so `all` can ask once for the whole fault phase: once you've
agreed to the start command, the stop command runs without a second question, even after a
failure or Ctrl-C, because a start command that partly worked can still leave the model down.
"""
import subprocess


def confirm(label, command, assume_yes=False):
    """Show the command and ask. True only for an explicit 'yes' (or assume_yes)."""
    if not command:
        raise SystemExit(f"no [fault] {label} command configured")
    print(f"\n[fault {label}] {command}")
    if assume_yes:
        return True
    try:
        answer = input("  run this command now? type 'yes' to continue: ").strip().lower()
    except EOFError:  # no terminal, e.g. in CI: never treat that as consent
        answer = ""
    if answer != "yes":
        print("  skipped")
        return False
    return True


def execute(command, timeout=300):
    """Run an already-confirmed command. True if it exited 0."""
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


def run_command(label, command, dry_run=False, assume_yes=False, timeout=300):
    if dry_run:
        if not command:
            raise SystemExit(f"no [fault] {label} command configured")
        print(f"\n[fault {label}] {command}\n  dry run: not executed")
        return True
    return confirm(label, command, assume_yes) and execute(command, timeout)
