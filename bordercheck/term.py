"""Optional ANSI color for a terminal. Off when stdout is not a TTY or NO_COLOR is set."""
import os
import sys


def paint(text, code, stream=None):
    stream = stream or sys.stdout
    if "NO_COLOR" in os.environ or not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\033[{code}m{text}\033[0m"
