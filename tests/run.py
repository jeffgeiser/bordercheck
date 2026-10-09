"""Run the test suite and fail on leaked resources.

`python -W error::ResourceWarning -m unittest` doesn't catch a file or socket left open: the
warning is raised during garbage collection, where Python only prints it ("unraisable") and the
run still passes. This runner records those warnings and fails if there were any.

    python tests/run.py          # what CI runs
"""
import gc
import os
import sys
import unittest
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
leaks = []


def record(unraisable):
    if isinstance(unraisable.exc_value, ResourceWarning):
        leaks.append(str(unraisable.exc_value))
    else:
        sys.__unraisablehook__(unraisable)


def main():
    warnings.simplefilter("error", ResourceWarning)
    sys.unraisablehook = record
    sys.path[:0] = [os.path.dirname(HERE), HERE]   # the package, and the test helpers
    suite = unittest.defaultTestLoader.discover(HERE, top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    gc.collect()
    for leak in leaks:
        print(f"leaked resource: {leak}", file=sys.stderr)
    return 0 if result.wasSuccessful() and not leaks else 1


if __name__ == "__main__":
    sys.exit(main())
