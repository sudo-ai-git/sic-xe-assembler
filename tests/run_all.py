#!/usr/bin/env python3
"""Run the SVL -> SIC/XE test suite.

Standalone programs are compiled and executed; each has an expected
marker (register value or printed text). test_utils.svl / test_main2.svl
are link inputs (they reference each other) and are exercised by
test_multifile.py instead.
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# test file -> substring that must appear in the output
EXPECT = {
    "test_add.svl":    "A = 000003",
    "test_bitwise.svl": "A = 000000",
    "test_bitwise2.svl": "A = FFFFFE",
    "test_call.svl":   "PRINT: 'Done",
    "test_cat.svl":    "A = 000007",
    "test_expr.svl":   "PRINT: '",
    "test_for.svl":    "A = 000006",
    "test_if.svl":     "A = 000001",
    "test_loop.svl":   "PRINT: 'Done",
    "test_min.svl":    "A = 000000",
    "test_min2.svl":   "A = 000003",
    "test_full.svl":   "PRINT: 'Done",
    "test_shift.svl":  "PRINT_INT: A = 4",
}

# Files that are linker inputs, not standalone programs
LINK_INPUTS = {"test_utils.svl", "test_main2.svl"}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT), **kw)


def main():
    failures = []
    for name, marker in EXPECT.items():
        r = run([sys.executable, "svl_to_sic.py", str(HERE / name)])
        out = r.stdout + r.stderr
        if r.returncode != 0:
            failures.append((name, f"exit {r.returncode}: {out.strip().splitlines()[-1] if out.strip() else ''}"))
        elif marker not in out:
            failures.append((name, f"marker {marker!r} not found"))
        else:
            print(f"  PASS {name}")

    for name in sorted(LINK_INPUTS):
        print(f"  skip {name} (link input)")

    r = run([sys.executable, str(HERE / "test_multifile.py")])
    if r.returncode != 0:
        failures.append(("test_multifile.py", r.stdout + r.stderr))
    else:
        print("  PASS test_multifile.py")

    print()
    if failures:
        print(f"RESULT: FAIL ({len(failures)} failures)")
        for name, why in failures:
            print(f"  {name}: {why}")
        return 1
    print(f"RESULT: PASS ({len(EXPECT)} standalone + multifile)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
