#!/usr/bin/env python3
"""Adaptive lab verification driver (thin entry point).

Fingerprints a lab target, selects the applicable RCE chain, executes it with
a benign allowlisted command (id | uname | whoami), and returns the output.

    python3 php2shell_adaptive.py localhost -p 18080 -c id
    python3 php2shell_adaptive.py localhost -p 18080 --fingerprint-only

Lab targets only. See docs/PLAN.md and php2shell/.
"""

import sys

from php2shell.driver import main

if __name__ == "__main__":
    sys.exit(main())