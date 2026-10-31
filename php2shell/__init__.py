"""php2shell — adaptive lab verification driver.

Phase-1 package backing php2shell_adaptive.py. All execution is scoped to
this repo's own labs: local hosts only, benign allowlisted commands only
(id | uname | whoami), no arbitrary-command / reverse-shell / leak stages.
See docs/PLAN.md.
"""

__version__ = "0.1.0"