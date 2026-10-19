"""Process hardening against prompt residue in memory.

CPython cannot zero every copy of a string, so instead of promising erasure we make the
residue unreadable and short-lived ("The Illusion of Local Privacy", 2026: canaries
recovered via /proc/<pid>/mem, core dumps and swap):

  - non-dumpable process (Linux prctl): blocks /proc/<pid>/mem reads and ptrace by other
    processes of the same user, and suppresses core dumps
  - core dump size 0
  - optional mlockall (VEIL_MLOCK=1): nothing pages out to swap; needs CAP_IPC_LOCK or a
    large enough memlock limit
  - worker recycling (gunicorn max_requests, see gunicorn_conf.py) bounds how long any
    residue can live
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import resource
import sys

log = logging.getLogger("veil")

_PR_SET_DUMPABLE = 4
_MCL_CURRENT, _MCL_FUTURE = 1, 2


def harden() -> dict:
    applied = {}
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        applied["core_dumps"] = "disabled"
    except (ValueError, OSError) as e:
        applied["core_dumps"] = f"failed: {e}"

    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        applied["dumpable"] = "off" if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 else f"failed: errno {ctypes.get_errno()}"
        if os.environ.get("VEIL_MLOCK", "0") == "1":
            ok = libc.mlockall(_MCL_CURRENT | _MCL_FUTURE) == 0
            applied["mlock"] = "on" if ok else f"failed: errno {ctypes.get_errno()} (needs CAP_IPC_LOCK / memlock limit)"
    else:
        applied["dumpable"] = "n/a (not Linux)"
    log.info("process hardening: %s", applied)
    return applied
