# nwproc.py -- centralized subprocess execution with enforced timeouts.
#
# Every external-tool invocation in NightOwl must go through run() so a hung
# jadx/apktool/adb on malformed input can never freeze a scan (or an agent
# host attached over MCP). Default timeout is 120s; override globally with
# the NIGHTOWL_TIMEOUT environment variable (seconds).

import os
import subprocess

DEFAULT_TIMEOUT = float(os.environ.get("NIGHTOWL_TIMEOUT", "120"))


class ToolTimeout(subprocess.TimeoutExpired):
    """Raised when an external tool exceeds its budget.

    Keeps the command around for actionable error messages.
    """

    def __init__(self, cmd, timeout):
        super().__init__(cmd=cmd, timeout=timeout)
        self.cmd_str = " ".join(str(c) for c in cmd)

    def __str__(self):
        return (f"external tool exceeded {self.timeout:.0f}s budget: "
                f"{self.cmd_str[:160]}")


def run(cmd, timeout=None, check=False, **kwargs):
    """subprocess.run with a mandatory timeout and rich failure semantics.

    Returns CompletedProcess. Raises ToolTimeout on hang; CalledProcessError
    only when check=True (same contract as subprocess.run otherwise).
    """
    t = float(timeout) if timeout else DEFAULT_TIMEOUT
    try:
        return subprocess.run(cmd, timeout=t, check=check, **kwargs)
    except subprocess.TimeoutExpired as e:
        raise ToolTimeout(cmd, t) from None
