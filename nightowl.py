# nightowl.py -- backward-compatibility shim.
#
# The real engine lives in nightowl_pkg/engine.py (single source of truth).
# This shim keeps legacy entry points working:
#   python3 nightowl.py <cmd> ...     (old docs / muscle memory)
#   import nightowl                   (legacy test suite)
import sys

if __package__ in (None, ""):  # executed as a script
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from nightowl_pkg.engine import *  # noqa: F401,F403
from nightowl_pkg.engine import (  # noqa: F401  underscore names used by tests
    _resolve_apk,
    _is_flutter_app,
    _is_likely_false_positive,
    _iss,
    _find_tool,
)

__version__ = "8.0"

if __name__ == "__main__":
    main()  # noqa: F405
