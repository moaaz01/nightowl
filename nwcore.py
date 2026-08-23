# nwcore.py -- deprecated alias kept for backward compatibility.
# The real engine lives in nightowl_pkg/engine.py.
from nightowl_pkg.engine import *  # noqa: F401,F403
from nightowl_pkg.engine import (  # noqa: F401
    _resolve_apk, _is_flutter_app, _is_likely_false_positive, _iss, _find_tool,
)

__version__ = "8.0"

if __name__ == "__main__":  # pragma: no cover
    main()  # noqa: F405
