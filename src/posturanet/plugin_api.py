"""The stable surface plugins (PosturaNet Pro and others) build on.

Plugins import CLI helpers from here, never from `posturanet.cli.app` directly, so the CLI can be
refactored without breaking a plugin. Removing or renaming anything in `__all__` is a breaking
change: `tests/unit/test_plugin_api.py` pins the list.
"""

from __future__ import annotations

from posturanet.cli import app as _app
from posturanet.cli.app import AsciiOpt, FormatOpt, OutputFormat, RepoOpt, StateOpt, WindowOpt

GATE_EXIT = _app._GATE_EXIT
examples = _app._examples
fail = _app._fail
frame = _app._frame
publish_check = _app._publish_check
window = _app._window
API_VERSION = 1

__all__ = [
    "API_VERSION",
    "GATE_EXIT",
    "AsciiOpt",
    "FormatOpt",
    "OutputFormat",
    "RepoOpt",
    "StateOpt",
    "WindowOpt",
    "examples",
    "fail",
    "frame",
    "publish_check",
    "window",
]
