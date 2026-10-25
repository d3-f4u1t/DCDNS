"""Runtime configuration shared by the long-running services.

On Windows the default asyncio event loop is the IOCP proactor. A client that
resets a connection at the wrong moment can make ``accept()`` raise
``WinError 64``, which kills the accept loop and leaves the process alive but no
longer listening. The selector loop does not have this failure mode and is
perfectly adequate for an HTTP server of this size.
"""

from __future__ import annotations

import asyncio
import sys


def configure_event_loop() -> None:
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
