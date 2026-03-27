"""PyInstaller runtime hook — fix import paths for frozen mode.

This runs before the main script. It ensures that scapy and other
dynamically-loaded packages can find their submodules.
"""

import os
import sys

# When frozen, ensure the temp extraction directory is in the path
if getattr(sys, "frozen", False):
    base = sys._MEIPASS  # type: ignore[attr-defined]
    if base not in sys.path:
        sys.path.insert(0, base)

    # Suppress scapy warnings in frozen mode
    os.environ.setdefault("SCAPY_USE_LIBPCAP", "0")
    # Disable scapy's interactive prompts
    os.environ.setdefault("SCAPY_NONINTERACTIVE", "1")
