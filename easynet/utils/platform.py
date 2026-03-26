"""Platform detection and OS-specific utilities."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from enum import Enum


class Platform(Enum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


def detect_platform() -> Platform:
    """Detect the current operating system."""
    system = platform.system().lower()
    if system == "linux":
        return Platform.LINUX
    elif system == "darwin":
        return Platform.MACOS
    elif system == "windows":
        return Platform.WINDOWS
    return Platform.UNKNOWN


def is_root() -> bool:
    """Check if running with root/admin privileges."""
    if detect_platform() == Platform.WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def check_dependencies() -> dict[str, bool]:
    """Check availability of required system tools."""
    deps = {
        "iptables": False,
        "ip6tables": False,
        "nftables": False,
        "python3": True,  # We're running, so yes
    }

    for tool in ["iptables", "ip6tables", "nft"]:
        try:
            subprocess.run(
                [tool, "--version"],
                capture_output=True,
                timeout=5,
            )
            key = "nftables" if tool == "nft" else tool
            deps[key] = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return deps


def get_default_interface() -> str | None:
    """Get the default network interface name."""
    plat = detect_platform()
    if plat == Platform.LINUX:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Output like: default via 10.0.0.1 dev eth0 proto ...
            parts = result.stdout.strip().split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    elif plat == Platform.MACOS:
        try:
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if "interface:" in line:
                    return line.split(":")[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return None
