"""Entry point for PyInstaller frozen executable."""

# === TOP-LEVEL IMPORTS FOR PYINSTALLER ===
# PyInstaller traces imports via static analysis starting from this file.
# Everything imported here at module level WILL be included in the bundle.
# Lazy imports inside functions are invisible to PyInstaller.

import multiprocessing
import os
import sys
import traceback

# All runtime dependencies — must be top-level for PyInstaller to find them
import asyncio  # noqa: F401
import socket  # noqa: F401
import ssl  # noqa: F401
import struct  # noqa: F401

import click  # noqa: F401
import click.core  # noqa: F401
import click.decorators  # noqa: F401
import click.types  # noqa: F401

import yaml  # noqa: F401

import rich  # noqa: F401
import rich.console  # noqa: F401
import rich.table  # noqa: F401

import aiohttp  # noqa: F401
import aiohttp.web  # noqa: F401
import aiohttp.client  # noqa: F401

import dns  # noqa: F401
import dns.message  # noqa: F401
import dns.rdatatype  # noqa: F401

import multidict  # noqa: F401
import yarl  # noqa: F401

# EasyNet modules
import easynet.cli.main  # noqa: F401
import easynet.core.engine  # noqa: F401
import easynet.core.fragmentation  # noqa: F401
import easynet.core.host_manipulation  # noqa: F401
import easynet.core.ttl_desync  # noqa: F401
import easynet.core.tcp_desync  # noqa: F401
import easynet.dns.resolver  # noqa: F401
import easynet.proxy.socks5  # noqa: F401
import easynet.proxy.transparent  # noqa: F401
import easynet.routing.router  # noqa: F401
import easynet.web.app  # noqa: F401
import easynet.utils.config  # noqa: F401
import easynet.utils.platform  # noqa: F401

# === END TOP-LEVEL IMPORTS ===


def _is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def _pause_on_error() -> None:
    """On Windows, keep the console window open so the user can read the error."""
    if _is_frozen() and sys.platform == "win32":
        print("\nPress Enter to exit...")
        try:
            input()
        except EOFError:
            pass


def main() -> None:
    try:
        multiprocessing.freeze_support()

        from easynet.cli.main import cli

        # When double-clicked on Windows with no arguments, show help and pause
        if _is_frozen() and len(sys.argv) == 1:
            sys.argv.append("--help")
            try:
                cli(standalone_mode=False)
            except SystemExit:
                pass
            _pause_on_error()  # Keep window open so user can read help
            return

        cli()

    except Exception:
        traceback.print_exc()
        _pause_on_error()
        sys.exit(1)


if __name__ == "__main__":
    main()
