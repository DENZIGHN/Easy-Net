"""Explicit imports for PyInstaller static analysis.

PyInstaller traces imports statically. Since easynet/__main__.py imports
cli.main inside a function (not at module level), PyInstaller can't see
the full dependency tree. This file imports everything explicitly so
PyInstaller's Analysis picks them up.

This file is NOT used at runtime — it's only referenced in the spec file
as an additional script for Analysis.
"""

# Core dependencies — import at top level so PyInstaller can trace them
import asyncio  # noqa: F401
import ssl  # noqa: F401
import struct  # noqa: F401
import socket  # noqa: F401

import click  # noqa: F401
import click.core  # noqa: F401
import click.decorators  # noqa: F401
import click.types  # noqa: F401
import click.shell_completion  # noqa: F401

import rich  # noqa: F401
import rich.console  # noqa: F401
import rich.table  # noqa: F401
import rich.text  # noqa: F401
import rich.traceback  # noqa: F401

import yaml  # noqa: F401

import aiohttp  # noqa: F401
import aiohttp.web  # noqa: F401
import aiohttp.client  # noqa: F401

import dns  # noqa: F401
import dns.message  # noqa: F401
import dns.query  # noqa: F401
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
import easynet.utils.logging  # noqa: F401
import easynet.utils.platform  # noqa: F401
