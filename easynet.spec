# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for building a portable EasyNet executable.

Usage:
    pyinstaller easynet.spec

Or use the build script:
    python scripts/build_exe.py
"""

import os
import sys
from pathlib import Path

block_cipher = None

# Paths
PROJECT_ROOT = os.path.abspath(".")
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")

a = Analysis(
    [
        os.path.join("easynet", "__main__.py"),
        # This file has explicit top-level imports of all dependencies,
        # so PyInstaller's static analysis can trace them even though
        # __main__.py uses lazy imports inside functions.
        os.path.join("easynet", "_frozen_imports.py"),
    ],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        # Bundle the default config file inside the executable
        (os.path.join("config", "default.yaml"), "config"),
    ],
    hiddenimports=[
        # NOTE: scapy is a declared dependency but not imported at runtime.
        # All packet crafting uses struct+socket directly.
        # --- aiohttp ---
        "aiohttp",
        "aiohttp.web",
        "aiohttp.web_app",
        "aiohttp.web_request",
        "aiohttp.web_response",
        "aiohttp.web_runner",
        "aiohttp.web_server",
        "aiohttp.client",
        "aiohttp.connector",
        "aiohttp.resolver",
        # --- multidict (aiohttp dependency, C extension) ---
        "multidict",
        "multidict._multidict",
        # --- yarl (aiohttp dependency) ---
        "yarl",
        "yarl._quoting",
        # --- frozenlist (aiohttp dependency) ---
        "frozenlist",
        "frozenlist._frozenlist",
        # --- aiosignal ---
        "aiosignal",
        # --- dnspython ---
        "dns",
        "dns.asyncresolver",
        "dns.message",
        "dns.query",
        "dns.rdatatype",
        "dns.rdtypes",
        "dns.rdtypes.ANY",
        "dns.rdtypes.ANY.SOA",
        "dns.rdtypes.ANY.TXT",
        "dns.rdtypes.ANY.MX",
        "dns.rdtypes.ANY.NS",
        "dns.rdtypes.ANY.CNAME",
        "dns.rdtypes.ANY.PTR",
        "dns.rdtypes.IN",
        "dns.rdtypes.IN.A",
        "dns.rdtypes.IN.AAAA",
        "dns.rdtypes.IN.SRV",
        # --- Click ---
        "click",
        "click.core",
        "click.decorators",
        "click.exceptions",
        "click.shell_completion",
        # --- Rich ---
        "rich",
        "rich.console",
        "rich.table",
        "rich.text",
        "rich.traceback",
        "rich.markup",
        # --- PyYAML ---
        "yaml",
        "_yaml",
        # --- stdlib that PyInstaller sometimes misses ---
        "asyncio",
        "asyncio.events",
        "asyncio.base_events",
        "asyncio.selector_events",
        "asyncio.proactor_events",
        "ssl",
        "struct",
        "socket",
        "ipaddress",
        "email.mime.text",
        # --- EasyNet submodules ---
        "easynet",
        "easynet.core",
        "easynet.core.base",
        "easynet.core.engine",
        "easynet.core.fragmentation",
        "easynet.core.host_manipulation",
        "easynet.core.ttl_desync",
        "easynet.core.tcp_desync",
        "easynet.dns",
        "easynet.dns.resolver",
        "easynet.proxy",
        "easynet.proxy.socks5",
        "easynet.proxy.transparent",
        "easynet.routing",
        "easynet.routing.router",
        "easynet.cli",
        "easynet.cli.main",
        "easynet.web",
        "easynet.web.app",
        "easynet.utils",
        "easynet.utils.config",
        "easynet.utils.logging",
        "easynet.utils.platform",
    ],
    hookspath=[os.path.join(PROJECT_ROOT, "scripts")],
    hooksconfig={},
    runtime_hooks=[
        os.path.join("scripts", "pyinstaller_runtime_hook.py"),
    ],
    excludes=[
        # Exclude heavy unused packages to reduce binary size
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "PIL",
        "scipy",
        "IPython",
        "notebook",
        "test",
        "unittest",
        "pytest",
        "cryptography",
        # Scapy is not imported at runtime (we use struct+socket directly)
        # Excluding it avoids cryptography pyo3 issues
        "scapy",
        "scapy.all",
        "scapy.config",
        "scapy.layers",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="easynet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,               # Compress with UPX if available
    upx_exclude=[],
    runtime_tmpdir=None,     # Extract to temp dir (None = auto)
    console=True,            # Console application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,        # Auto-detect architecture
    codesign_identity=None,
    entitlements_file=None,
    icon=None,               # Add icon path here if desired: icon="assets/icon.ico"
)
