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
    [os.path.join("easynet", "__main__.py")],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        # Bundle the default config file inside the executable
        (os.path.join("config", "default.yaml"), "config"),
    ],
    hiddenimports=[
        # Scapy layers needed at runtime (loaded dynamically)
        "scapy.layers.inet",
        "scapy.layers.l2",
        "scapy.layers.dns",
        # aiohttp internal modules
        "aiohttp._http_parser",
        "aiohttp._helpers",
        "aiohttp._websocket",
        # dnspython
        "dns.rdtypes.ANY",
        "dns.rdtypes.IN",
        "dns.rdtypes.IN.A",
        "dns.rdtypes.IN.AAAA",
        # Click completion
        "click.shell_completion",
        # Rich
        "rich.traceback",
        # EasyNet submodules
        "easynet.core",
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
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
