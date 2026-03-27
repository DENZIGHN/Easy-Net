#!/usr/bin/env python3
"""Build script for creating a portable EasyNet executable.

Creates a single-file portable .exe (Windows) or binary (Linux/macOS)
using PyInstaller. The output is placed in the dist/ directory.

Usage:
    python scripts/build_exe.py [--clean] [--upx] [--debug]

Options:
    --clean     Remove previous build artifacts before building
    --upx       Compress with UPX (must be installed)
    --debug     Build with debug output enabled
    --onedir    Build as a directory instead of single file
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
SPEC_FILE = PROJECT_ROOT / "easynet.spec"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def check_pyinstaller() -> None:
    """Ensure PyInstaller is installed."""
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Installing...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "pyinstaller>=6.0"
        ])


def clean(build: bool = True, dist: bool = True) -> None:
    """Remove previous build artifacts."""
    if build and BUILD_DIR.exists():
        print(f"Removing {BUILD_DIR}")
        shutil.rmtree(BUILD_DIR)
    if dist and DIST_DIR.exists():
        print(f"Removing {DIST_DIR}")
        shutil.rmtree(DIST_DIR)


def build_exe(
    debug: bool = False,
    upx: bool = True,
    onedir: bool = False,
) -> Path:
    """Build the executable using PyInstaller.

    Returns the path to the built executable.
    """
    cmd = [sys.executable, "-m", "PyInstaller"]

    if SPEC_FILE.exists() and not onedir:
        # Use the spec file for single-file build
        cmd.append(str(SPEC_FILE))
    else:
        # Fallback: build from entry point directly
        cmd.extend([
            str(PROJECT_ROOT / "easynet" / "__main__.py"),
            "--name", "easynet",
            "--add-data", f"config/default.yaml{':' if platform.system() != 'Windows' else ';'}config",
            "--hidden-import", "scapy.layers.inet",
            "--hidden-import", "scapy.layers.dns",
            "--hidden-import", "dns.rdtypes.IN.A",
            "--hidden-import", "dns.rdtypes.IN.AAAA",
            "--hidden-import", "dns.rdtypes.ANY",
            "--console",
        ])
        if onedir:
            cmd.append("--onedir")
        else:
            cmd.append("--onefile")

    using_spec = SPEC_FILE.exists() and not onedir

    if debug:
        cmd.append("--log-level=DEBUG")
    else:
        cmd.append("--log-level=WARN")

    # These flags are only valid when NOT using a .spec file
    if not using_spec:
        if not upx:
            cmd.append("--noupx")
        for exclude in ["pytest", "ruff", "tkinter", "matplotlib", "numpy"]:
            cmd.extend(["--exclude-module", exclude])

    cmd.extend(["--distpath", str(DIST_DIR)])
    cmd.extend(["--workpath", str(BUILD_DIR)])

    print(f"Building EasyNet executable...")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print(f"  Python:   {sys.version}")
    print(f"  Command:  {' '.join(cmd)}")
    print()

    subprocess.check_call(cmd, cwd=str(PROJECT_ROOT))

    # Determine output path
    system = platform.system()
    exe_name = "easynet.exe" if system == "Windows" else "easynet"

    if onedir:
        output = DIST_DIR / "easynet" / exe_name
    else:
        output = DIST_DIR / exe_name

    if output.exists():
        size_mb = output.stat().st_size / (1024 * 1024)
        print(f"\nBuild successful!")
        print(f"  Output: {output}")
        print(f"  Size:   {size_mb:.1f} MB")
        return output
    else:
        print(f"\nERROR: Expected output not found at {output}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build portable EasyNet executable")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts first")
    parser.add_argument("--upx", action="store_true", default=True, help="Compress with UPX")
    parser.add_argument("--no-upx", action="store_true", help="Disable UPX compression")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--onedir", action="store_true", help="Build as directory instead of single file")
    args = parser.parse_args()

    check_pyinstaller()

    if args.clean:
        clean()

    output = build_exe(
        debug=args.debug,
        upx=not args.no_upx,
        onedir=args.onedir,
    )

    print(f"\nTo run: {output}")
    if platform.system() != "Windows":
        print(f"  chmod +x {output}")
    print(f"  {output} --help")


if __name__ == "__main__":
    main()
