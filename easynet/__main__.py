"""Entry point for PyInstaller frozen executable."""

import multiprocessing
import sys

if __name__ == "__main__":
    # Required for Windows multiprocessing support in frozen executables
    multiprocessing.freeze_support()

    from easynet.cli.main import cli
    cli()
