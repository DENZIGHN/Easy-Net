"""Entry point for PyInstaller frozen executable."""

import multiprocessing
import os
import sys
import traceback


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
