"""PyInstaller hook for easynet — ensures all runtime dependencies are collected.

Place this file in hookspath or it will be picked up automatically via the spec.
PyInstaller runs hooks during Analysis to discover imports that static analysis misses.
"""

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# Collect ALL submodules of these packages — this is the nuclear option
# that guarantees nothing is missed regardless of platform.
hiddenimports = []

# Core dependencies that MUST be in the bundle
for pkg in [
    "click",
    "rich",
    "yaml",
    "aiohttp",
    "dns",
    "multidict",
    "yarl",
    "frozenlist",
    "aiosignal",
    "aiohappyeyeballs",
    "easynet",
]:
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

# Collect data files (templates, etc.)
datas = []
for pkg in ["rich", "click"]:
    try:
        datas += collect_data_files(pkg)
    except Exception:
        pass
