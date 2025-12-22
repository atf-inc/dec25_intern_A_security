# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from __future__ import annotations

import functools
import importlib.resources
import logging
import os
import shutil
from pathlib import Path

LOG: logging.Logger = logging.getLogger(__name__)

# We use buck internally to bundle the code into a .par file which
# can't access the rules directly. Hence the special casing here.
RULES_ROOT: Path = Path(__file__).parent / "rules"
RULES_CONFIG_FILE_PATH: Path = RULES_ROOT / "config.yaml"
ENABLE_REGEX_ANALYZER = True
INCLUDE_SEMGREP_PROJECT_ROOT_PARAMETER = True

# Allow disabling semgrep via environment variable (useful on platforms
# where semgrep-core is not available, e.g. some Windows setups).
ENABLE_SEMGREP: bool = os.environ.get("CODESHIELD_DISABLE_SEMGREP", "0") != "1"
SEMGREP_RULE_REPO_PATH: Path = Path(__file__).parent / "rules" / "semgrep"
SEMGREP_GENERATED_RULES_PATH: Path = SEMGREP_RULE_REPO_PATH / "_generated_"


def _get_semgrep_core_path() -> Path:
    # On Windows, the binary is semgrep-core.exe, on Unix it's semgrep-core
    import platform
    is_windows = platform.system() == "Windows"
    semgrep_core_name = "semgrep-core.exe" if is_windows else "semgrep-core"
    
    # Try using importlib.resources.files (newer API, more reliable)
    try:
        files = importlib.resources.files("semgrep.bin")
        path = files / semgrep_core_name
        if path.is_file():
            return Path(str(path))
    except (FileNotFoundError, ModuleNotFoundError, AttributeError):
        pass
    
    # Fallback to importlib.resources.path (older API)
    try:
        with importlib.resources.path("semgrep.bin", semgrep_core_name) as path:
            if path.is_file():
                return path
    except (FileNotFoundError, ModuleNotFoundError, AttributeError):
        pass
    
    # Try without .exe extension on Windows (fallback)
    if is_windows:
        try:
            files = importlib.resources.files("semgrep.bin")
            path = files / "semgrep-core"
            if path.is_file():
                return Path(str(path))
        except (FileNotFoundError, ModuleNotFoundError, AttributeError):
            pass
        
        try:
            with importlib.resources.path("semgrep.bin", "semgrep-core") as path:
                if path.is_file():
                    return path
        except (FileNotFoundError, ModuleNotFoundError, AttributeError):
            pass

    # Try finding in PATH
    path = shutil.which(semgrep_core_name)
    if path is not None:
        return Path(path)
    
    # Try without .exe extension on Windows
    if is_windows:
        path = shutil.which("semgrep-core")
        if path is not None:
            return Path(path)

    raise Exception(
        f"Failed to find {semgrep_core_name} in PATH or in the semgrep package."
    )


@functools.lru_cache(maxsize=None)
def _make_semgrep_binary_path() -> Path:
    # create symlink/copy to semgrep-core (as osemgrep)
    source = _get_semgrep_core_path()
    # Handle both .exe and non-.exe extensions
    source_str = str(source)
    if source_str.endswith(".exe"):
        destination = Path(source_str.replace("semgrep-core.exe", "osemgrep.exe"))
    else:
        destination = Path(source_str.replace("semgrep-core", "osemgrep"))
    
    if not os.path.exists(destination):
        try:
            os.symlink(source, destination)
        except (OSError, AttributeError):
            # Fallback for Windows or systems without symlink permissions
            shutil.copy(source, destination)
    return Path(destination)


try:
    SEMGREP_BINARY_PATH: Path = _make_semgrep_binary_path()
    SEMGREP_COMMAND: list[str] = [
        str(SEMGREP_BINARY_PATH),
        "--experimental",
        "--optimizations",
        "all",
        "--metrics",
        "off",
        "--quiet",
        "--json",
        "--config",
    ]
except Exception as e:
    # If semgrep-core is not available, fall back gracefully by disabling
    # semgrep-based analysis. Regex-based analysis will still run.
    LOG.warning(
        "CodeShield: semgrep-core not found, disabling SEMGREP analyzer. "
        "Set CODESHIELD_DISABLE_SEMGREP=0 and ensure semgrep is installed "
        "if you want SEMGREP-based scanning. Error: %s",
        e,
    )
    ENABLE_SEMGREP = False
    SEMGREP_BINARY_PATH = Path("")
    SEMGREP_COMMAND = []
