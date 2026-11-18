"""Machine profile for the config sheet (paper section 4.3 A: CPU, RAM, OS,
compiler flags, IUT name/version/commit, classical library version)."""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

import psutil

from . import backends
from .protocol import ROOT


def _cpu_model() -> str:
    try:
        if sys.platform == "win32":
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        if sys.platform == "darwin":
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def _git(*args: str) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def _power_note() -> str | None:
    try:
        if sys.platform == "win32":
            return subprocess.check_output(["powercfg", "/getactivescheme"], text=True,
                                           stderr=subprocess.DEVNULL).strip()
        gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        if gov.exists():
            return f"scaling_governor={gov.read_text().strip()}"
    except Exception:
        pass
    return None


def profile() -> dict:
    freq = psutil.cpu_freq()
    batt = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    commit = _git("rev-parse", "HEAD")
    dirty = _git("status", "--porcelain", "--", ".")
    return {
        "cpu_model": _cpu_model(),
        "cpu_logical": psutil.cpu_count(logical=True),
        "cpu_physical": psutil.cpu_count(logical=False),
        "cpu_freq_mhz": {"current": freq.current, "max": freq.max} if freq else None,
        "ram_bytes": psutil.virtual_memory().total,
        "os": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "python_impl": platform.python_implementation(),
        "python_compiler": platform.python_compiler(),
        "on_ac_power": None if batt is None else bool(batt.power_plugged),
        "power_profile": _power_note(),
        "iut_versions": {b: backends.version(b) for b in backends.BACKENDS},
        "harness_commit": commit,
        "harness_tree_dirty": bool(dirty) if dirty is not None else None,
        "env_overrides": {k: os.environ[k] for k in ("OPENSSL_ia32cap", "PYTHONHASHSEED") if k in os.environ},
    }
