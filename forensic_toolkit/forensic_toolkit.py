#!/usr/bin/env python3
"""
Forensic Toolkit - File Anomaly & Forensic Analysis Tool
=========================================================
A sandboxed, offline forensic analysis tool for detecting file anomalies.
Supports: Video, Image, Audio, and Document files.

Modes:
  1. Single File Analysis - Full forensic breakdown of one file
  2. Comparison Analysis  - Anomaly detection between two or more files

Usage:
  python3 forensic_toolkit.py

On first run, this script will:
  - Create a virtual environment
  - Install all required libraries (offline, no APIs)
  - Re-launch itself inside the virtual environment
"""

import os
import sys
import subprocess
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(SCRIPT_DIR, ".venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python3")
VENV_PIP = os.path.join(VENV_DIR, "bin", "pip")

REQUIRED_PACKAGES = [
    "opencv-python-headless",
    "Pillow",
    "pymediainfo",
    "mutagen",
    "python-docx",
    "PyPDF2",
    "numpy",
    "openpyxl",
]

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                  FORENSIC TOOLKIT v1.0                      ║
║          File Anomaly & Forensic Analysis Tool              ║
║                                                             ║
║  Sandboxed | Offline | No Data Leaves This Machine          ║
╚══════════════════════════════════════════════════════════════╝
"""


def is_inside_venv():
    """Check if we are already running inside our virtual environment."""
    return (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    ) and os.path.exists(VENV_DIR)


def setup_environment():
    """Create virtual environment and install dependencies."""
    print(BANNER)
    print("[*] First-run setup detected. Setting up environment...")
    print(f"[*] Creating virtual environment at: {VENV_DIR}")

    subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
    print("[+] Virtual environment created.")

    print("[*] Installing required libraries (all local, no APIs)...")
    for pkg in REQUIRED_PACKAGES:
        print(f"    Installing {pkg}...")
        subprocess.check_call(
            [VENV_PIP, "install", pkg],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    print("[+] All dependencies installed.\n")


def relaunch_in_venv():
    """Re-launch this script inside the virtual environment."""
    print("[*] Re-launching inside virtual environment...\n")
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)


def check_system_dependencies():
    """Check for system-level dependencies like mediainfo."""
    if not shutil.which("mediainfo"):
        print("[!] NOTE: 'mediainfo' is not installed on your system.")
        print("    Video/audio analysis will still work but with reduced detail.")
        print("    For full analysis, you can optionally install it later:")
        print("      Ubuntu/Debian: sudo apt install mediainfo")
        print("      Fedora:        sudo dnf install mediainfo")
        print("      macOS:         brew install mediainfo")
        print()


def main():
    # Step 1: Environment bootstrap
    if not is_inside_venv():
        if not os.path.exists(VENV_PYTHON):
            setup_environment()
        relaunch_in_venv()
        return

    # Step 2: We are inside the venv — import and run the toolkit
    check_system_dependencies()

    # Add project directory to path
    sys.path.insert(0, SCRIPT_DIR)

    from core.interface import run_toolkit
    run_toolkit()


if __name__ == "__main__":
    main()
