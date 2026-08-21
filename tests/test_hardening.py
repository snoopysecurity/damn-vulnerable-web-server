"""Verify the ENABLE_HARDENING CMake flag produces a PIE / no-PIE binary.

Replaces the older test_aslr.py, which used the deprecated flag name.
"""
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = REPO_ROOT / "build"
BINARY = BUILD_DIR / "damn_vulnerable_web_server"


def run(cmd, cwd=None):
    try:
        return subprocess.check_output(cmd, cwd=cwd, stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as e:
        print(f"[!] {cmd}\n{e.output.decode()}")
        return None


def clean_build():
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir()


def is_pie(binary_path: Path) -> bool | None:
    system = platform.system()
    if system == "Darwin":
        out = run(["otool", "-hv", str(binary_path)])
        return bool(out and "PIE" in out)
    if system == "Linux":
        try:
            out = subprocess.check_output(
                ["readelf", "-h", str(binary_path)],
                stderr=subprocess.DEVNULL,
            ).decode()
            if "DYN" in out:
                return True
            if "EXEC" in out:
                return False
        except FileNotFoundError:
            pass
        out = run(["file", str(binary_path)])
        if out:
            return "shared object" in out or "pie executable" in out
    return None


def build(hardening: bool) -> bool:
    clean_build()
    flag = "ON" if hardening else "OFF"
    if run(["cmake", f"-DENABLE_HARDENING={flag}", ".."], cwd=BUILD_DIR) is None:
        return False
    if run(["make", "-j"], cwd=BUILD_DIR) is None:
        return False
    return BINARY.exists()


def main() -> int:
    failed = 0

    print("--- ENABLE_HARDENING=OFF ---")
    if not build(hardening=False):
        print("[FAIL] build did not produce a binary")
        failed += 1
    else:
        pie = is_pie(BINARY)
        if pie is False:
            print("[PASS] non-PIE binary produced")
        else:
            note = ""
            if platform.system() == "Darwin" and platform.machine() == "arm64":
                note = " (expected: macOS arm64 always enforces PIE)"
            print(f"[FAIL] expected non-PIE, got PIE={pie}{note}")
            if not note:
                failed += 1

    print("\n--- ENABLE_HARDENING=ON ---")
    if not build(hardening=True):
        print("[FAIL] build did not produce a binary")
        failed += 1
    else:
        pie = is_pie(BINARY)
        if pie:
            print("[PASS] PIE binary produced")
        else:
            print(f"[FAIL] expected PIE, got PIE={pie}")
            failed += 1

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
