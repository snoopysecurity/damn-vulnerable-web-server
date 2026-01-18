import os
import subprocess
import sys
import platform
import shutil

def run_command(cmd, cwd=None):
    try:
        output = subprocess.check_output(cmd, cwd=cwd, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running command {cmd}: {e.output.decode('utf-8')}")
        return None

def clean_build():
    if os.path.exists("build"):
        shutil.rmtree("build")
    os.makedirs("build")

def check_aslr(binary_path):
    print(f"Checking ASLR for {binary_path}...")
    system = platform.system()
    if system == "Darwin":
        # check for PIE flag in otool -hv
        output = run_command(["otool", "-hv", binary_path])
        if output and "PIE" in output:
            return True
        return False
    elif system == "Linux":
        # use file command or readelf
        # prefer readelf if available
        try:
             output = subprocess.check_output(["readelf", "-h", binary_path], stderr=subprocess.DEVNULL).decode('utf-8')
             if "Type:" in output:
                 # DYN (Shared object file) -> PIE
                 # EXEC (Executable file) -> No PIE
                 if "DYN (Shared object file)" in output:
                     return True
                 elif "DYN (Position-Independent Executable file)" in output:
                     return True
                 elif "EXEC (Executable file)" in output:
                     return False
        except Exception:
             pass
        
        # fallback to file command
        output = run_command(["file", binary_path])
        if output:
            if "shared object" in output or "pie executable" in output:
                 return True
            return False
        return False
    else:
        print("Unknown system")
        return None

def test_aslr_builds():
    binary = os.path.abspath("build/damn_vulnerable_web_server")

    # Test 1: ASLR OFF
    print("--- Testing ASLR OFF ---")
    clean_build()
    print("Configuring CMake with -DENABLE_ASLR=OFF...")
    res = run_command(["cmake", "-DENABLE_ASLR=OFF", ".."], cwd="build")
    if res is None:
        print("CMake failed.")
        return

    print("Building...")
    res = run_command(["make"], cwd="build")
    if res is None:
        print("Make failed.")
        return
    
    if os.path.exists(binary):
        is_pie = check_aslr(binary)
        if not is_pie:
            print("[PASS] ASLR is disabled (No PIE detected).")
        else:
            print("[FAIL] ASLR is enabled but should be disabled.")
            if platform.system() == "Darwin" and platform.machine() == "arm64":
                print("       Note: macOS arm64 enforces PIE, ignoring -no_pie flag.")
    else:
        print("[FAIL] Binary not found.")

    # Test 2: ASLR ON
    print("\n--- Testing ASLR ON ---")
    clean_build()
    print("Configuring CMake with -DENABLE_ASLR=ON...")
    res = run_command(["cmake", "-DENABLE_ASLR=ON", ".."], cwd="build")
    if res is None:
        print("CMake failed.")
        return

    print("Building...")
    res = run_command(["make"], cwd="build")
    if res is None:
        print("Make failed.")
        return
    
    if os.path.exists(binary):
        is_pie = check_aslr(binary)
        if is_pie:
            print("[PASS] ASLR is enabled (PIE detected).")
        else:
            print("[FAIL] ASLR is disabled but should be enabled.")
    else:
        print("[FAIL] Binary not found.")

if __name__ == "__main__":
    test_aslr_builds()
