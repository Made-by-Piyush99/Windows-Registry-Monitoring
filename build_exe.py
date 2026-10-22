"""Build Script for Windows Registry Monitoring System

Compiles the application into a standalone Windows Executable (.exe)
using PyInstaller with all assets, icons, and dependencies bundled.
"""

import os
import sys
import subprocess
import shutil

APP_DIR = os.path.dirname(os.path.abspath(__file__))

def build():
    print("=" * 60)
    print("Building Windows Registry Monitoring System Standalone EXE")
    print("=" * 60)

    dist_dir = os.path.join(APP_DIR, "dist")
    build_dir = os.path.join(APP_DIR, "build")
    icon_path = os.path.join(APP_DIR, "data", "app_icon.ico")
    config_path = os.path.join(APP_DIR, "config.json")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name", "WindowsRegistryMonitor",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
    ]

    if os.path.exists(icon_path):
        cmd.extend(["--icon", icon_path])
        cmd.extend(["--add-data", f"{icon_path};data"])

    if os.path.exists(config_path):
        cmd.extend(["--add-data", f"{config_path};."])

    # Hidden imports
    hidden_imports = [
        "PIL",
        "PIL.Image",
        "PIL.ImageTk",
        "PIL.ImageDraw",
        "PIL.ImageFont",
        "pandas",
        "winreg",
        "ctypes",
        "ctypes.wintypes",
        "queue",
        "threading",
        "json",
        "csv",
        "hashlib",
        "sqlite3",
        "cryptography",
        "cryptography.fernet",
        "registry_scanner",
        "change_detector",
        "file_resolver",
        "alert_manager",
        "report_generator",
        "visual_reporter",
        "database",
        "autostart",
        "theme_manager",
        "settings_window",
    ]

    for hi in hidden_imports:
        cmd.extend(["--hidden-import", hi])

    cmd.append(os.path.join(APP_DIR, "main.py"))

    print("Running command:")
    print(" ".join(cmd))
    print("-" * 60)

    result = subprocess.run(cmd, cwd=APP_DIR)
    if result.returncode == 0:
        exe_path = os.path.join(dist_dir, "WindowsRegistryMonitor.exe")
        print("=" * 60)
        print("SUCCESS! Executable built successfully:")
        print(f"Path: {exe_path}")
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"Size: {size_mb:.2f} MB")
        print("=" * 60)
        return exe_path
    else:
        print(f"ERROR: Build failed with exit code {result.returncode}")
        sys.exit(result.returncode)

if __name__ == "__main__":
    build()
