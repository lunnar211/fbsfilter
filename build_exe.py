"""
build_exe.py – Build FBSFilter GUI as a Windows .exe using PyInstaller.

Usage (from the project root):
    python build_exe.py

Requirements:
    pip install pyinstaller

The resulting executable will be written to:
    dist/FBSFilter/FBSFilter.exe   (one-folder bundle)
or
    dist/FBSFilter.exe             (single-file, with --onefile flag)
"""

import os
import subprocess
import sys


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    spec = os.path.join(root, "fbsfilter.spec")

    if os.path.isfile(spec):
        cmd = [sys.executable, "-m", "PyInstaller", spec, "--noconfirm"]
    else:
        icon_path = os.path.join(root, "assets", "icon.ico")
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name", "FBSFilter",
            "--onedir",
            "--windowed",
            "--add-data", f"{os.path.join(root, 'utils')}{os.pathsep}utils",
            "--add-data", f"{os.path.join(root, 'config.ini')}{os.pathsep}.",
            "--hidden-import", "groq",
            "--hidden-import", "requests",
            "--hidden-import", "urllib3",
            "--hidden-import", "colorama",
            "--hidden-import", "tqdm",
            "--hidden-import", "tkinter",
            "--hidden-import", "tkinter.ttk",
            "--hidden-import", "tkinter.scrolledtext",
            "--hidden-import", "tkinter.filedialog",
            "--hidden-import", "tkinter.messagebox",
            os.path.join(root, "fbsfilter_gui.py"),
        ]
        if os.path.isfile(icon_path):
            cmd = cmd[:5] + ["--icon", icon_path] + cmd[5:]

    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=root)
    if result.returncode != 0:
        print("\n[ERROR] PyInstaller failed. See output above.")
        sys.exit(1)
    print("\n[SUCCESS] Build complete.")
    print("  Executable: dist/FBSFilter/FBSFilter.exe  (or dist/FBSFilter.exe if --onefile)")


if __name__ == "__main__":
    main()
