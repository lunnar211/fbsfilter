# -*- mode: python ; coding: utf-8 -*-
"""
FBSFilter PyInstaller spec file.

Build commands (from project root):
    pyinstaller fbsfilter.spec --noconfirm --clean

or via the helper script:
    python build_exe.py

Output:
    dist/FBSFilter/FBSFilter.exe   – main executable
    dist/FBSFilter/*.dll / *.pyd   – supporting files (keep in same folder)

Zip the entire dist/FBSFilter/ folder for distribution.
"""

import os

block_cipher = None

a = Analysis(
    ['fbsfilter_gui.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('utils', 'utils'),
        ('config.ini', '.'),
    ],
    hiddenimports=[
        # Groq SDK – collect all sub-modules so runtime imports work
        'groq',
        'groq._models',
        'groq._client',
        'groq._base_client',
        'groq.resources',
        'groq.resources.chat',
        'groq.resources.chat.completions',
        'groq.resources.models',
        'groq._streaming',
        'groq._exceptions',
        # HTTP / networking
        'requests',
        'requests.adapters',
        'requests.auth',
        'requests.packages',
        'urllib3',
        'urllib3.contrib',
        'urllib3.contrib.socks',
        'httpx',
        'httpcore',
        'anyio',
        'anyio._backends._asyncio',
        'anyio._backends._trio',
        'sniffio',
        # Utilities
        'colorama',
        'tqdm',
        'certifi',
        'charset_normalizer',
        'idna',
        # tkinter (Windows build bundles these automatically but list them
        # to avoid missing-module warnings)
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.messagebox',
        # Standard-library helpers
        'concurrent.futures',
        'logging.handlers',
        'json',
        'configparser',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy packages we don't need
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
        'test',
        'unittest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='FBSFilter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # GUI app – no console window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Uncomment the next line and set a path to add a custom taskbar icon:
    # icon='assets/icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='FBSFilter',
)
