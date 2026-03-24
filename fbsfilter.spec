# -*- mode: python ; coding: utf-8 -*-
"""
FBSFilter PyInstaller spec file.

Build command (from project root):
    pyinstaller fbsfilter.spec --noconfirm

or use the helper script:
    python build_exe.py
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
        'groq',
        'groq._models',
        'requests',
        'urllib3',
        'colorama',
        'tqdm',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'concurrent.futures',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    console=False,          # GUI app – no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/icon.ico',   # uncomment and set path to add a custom icon
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
