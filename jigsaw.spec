# -*- mode: python ; coding: utf-8 -*-
# JIGSAW — PyInstaller spec
# Author: Kennedy Aikohi

block_cipher = None

a = Analysis(
    ['jigsaw.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('rules/',    'rules/'),
        ('mappings/', 'mappings/'),
        ('USAGE.md', 'docs/'),
        ('README.md', '.'),
    ],
    hiddenimports=[
        'tkinter', 'tkinter.ttk', 'tkinter.scrolledtext',
        'tkinter.messagebox', 'tkinter.filedialog', 'tkinter.font',
        'xml.etree.ElementTree', 'json', 'csv',
        'subprocess', 'threading', 'queue', 'glob', 'pathlib',
        'ctypes', 'ctypes.wintypes',
        'Evtx', 'Evtx.Evtx', 'Evtx.Views',
        'yaml', 'tomllib', 'tomli',
        'collections',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'PIL', 'scipy', 'pandas'],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Jigsaw',
    debug=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    uac_admin=True,
    version='version_info.txt',
    icon=None,
)
