# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['cutter.py'],
    pathex=['.'],
    binaries=[],
    datas=[('config/config.json', 'config')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PyQt5", "PySide6",
        "torch", "torchvision", "torchaudio",
        "scipy", "numpy", "pandas",
        "matplotlib", "IPython", "jupyter",
        "notebook", "qtconsole",
        "tkinter", "_tkinter",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='cutter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='cutter',
)
