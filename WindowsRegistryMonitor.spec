# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['D:/Windows Registry Monitoring System/main.py'],
    pathex=[],
    binaries=[],
    datas=[('D:/Windows Registry Monitoring System/data/app_icon.ico', 'data'), ('D:/Windows Registry Monitoring System/config.json', '.')],
    hiddenimports=['PIL', 'PIL.Image', 'PIL.ImageTk', 'PIL.ImageDraw', 'PIL.ImageFont', 'pandas', 'winreg', 'ctypes', 'ctypes.wintypes', 'queue', 'threading', 'json', 'csv', 'hashlib', 'sqlite3', 'cryptography', 'cryptography.fernet', 'registry_scanner', 'change_detector', 'file_resolver', 'alert_manager', 'report_generator', 'visual_reporter', 'database', 'autostart', 'theme_manager', 'settings_window'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='WindowsRegistryMonitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['D:/Windows Registry Monitoring System/data/app_icon.ico'],
)
