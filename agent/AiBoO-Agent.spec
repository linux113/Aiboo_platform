# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('api', 'api'), ('agents', 'agents'), ('core', 'core'), ('engines', 'engines'), ('gates', 'gates'), ('log_ingestion', 'log_ingestion'), ('response', 'response'), ('utils', 'utils'), ('config', 'config')]
binaries = []
hiddenimports = ['yaml', 'win32evtlog', 'win32evtlogutil', 'win32security', 'pywintypes', 'psutil', 'uvicorn', 'httpx', 'fastapi', 'sqlite3', 'configparser', 'aiohttp', 'socketio', 'engineio', 'engineio.async_drivers.asyncio', 'engineio.async_drivers.threading']
tmp_ret = collect_all('socketio')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('engineio')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    name='AiBoO-Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
