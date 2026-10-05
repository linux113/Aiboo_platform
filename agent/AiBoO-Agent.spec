# -*- mode: python ; coding: utf-8 -*-
#
# AiBoO agent - PyInstaller build recipe -> dist\AiBoO-Agent.exe
#
# Do not run this by hand: double-click build_agent.bat (Windows). It installs
# the right packages, runs PyInstaller with this file and puts the finished
# package (exe + config.ini + installer) into dist.zip.
#
# Notes
# * One single .exe (onefile). Everything the agent writes (config.ini,
#   trigate_memory.json, alerts_queue.db, access_control_state.json,
#   threat_feeds\, logs) is kept NEXT TO the .exe, never in the temporary
#   unpack folder.
# * config\event_rules.yaml and config\ip_blocklist.txt are packed inside the
#   .exe as a fallback; the copies in the config folder next to the .exe win
#   (so they can be edited).
# * Must be built ON WINDOWS (PyInstaller cannot cross-compile).
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

AGENT_DIR = os.path.abspath(SPECPATH)
sys.path.insert(0, AGENT_DIR)

# All agent code packages (some modules are only imported inside functions,
# so list every module explicitly). The names are read from the folders -
# importing the packages here would hit their circular imports.
LOCAL_PACKAGES = ['agents', 'api', 'core', 'engines', 'gates', 'llm',
                  'log_ingestion', 'models', 'response', 'utils']


def local_modules(package):
    names = []
    root = os.path.join(AGENT_DIR, package)
    for folder, subdirs, files in os.walk(root):
        subdirs[:] = [d for d in subdirs if d != '__pycache__' and not d.startswith('.')]
        rel = os.path.relpath(folder, AGENT_DIR).replace(os.sep, '.')
        for f in files:
            if f.endswith('.py'):
                names.append(rel if f == '__init__.py' else f'{rel}.{f[:-3]}')
    return sorted(names)


hiddenimports = []
for pkg in LOCAL_PACKAGES:
    hiddenimports += local_modules(pkg)

hiddenimports += [
    # pywin32 (Windows event log, accounts). win32timezone is needed by
    # pywin32 for event times but is not found automatically.
    'win32evtlog', 'win32evtlogutil', 'win32security', 'win32api', 'win32con',
    'pywintypes', 'win32timezone',
    # other run-time imports
    'yaml', 'sqlite3', 'configparser', 'psutil', 'httpx', 'aiohttp',
    'requests', 'cachetools', 'dotenv',
]
hiddenimports += collect_submodules('uvicorn')

datas = [(os.path.join(AGENT_DIR, 'config'), 'config')]
binaries = []
for pkg in ('socketio', 'engineio'):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h
hiddenimports += ['engineio.async_drivers.aiohttp', 'engineio.async_drivers.threading']

a = Analysis(
    [os.path.join(AGENT_DIR, 'main.py')],
    pathex=[AGENT_DIR],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'pytest', 'tests', 'IPython', 'matplotlib'],
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
    upx=False,              # UPX-packed files are flagged more often by antivirus
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # WINDOWLESS: no black window ever appears on the client PC.
                            # The agent still writes its log to logs\agent-stdout.log
                            # next to the .exe (see prepare_std_streams() in main.py),
                            # and show_status.bat shows it when you want to look.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,         # ask Windows for Administrator rights (needed to read
                            # the Security log). Windows shows its own yes/no box;
                            # that is the correct, visible UAC prompt.
)
