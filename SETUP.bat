@echo off
setlocal
set "_LG_ORIG_CP="
for /f "tokens=2 delims=:." %%A in ('chcp') do set "_LG_ORIG_CP=%%A"
chcp 65001 >nul
set ELECTRON_RUN_AS_NODE=
cd /d "%~dp0"

echo [1/4] Preparing Python virtual environment (backend\venv)...
if not exist "backend\venv\Scripts\python.exe" (
  python -m venv backend\venv
  if errorlevel 1 (
    echo [ERROR] Failed to create Python venv. Ensure Python 3.11+ is installed.
    goto :fail
  )
)
"backend\venv\Scripts\python.exe" -m pip install --upgrade pip -q
if errorlevel 1 (
  echo [ERROR] Failed to upgrade pip in backend\venv.
  goto :fail
)
"backend\venv\Scripts\python.exe" -m pip install -r backend\requirements.txt -q
if errorlevel 1 (
  echo [ERROR] Failed to install Python dependencies from backend\requirements.txt.
  goto :fail
)

echo [2/4] Installing and building desktop UI (Electron + React + Vite)...
call npm --prefix frontend install
if errorlevel 1 (
  echo [ERROR] npm install failed in frontend directory.
  goto :fail
)
call npm --prefix frontend run build
if errorlevel 1 (
  echo [ERROR] Frontend production build failed.
  goto :fail
)

echo [3/4] Generating logo.ico, Desktop shortcut, and lgraph CLI launcher...
"backend\venv\Scripts\python.exe" scripts\build_windows_shortcuts.py
if errorlevel 1 (
  echo [ERROR] Failed to create Windows icon, shortcut, or CLI command.
  goto :fail
)

echo [4/4] Registering lgraph-intelligence and independent-auditor plugins...
"backend\venv\Scripts\python.exe" scripts\install_antigravity_plugin.py
if errorlevel 1 (
  echo [ERROR] Failed to install Antigravity plugins.
  goto :fail
)

echo.
echo [OK] Lgraph setup completed! Launch Lgraph from Desktop or run `lgraph .` in terminal.
if defined _LG_ORIG_CP chcp %_LG_ORIG_CP% >nul
exit /b 0

:fail
if defined _LG_ORIG_CP chcp %_LG_ORIG_CP% >nul
pause
exit /b 1
