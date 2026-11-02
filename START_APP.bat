@echo off
setlocal
set "_LG_ORIG_CP="
for /f "tokens=2 delims=:." %%A in ('chcp') do set "_LG_ORIG_CP=%%A"
chcp 65001 >nul
set ELECTRON_RUN_AS_NODE=
if "%~1"=="" (
  start "" "%~dp0frontend\node_modules\electron\dist\electron.exe" "%~dp0frontend"
) else (
  start "" "%~dp0frontend\node_modules\electron\dist\electron.exe" "%~dp0frontend" "--open-project=%~f1"
)
if defined _LG_ORIG_CP chcp %_LG_ORIG_CP% >nul
exit /b 0
