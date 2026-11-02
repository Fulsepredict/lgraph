@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo [1/4] Подготовка виртуального окружения Python (backend\venv)...
if not exist "backend\venv\Scripts\python.exe" (
  python -m venv backend\venv
  if errorlevel 1 (
    echo [ОШИБКА] Не удалось создать Python venv. Убедитесь, что установлен Python 3.11+.
    pause
    exit /b 1
  )
)
"backend\venv\Scripts\python.exe" -m pip install --upgrade pip -q
"backend\venv\Scripts\python.exe" -m pip install -r backend\requirements.txt -q
if errorlevel 1 (
  echo [ОШИБКА] Не удалось установить зависимости Python.
  pause
  exit /b 1
)

echo [2/4] Установка и сборка десктопного интерфейса (Electron + React + Vite)...
call npm --prefix frontend install
if errorlevel 1 (
  echo [ОШИБКА] Не удалось выполнить npm install в папке frontend.
  pause
  exit /b 1
)
call npm --prefix frontend run build
if errorlevel 1 (
  echo [ОШИБКА] Сборка фронтенда завершилась с ошибкой.
  pause
  exit /b 1
)

echo [3/4] Создание иконки logo.ico, ярлыка на Рабочем столе и команды `lgraph`...
"backend\venv\Scripts\python.exe" scripts\build_windows_shortcuts.py

echo [4/4] Регистрация плагинов lgraph-intelligence и independent-auditor в ~/.gemini/config/plugins...
"backend\venv\Scripts\python.exe" scripts\install_antigravity_plugin.py

echo.
echo [ГОТОВО] Lgraph успешно установлен! Запустите ярлык Lgraph на Рабочем столе или введите `lgraph .` в терминале.
exit /b 0
