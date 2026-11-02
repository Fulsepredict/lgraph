/**
 * Главный процесс десктопного приложения Lgraph (`electron/main.cjs`).
 *
 * Почему демон запускается с `windowsHide: true` на выделенном порту `127.0.0.1:8765`
 * и защищён `requestSingleInstanceLock()`:
 * 1. При запуске через ярлык или команду `lgraph .` не всплывают чёрные консоли Python.
 * 2. Проверка здоровья демона сверяет совпадение заголовка `X-Lgraph-Token`.
 * 3. Повторный вызов `lgraph <папка>` фокусирует уже открытое окно и без гонок переключает карту.
 */

const { app, BrowserWindow } = require('electron');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { initializeDaemonToken, registerIpcGateway } = require('./ipcGateway.cjs');

const PROJECT_ROOT = path.resolve(__dirname, '../..');
const RUNTIME_DIR = path.join(PROJECT_ROOT, '.lgraph_runtime');
const DAEMON_BASE_URL = process.env.LGRAPH_DAEMON_URL || 'http://127.0.0.1:8765';
const OPEN_PROJECT_ARG_PREFIX = '--open-project=';

let mainWindow = null;
let daemonProcess = null;
let isRendererReady = false;
let pendingInitialProjectDir = resolveCliTargetDirectory(process.argv, process.cwd());

function resolveCliTargetDirectory(argv, baseDir) {
  if (!Array.isArray(argv)) {
    return null;
  }
  for (const rawArg of argv) {
    if (typeof rawArg !== 'string' || !rawArg.startsWith(OPEN_PROJECT_ARG_PREFIX)) {
      continue;
    }
    const candidateRaw = rawArg.slice(OPEN_PROJECT_ARG_PREFIX.length).trim().replace(/^"+|"+$/g, '');
    if (!candidateRaw || candidateRaw.includes('\0')) {
      continue;
    }
    try {
      const candidatePath = path.resolve(baseDir || process.cwd(), candidateRaw);
      const stat = fs.lstatSync(candidatePath);
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        return null;
      }
      const realPath = fs.realpathSync.native(candidatePath);
      const samePath =
        process.platform === 'win32'
          ? realPath.toLowerCase() === candidatePath.toLowerCase()
          : realPath === candidatePath;
      if (samePath) {
        return realPath;
      }
    } catch (_err) {
      return null;
    }
  }
  return null;
}

function resolvePythonExecutable() {
  const venvPy = path.join(PROJECT_ROOT, 'backend', 'venv', 'Scripts', 'python.exe');
  if (fs.existsSync(venvPy)) {
    return venvPy;
  }
  return 'python';
}

async function isDaemonHealthyAndAuthenticated(daemonToken) {
  try {
    const healthRes = await fetch(`${DAEMON_BASE_URL}/api/health`, { method: 'GET' });
    if (!healthRes.ok) {
      return false;
    }
    const healthJson = await healthRes.json().catch(() => null);
    if (!healthJson || healthJson.service !== 'lgraph') {
      return false;
    }
    const authRes = await fetch(`${DAEMON_BASE_URL}/api/projects`, {
      method: 'GET',
      headers: { 'X-Lgraph-Token': daemonToken, Accept: 'application/json' },
    });
    return authRes.status === 200;
  } catch (_err) {
    return false;
  }
}

async function ensurePythonDaemonRunning(daemonToken) {
  if (await isDaemonHealthyAndAuthenticated(daemonToken)) {
    return;
  }

  const pyExe = resolvePythonExecutable();
  const childEnv = { ...process.env };
  delete childEnv.ELECTRON_RUN_AS_NODE;

  daemonProcess = spawn(
    pyExe,
    ['-m', 'uvicorn', 'backend.api.main:app', '--host', '127.0.0.1', '--port', '8765'],
    {
      cwd: PROJECT_ROOT,
      windowsHide: true,
      env: {
        ...childEnv,
        LGRAPH_RUNTIME_DIR: RUNTIME_DIR,
        LGRAPH_API_TOKEN: daemonToken,
        PYTHONIOENCODING: 'utf-8',
      },
    }
  );

  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (await isDaemonHealthyAndAuthenticated(daemonToken)) {
      return;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

function stopPythonDaemon() {
  if (daemonProcess && !daemonProcess.killed) {
    try {
      daemonProcess.kill();
    } catch (_err) {
      // Игнорируем ошибку при завершении дочернего процесса
    }
    daemonProcess = null;
  }
}

function resolveWindowIconPath() {
  const iconIco = path.join(__dirname, '..', 'public', 'logo.ico');
  if (fs.existsSync(iconIco)) {
    return iconIco;
  }
  const iconPng = path.join(__dirname, '..', 'public', 'logo.png');
  return fs.existsSync(iconPng) ? iconPng : undefined;
}

async function createMainWindow() {
  isRendererReady = false;
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 1120,
    minHeight: 720,
    backgroundColor: '#0E0E10',
    autoHideMenuBar: true,
    title: 'Lgraph — Карта архитектуры и контрактов',
    icon: resolveWindowIconPath(),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.webContents.on('did-start-loading', () => {
    isRendererReady = false;
  });
  mainWindow.on('closed', () => {
    isRendererReady = false;
    mainWindow = null;
  });

  const distIndex = path.join(__dirname, '..', 'dist', 'index.html');
  const forceDev = process.env.LGRAPH_DEV === '1';

  if (!forceDev && fs.existsSync(distIndex)) {
    await mainWindow.loadFile(distIndex);
  } else {
    await mainWindow.loadURL('http://127.0.0.1:5179');
  }
}

const gotSingleInstanceLock = app.requestSingleInstanceLock();

if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', (_event, commandLine, workingDirectory) => {
    const requestedDir = resolveCliTargetDirectory(commandLine, workingDirectory);
    if (requestedDir) {
      pendingInitialProjectDir = requestedDir;
    }
    if (mainWindow) {
      if (mainWindow.isMinimized()) {
        mainWindow.restore();
      }
      mainWindow.focus();
      if (requestedDir && isRendererReady) {
        mainWindow.webContents.send('lgraph-app:open-folder', requestedDir);
      }
    }
  });

  app.whenReady().then(async () => {
    const daemonToken = initializeDaemonToken(RUNTIME_DIR);
    registerIpcGateway({
      daemonBaseUrl: DAEMON_BASE_URL,
      daemonToken,
      getMainWindow: () => mainWindow,
      selfRootPath: PROJECT_ROOT,
      getInitialProjectDir: () => {
        isRendererReady = true;
        return pendingInitialProjectDir;
      },
    });
    await ensurePythonDaemonRunning(daemonToken);
    await createMainWindow();
  });

  app.on('window-all-closed', () => {
    stopPythonDaemon();
    if (process.platform !== 'darwin') {
      app.quit();
    }
  });

  app.on('before-quit', () => {
    stopPythonDaemon();
  });
}
