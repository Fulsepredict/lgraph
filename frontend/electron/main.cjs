/**
 * Главный процесс десктопного приложения Lgraph (`electron/main.cjs`).
 *
 * Почему демон запускается с `windowsHide: true` на выделенном порту `127.0.0.1:8765`
 * и завершается через `taskkill /T /F` на Windows:
 * 1. При запуске через ярлык или команду `lgraph .` не всплывают чёрные консоли Python.
 * 2. На Windows `venv\Scripts\python.exe` — пусковой стаб, порождающий дочерний `uvicorn`;
 *    завершение всего дерева процессов исключает зависание сиротского сервера на порту `8765`.
 * 3. Навигация окна жёстко ограничена локальным `dist/index.html` (или `127.0.0.1:5179` в dev-режиме).
 */

const { app, BrowserWindow, session } = require('electron');
const { execFileSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const { initializeDaemonToken, registerIpcGateway } = require('./ipcGateway.cjs');

const PROJECT_ROOT = path.resolve(__dirname, '../..');
const RUNTIME_DIR = path.join(PROJECT_ROOT, '.lgraph_runtime');
const DEFAULT_DAEMON_HOST = '127.0.0.1';
const DEFAULT_DAEMON_PORT = '8765';
const DAEMON_BASE_URL = process.env.LGRAPH_DAEMON_URL || `http://${DEFAULT_DAEMON_HOST}:${DEFAULT_DAEMON_PORT}`;
const DEV_SERVER_URL = 'http://127.0.0.1:5179';
const OPEN_PROJECT_ARG_PREFIX = '--open-project=';
const DAEMON_BOOT_MAX_ATTEMPTS = 40;
const DAEMON_BOOT_POLL_MS = 200;
const HEALTH_CHECK_TIMEOUT_MS = 3_000;
const APP_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; connect-src 'self' http://127.0.0.1:5179 ws://127.0.0.1:5179; object-src 'none'; base-uri 'self';";

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
    const healthRes = await fetch(`${DAEMON_BASE_URL}/api/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT_MS),
    });
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
      signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT_MS),
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
    [
      '-m',
      'uvicorn',
      'backend.api.main:app',
      '--host',
      DEFAULT_DAEMON_HOST,
      '--port',
      DEFAULT_DAEMON_PORT,
    ],
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

  for (let attempt = 0; attempt < DAEMON_BOOT_MAX_ATTEMPTS; attempt += 1) {
    if (await isDaemonHealthyAndAuthenticated(daemonToken)) {
      return;
    }
    await new Promise((r) => setTimeout(r, DAEMON_BOOT_POLL_MS));
  }
}

function stopPythonDaemon() {
  if (!daemonProcess) {
    return;
  }
  const pid = daemonProcess.pid;
  try {
    if (pid && process.platform === 'win32') {
      execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore',
      });
    } else if (!daemonProcess.killed) {
      daemonProcess.kill('SIGTERM');
    }
  } catch (_err) {
    // Дочернее дерево процессов уже завершено
  } finally {
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

  const distIndex = path.join(__dirname, '..', 'dist', 'index.html');
  const forceDev = process.env.LGRAPH_DEV === '1';
  const allowedDistHref = pathToFileURL(distIndex).href;

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    try {
      const parsedNav = new URL(navigationUrl);
      if (!forceDev && fs.existsSync(distIndex)) {
        const allowedParsed = new URL(allowedDistHref);
        const sameFile =
          process.platform === 'win32'
            ? parsedNav.pathname.toLowerCase() === allowedParsed.pathname.toLowerCase()
            : parsedNav.pathname === allowedParsed.pathname;
        if (parsedNav.protocol === 'file:' && sameFile) {
          return;
        }
      } else if (parsedNav.origin === DEV_SERVER_URL) {
        return;
      }
    } catch (_err) {
      // Некорректный URL блокируется ниже
    }
    event.preventDefault();
  });

  mainWindow.webContents.on('did-start-loading', () => {
    isRendererReady = false;
  });
  mainWindow.on('closed', () => {
    isRendererReady = false;
    mainWindow = null;
  });

  if (!forceDev && fs.existsSync(distIndex)) {
    await mainWindow.loadFile(distIndex);
  } else {
    await mainWindow.loadURL(DEV_SERVER_URL);
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
    if (process.env.LGRAPH_DEV !== '1') {
      session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
        callback({
          responseHeaders: {
            ...details.responseHeaders,
            'Content-Security-Policy': [APP_CSP],
          },
        });
      });
    }

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
