/**
 * Сквозной E2E-тест живой связки Electron (preload + sandbox + CSP + ipcGateway) + Python Uvicorn + React/ELK.js.
 *
 * Почему запускается в скрытом окне на изолированном порту `18765` и временной папке `os.tmpdir()`:
 * 1. Не мешает работе пользователя и параллельным процессам в других проектах; дерево `uvicorn` гасится через `taskkill /T /F`.
 * 2. Доказывает на 100%, что собранный `frontend/dist/index.html` со строгим CSP без единой ошибки в консоли
 *    связывается с демоном по токену `X-Lgraph-Token`, индексирует проект и рисует карточки графа `@xyflow/react`.
 * 3. Проверяет `validateAndResolveProjectFile` на реальном внешнем файле (`Path Traversal`), реальном NTFS Directory Junction
 *    (`mklink /J`) и легитимных папках `C3` / файлах `C4`.
 */

const { app, BrowserWindow } = require('electron');
const { execFileSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  initializeDaemonToken,
  registerIpcGateway,
  validateAndResolveProjectFile,
} = require('../../frontend/electron/ipcGateway.cjs');

const PROJECT_ROOT = path.resolve(__dirname, '../..');
const STATUS_FILE = process.env.LGRAPH_E2E_STATUS || '';
function writeStatus(obj) {
  if (STATUS_FILE) {
    fs.writeFileSync(STATUS_FILE, JSON.stringify(obj, null, 2), 'utf8');
  }
}

const TMP_RUNTIME = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'lgraph_e2e_')));
const TEST_PORT = 18765;
const DAEMON_URL = `http://127.0.0.1:${TEST_PORT}`;
const TOKEN = initializeDaemonToken(TMP_RUNTIME);

let daemonProc = null;

function cleanupAndExit(code) {
  if (daemonProc) {
    const pid = daemonProc.pid;
    try {
      if (pid && process.platform === 'win32') {
        execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
      } else if (!daemonProc.killed) {
        daemonProc.kill('SIGTERM');
      }
    } catch (_e) { /* ignore */ }
    daemonProc = null;
  }
  try {
    fs.rmSync(TMP_RUNTIME, { recursive: true, force: true });
  } catch (_e) { /* ignore */ }
  app.exit(code);
}

async function waitHealth() {
  for (let i = 0; i < 40; i += 1) {
    try {
      const r = await fetch(`${DAEMON_URL}/api/health`);
      if (r.ok) return true;
    } catch (_e) {
      // wait
    }
    await new Promise((res) => setTimeout(res, 200));
  }
  return false;
}

function runFilesystemPerimeterChecks() {
  const projRoot = path.join(TMP_RUNTIME, 'sec_proj');
  const c3ModuleDir = path.join(projRoot, 'backend', 'api');
  const insideFile = path.join(c3ModuleDir, 'inside.py');
  fs.mkdirSync(c3ModuleDir, { recursive: true });
  fs.writeFileSync(insideFile, 'x = 1\n', 'utf8');

  // 1. Честный тест Path Traversal: целевой секретный файл РЕАЛЬНО существует за пределами корня проекта
  const outsideFile = path.join(TMP_RUNTIME, 'outside_real_secret.txt');
  fs.writeFileSync(outsideFile, 'REAL_OUTSIDE_SECRET=1\n', 'utf8');
  if (!fs.existsSync(outsideFile)) {
    throw new Error('outside_real_secret.txt was not created');
  }

  let traversalSecurityBlocked = false;
  try {
    validateAndResolveProjectFile(projRoot, '..\\outside_real_secret.txt');
  } catch (secErr) {
    const msg = String(secErr && secErr.message ? secErr.message : secErr);
    traversalSecurityBlocked = msg.includes('Отклонено по безопасности');
  }
  if (!traversalSecurityBlocked) {
    return { ok: false, stage: 'traversalRealFileCheck' };
  }

  // 2. Честный тест NTFS Directory Junction (`mklink /J`) наружу на Windows (или симлинка на POSIX)
  const outsideDir = path.join(TMP_RUNTIME, 'outside_dir');
  fs.mkdirSync(outsideDir, { recursive: true });
  fs.writeFileSync(path.join(outsideDir, 'leak.txt'), 'JUNCTION_LEAK=1\n', 'utf8');
  const junctionDir = path.join(projRoot, 'evil_junction');

  if (process.platform === 'win32') {
    execFileSync('cmd.exe', ['/c', 'mklink', '/J', junctionDir, outsideDir], {
      windowsHide: true,
      stdio: 'ignore',
    });
  } else {
    fs.symlinkSync(outsideDir, junctionDir, 'dir');
  }

  try {
    if (!fs.existsSync(path.join(junctionDir, 'leak.txt'))) {
      return { ok: false, stage: 'junctionSetupFailed' };
    }
    let junctionFileBlocked = false;
    let junctionDirBlocked = false;
    try {
      validateAndResolveProjectFile(projRoot, path.join('evil_junction', 'leak.txt'));
    } catch (jErr1) {
      junctionFileBlocked = String(jErr1 && jErr1.message ? jErr1.message : jErr1).includes(
        'Отклонено по безопасности'
      );
    }
    try {
      validateAndResolveProjectFile(projRoot, 'evil_junction');
    } catch (jErr2) {
      junctionDirBlocked = String(jErr2 && jErr2.message ? jErr2.message : jErr2).includes(
        'Отклонено по безопасности'
      );
    }
    if (!junctionFileBlocked || !junctionDirBlocked) {
      return { ok: false, stage: 'junctionBlockedCheck', junctionFileBlocked, junctionDirBlocked };
    }
  } finally {
    try {
      if (process.platform === 'win32') {
        fs.rmdirSync(junctionDir);
      } else {
        fs.unlinkSync(junctionDir);
      }
    } catch (_rmErr) {
      // ignore
    }
  }

  // 3. Легитимная папка бизнес-модуля C3 (`backend/api`) и файл C4 (`backend/api/inside.py`) разрешаются без ошибок
  const resolvedC3Dir = validateAndResolveProjectFile(projRoot, 'backend/api');
  const resolvedC4File = validateAndResolveProjectFile(projRoot, 'backend/api/inside.py');
  const expectedDir = fs.realpathSync.native(c3ModuleDir);
  const expectedFile = fs.realpathSync.native(insideFile);
  const sameDir =
    process.platform === 'win32'
      ? resolvedC3Dir.toLowerCase() === expectedDir.toLowerCase()
      : resolvedC3Dir === expectedDir;
  const sameFile =
    process.platform === 'win32'
      ? resolvedC4File.toLowerCase() === expectedFile.toLowerCase()
      : resolvedC4File === expectedFile;

  if (!sameDir || !sameFile) {
    return { ok: false, stage: 'legitimateC3AndC4Check', resolvedC3Dir, resolvedC4File };
  }
  return { ok: true };
}

app.whenReady().then(async () => {
  try {
    const pyExe = path.join(PROJECT_ROOT, 'backend', 'venv', 'Scripts', 'python.exe');
    const childEnv = { ...process.env };
    delete childEnv.ELECTRON_RUN_AS_NODE;

    daemonProc = spawn(
      pyExe,
      ['-m', 'uvicorn', 'backend.api.main:app', '--host', '127.0.0.1', '--port', String(TEST_PORT)],
      {
        cwd: PROJECT_ROOT,
        windowsHide: true,
        env: {
          ...childEnv,
          LGRAPH_RUNTIME_DIR: TMP_RUNTIME,
          LGRAPH_API_TOKEN: TOKEN,
          PYTHONUTF8: '1',
        },
      }
    );

    const healthy = await waitHealth();
    if (!healthy) {
      writeStatus({ ok: false, stage: 'waitHealth' });
      cleanupAndExit(1);
      return;
    }

    let win = null;
    registerIpcGateway({
      daemonBaseUrl: DAEMON_URL,
      daemonToken: TOKEN,
      getMainWindow: () => win,
    });

    win = new BrowserWindow({
      width: 1480,
      height: 920,
      show: true,
      opacity: 0,
      skipTaskbar: true,
      focusable: false,
      webPreferences: {
        preload: path.join(PROJECT_ROOT, 'frontend', 'electron', 'preload.cjs'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        backgroundThrottling: false,
      },
    });

    const pageErrors = [];
    win.webContents.on('page-error', (_ev, err) => pageErrors.push(String(err)));
    win.webContents.on('console-message', (_ev, level, message) => {
      if (level >= 3) {
        pageErrors.push(message);
      }
    });

    const distHtml = path.join(PROJECT_ROOT, 'frontend', 'dist', 'index.html');
    await win.loadFile(distHtml);

    await win.webContents.executeJavaScript(`
      (async () => {
        for (let i = 0; i < 20; i += 1) {
          const btns = Array.from(document.querySelectorAll('button'));
          const selfBtn = btns.find((b) => b.textContent && b.textContent.includes('Открыть сам Lgraph'));
          if (selfBtn) {
            selfBtn.click();
            return;
          }
          await new Promise((r) => setTimeout(r, 100));
        }
        throw new Error('Start button not found');
      })();
    `);

    let nodeCount = 0;
    for (let attempt = 0; attempt < 35; attempt += 1) {
      await new Promise((r) => setTimeout(r, 250));
      nodeCount = await win.webContents.executeJavaScript(
        `document.querySelectorAll('.react-flow__node').length`
      );
      if (nodeCount >= 5) break;
    }

    if (nodeCount < 5) {
      writeStatus({ ok: false, stage: 'nodeCount', nodeCount, pageErrors });
      cleanupAndExit(1);
      return;
    }

    const inspectorCheck = await win.webContents.executeJavaScript(`
      (async () => {
        const cards = Array.from(document.querySelectorAll('.react-flow__node'));
        const bridgeCard = cards.find((c) => c.innerText.includes('bridge_linker') || c.innerText.includes('api')) || cards[0];
        bridgeCard.click();
        await new Promise((r) => setTimeout(r, 500));
        const hasTabs = document.body.innerText.includes('Простым языком') && document.body.innerText.includes('Техпаспорт');
        const techTab = Array.from(document.querySelectorAll('button')).find((b) => b.textContent && b.textContent.includes('Техпаспорт'));
        if (techTab) {
          techTab.click();
          await new Promise((r) => setTimeout(r, 150));
        }
        const hasFolderBtn = document.body.innerText.includes('Показать папку');
        return { hasTabs, hasFolderBtn };
      })();
    `);

    if (!inspectorCheck.hasTabs || !inspectorCheck.hasFolderBtn || pageErrors.length > 0) {
      writeStatus({ ok: false, stage: 'inspector', inspectorCheck, pageErrors });
      cleanupAndExit(1);
      return;
    }

    const secResult = runFilesystemPerimeterChecks();
    if (!secResult.ok) {
      writeStatus(secResult);
      cleanupAndExit(1);
      return;
    }

    const ipcUrlGuardOk = await win.webContents.executeJavaScript(`
      (async () => {
        const badPaths = ['/api/../health', '/api/%2e%2e/health', '//evil.example/api/health'];
        for (const p of badPaths) {
          let blocked = false;
          try {
            await window.lgraphBridge.apiRequest({ path: p });
          } catch (e) {
            blocked = String(e && e.message ? e.message : e).includes('Отклонено шлюзом IPC');
          }
          if (!blocked) return false;
        }
        return true;
      })();
    `);
    if (!ipcUrlGuardOk) {
      writeStatus({ ok: false, stage: 'ipcUrlGuardCheck' });
      cleanupAndExit(1);
      return;
    }

    const fixtureDir = path.join(PROJECT_ROOT, 'fixtures', 'polyglot_rest_basic');
    win.webContents.send('lgraph-app:open-folder', fixtureDir);
    let switchedOk = false;
    for (let attempt = 0; attempt < 25; attempt += 1) {
      await new Promise((r) => setTimeout(r, 200));
      switchedOk = await win.webContents.executeJavaScript(
        `document.body.innerText.includes('polyglot_rest_basic')`
      );
      if (switchedOk) break;
    }
    if (!switchedOk || pageErrors.length > 0) {
      writeStatus({ ok: false, stage: 'cliSwitch', switchedOk, pageErrors });
      cleanupAndExit(1);
      return;
    }

    const shotPath = process.env.LGRAPH_E2E_SCREENSHOT || '';
    if (shotPath) {
      await new Promise((r) => setTimeout(r, 500));
      const image = await win.webContents.capturePage();
      fs.writeFileSync(shotPath, image.toPNG());
    }

    writeStatus({
      ok: true,
      renderedC3Nodes: nodeCount,
      inspectorOpened: inspectorCheck.hasTabs,
      c3FolderButtonVerified: inspectorCheck.hasFolderBtn,
      perimeterChecksPassed: true,
      pageErrors,
    });
    cleanupAndExit(0);
  } catch (err) {
    writeStatus({ ok: false, stage: 'catch', error: String(err && err.stack ? err.stack : err) });
    cleanupAndExit(1);
  }
});
