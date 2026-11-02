/**
 * Сквозной E2E-тест живой связки Electron (preload + sandbox + ipcGateway) + Python Uvicorn + React/ELK.js.
 *
 * Почему запускается в скрытом окне (`show: false`) на изолированном порту `18765` и временной папке:
 * 1. Не мешает работе пользователя и параллельным процессам в других проектах.
 * 2. Доказывает на 100%, что собранный `frontend/dist/index.html` без единой ошибки в консоли
 *    связывается с демоном по токену `X-Lgraph-Token`, индексирует проект и рисует карточки графа `@xyflow/react`.
 */

const { app, BrowserWindow } = require('electron');
const { spawn } = require('node:child_process');
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
const TMP_RUNTIME = fs.mkdtempSync(path.join(os.tmpdir(), 'lgraph_e2e_'));
const TEST_PORT = 18765;
const DAEMON_URL = `http://127.0.0.1:${TEST_PORT}`;
const TOKEN = initializeDaemonToken(TMP_RUNTIME);

let daemonProc = null;

function cleanupAndExit(code) {
  if (daemonProc && !daemonProc.killed) {
    try {
      daemonProc.kill();
    } catch (_e) {
      // ignore
    }
  }
  try {
    fs.rmSync(TMP_RUNTIME, { recursive: true, force: true });
  } catch (_e) {
    // ignore
  }
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

app.whenReady().then(async () => {
  try {
    const pyExe = path.join(PROJECT_ROOT, 'backend', 'venv', 'Scripts', 'python.exe');
    daemonProc = spawn(
      pyExe,
      ['-m', 'uvicorn', 'backend.api.main:app', '--host', '127.0.0.1', '--port', String(TEST_PORT)],
      {
        cwd: PROJECT_ROOT,
        windowsHide: true,
        env: {
          ...process.env,
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

    // Кликаем кнопку быстрого открытия самого проекта Lgraph на стартовом экране (ждём resolve startup-context)
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

    // Ждём завершения индексации и укладки графа ELK.js
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

    // Кликаем первый узел на карте и проверяем открытие двуязычного Паспорта модуля («Простым языком»)
    const inspectorOpened = await win.webContents.executeJavaScript(`
      (async () => {
        const cards = Array.from(document.querySelectorAll('.react-flow__node'));
        const bridgeCard = cards.find((c) => c.innerText.includes('bridge_linker') || c.innerText.includes('api')) || cards[0];
        bridgeCard.click();
        await new Promise((r) => setTimeout(r, 500));
        return document.body.innerText.includes('Простым языком') && document.body.innerText.includes('Техпаспорт');
      })();
    `);

    if (!inspectorOpened || pageErrors.length > 0) {
      writeStatus({ ok: false, stage: 'inspector', inspectorOpened, pageErrors });
      cleanupAndExit(1);
      return;
    }

    // Проверяем защиту от выхода за пределы корня в validateAndResolveProjectFile (P0-2)
    let traversalBlocked = false;
    try {
      validateAndResolveProjectFile(PROJECT_ROOT, '..\\outside_secret.txt');
    } catch (_secErr) {
      traversalBlocked = true;
    }
    if (!traversalBlocked) {
      writeStatus({ ok: false, stage: 'traversalCheck' });
      cleanupAndExit(1);
      return;
    }

    // Проверяем живое переключение папки через push-канал `lgraph-app:open-folder` (CLI second-instance)
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
      inspectorOpened,
      pageErrors,
    });
    cleanupAndExit(0);
  } catch (err) {
    writeStatus({ ok: false, stage: 'catch', error: String(err && err.stack ? err.stack : err) });
    cleanupAndExit(1);
  }
});
