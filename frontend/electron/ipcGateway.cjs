/**
 * Шлюз безопасности Electron IPC -> Локальный демон Python (`127.0.0.1:8765`).
 *
 * Почему все запросы UI проходят через `ipcMain.handle`:
 * 1. Главный процесс сам прикрепляет одноразовый токен `X-Lgraph-Token` (с правами `icacls` / `0600`).
 * 2. Проверяется, что путь запроса начинается строго с `/api/`, исключая SSRF.
 * 3. Показ файла в Проводнике проходит каноническую проверку `realpathSync.native` без `shell.openPath`
 *    (чтобы клик по `.js` / `.bat` в чужом проекте никогда не запускал `wscript.exe`).
 */

const { dialog, ipcMain, shell } = require('electron');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_SELF_ROOT = path.resolve(__dirname, '../..');

function restrictTokenFileAcl(tokenPath) {
  if (!fs.existsSync(tokenPath)) {
    return;
  }
  if (process.platform === 'win32') {
    const username = (process.env.USERNAME || '').trim();
    if (username) {
      try {
        execFileSync(
          'icacls',
          [tokenPath, '/inheritance:r', '/grant:r', `${username}:(R,W)`],
          { windowsHide: true, stdio: 'ignore' }
        );
      } catch (_err) {
        // Игнорируем сбой утилиты на нестандартных ФС без NTFS ACL
      }
    }
  } else {
    try {
      fs.chmodSync(tokenPath, 0o600);
    } catch (_err) {
      // Игнорируем ошибку смены прав
    }
  }
}

function initializeDaemonToken(runtimeDir) {
  fs.mkdirSync(runtimeDir, { recursive: true });
  const tokenPath = path.join(runtimeDir, 'daemon.token');
  if (fs.existsSync(tokenPath)) {
    const existing = fs.readFileSync(tokenPath, 'utf8').trim();
    if (existing.length >= 32) {
      restrictTokenFileAcl(tokenPath);
      return existing;
    }
  }
  const fresh = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(tokenPath, fresh, { encoding: 'utf8', mode: 0o600 });
  restrictTokenFileAcl(tokenPath);
  return fresh;
}

function validateAndResolveProjectFile(rootPath, relPath) {
  if (!rootPath || !relPath || rootPath.includes('\0') || relPath.includes('\0')) {
    throw new Error('Некорректный путь к файлу проекта.');
  }
  const rootStat = fs.lstatSync(rootPath);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('Отклонено по безопасности: корень проекта недоступен или является ссылкой.');
  }
  const realRoot = fs.realpathSync.native(rootPath);
  const candidateTarget = path.resolve(realRoot, relPath);
  const targetStat = fs.lstatSync(candidateTarget);
  if (!targetStat.isFile() || targetStat.isSymbolicLink()) {
    throw new Error('Отклонено по безопасности: целевой объект не является обычным файлом.');
  }
  const realTarget = fs.realpathSync.native(candidateTarget);
  const relCheck = path.relative(realRoot, realTarget);
  if (!relCheck || relCheck === '..' || relCheck.startsWith(`..${path.sep}`) || path.isAbsolute(relCheck)) {
    throw new Error('Отклонено по безопасности: обнаружен выход за пределы директории проекта.');
  }
  return realTarget;
}

function registerIpcGateway({
  daemonBaseUrl,
  daemonToken,
  getMainWindow,
  selfRootPath = DEFAULT_SELF_ROOT,
  getInitialProjectDir = () => null,
}) {
  ipcMain.handle('lgraph-app:startup-context', async () => ({
    selfRootPath,
    initialProjectDir: getInitialProjectDir(),
  }));

  ipcMain.handle('lgraph-api:request', async (_event, payload) => {
    const rawPath = String((payload && payload.path) || '');
    if (!rawPath.startsWith('/api/')) {
      throw new Error('Отклонено шлюзом IPC: разрешены только маршруты /api/*.');
    }
    const method = String((payload && payload.method) || 'GET').toUpperCase();
    const targetUrl = `${daemonBaseUrl}${rawPath}`;

    const headers = {
      'X-Lgraph-Token': daemonToken,
      Accept: 'application/json',
    };
    const fetchOpts = { method, headers };
    if (payload && payload.body !== undefined && method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      fetchOpts.body = JSON.stringify(payload.body);
    }

    const res = await fetch(targetUrl, fetchOpts);
    const data = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
    if (!res.ok) {
      throw new Error(data.detail || `Ошибка демона Lgraph (${res.status})`);
    }
    return data;
  });

  ipcMain.handle('lgraph-dialog:pick-folder', async () => {
    const win = getMainWindow();
    const result = await dialog.showOpenDialog(win, {
      title: 'Выберите корневую папку проекта для анализа в Lgraph',
      properties: ['openDirectory'],
    });
    if (result.canceled || !result.filePaths.length) {
      return null;
    }
    return result.filePaths[0];
  });

  ipcMain.handle('lgraph-editor:open-file', async (_event, payload) => {
    const rootPath = String((payload && payload.rootPath) || '');
    const relPath = String((payload && payload.relPath) || '');
    if (!rootPath || !relPath) {
      return { ok: false };
    }
    const safeTarget = validateAndResolveProjectFile(rootPath, relPath);
    shell.showItemInFolder(safeTarget);
    return { ok: true };
  });
}

module.exports = {
  initializeDaemonToken,
  registerIpcGateway,
  validateAndResolveProjectFile,
};
