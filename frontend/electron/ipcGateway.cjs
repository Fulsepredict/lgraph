/**
 * Шлюз безопасности Electron IPC -> Локальный демон Python (`127.0.0.1:8765`).
 *
 * Почему все запросы UI проходят через `ipcMain.handle`:
 * 1. Главный процесс сам прикрепляет одноразовый токен `X-Lgraph-Token` (с правами `icacls` / `0600`).
 * 2. Проверяется отправитель (`senderFrame === mainFrame`) и канонический URL строго внутри `/api/*`.
 * 3. Показ файла/папки в Проводнике проходит посегментную проверку `lstatSync` и `realpathSync.native`
 *    без `shell.openPath` (блокируя как симлинки, так и NTFS Directory Junctions `mklink /J`).
 */

const { dialog, ipcMain, shell } = require('electron');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_SELF_ROOT = path.resolve(__dirname, '../..');
const IPC_FETCH_TIMEOUT_MS = 30_000;
const MIN_TOKEN_LENGTH = 32;

function restrictRuntimePathAcl(targetPath, isDirectory = false) {
  if (!fs.existsSync(targetPath)) {
    return;
  }
  if (process.platform === 'win32') {
    const username = (process.env.USERNAME || os.userInfo().username || '').trim();
    if (username) {
      const grantSpec = isDirectory ? `${username}:(OI)(CI)F` : `${username}:(R,W,D)`;
      try {
        execFileSync(
          'icacls',
          [targetPath, '/inheritance:r', '/grant:r', grantSpec],
          { windowsHide: true, stdio: 'ignore' }
        );
      } catch (_err) {
        // Игнорируем сбой утилиты на нестандартных ФС без NTFS ACL
      }
    }
  } else {
    try {
      fs.chmodSync(targetPath, isDirectory ? 0o700 : 0o600);
    } catch (_err) {
      // Игнорируем ошибку смены прав
    }
  }
}

function initializeDaemonToken(runtimeDir) {
  fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
  restrictRuntimePathAcl(runtimeDir, true);

  const tokenPath = path.join(runtimeDir, 'daemon.token');
  if (fs.existsSync(tokenPath)) {
    const existing = fs.readFileSync(tokenPath, 'utf8').trim();
    if (existing.length >= MIN_TOKEN_LENGTH) {
      restrictRuntimePathAcl(tokenPath, false);
      return existing;
    }
  }
  const fresh = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(tokenPath, fresh, { encoding: 'utf8', mode: 0o600 });
  restrictRuntimePathAcl(tokenPath, false);
  return fresh;
}

function isSameCanonicalPath(pathA, pathB) {
  return process.platform === 'win32'
    ? pathA.toLowerCase() === pathB.toLowerCase()
    : pathA === pathB;
}

function validateAndResolveProjectFile(rootPath, relPath) {
  if (
    typeof rootPath !== 'string' ||
    typeof relPath !== 'string' ||
    !rootPath.trim() ||
    !relPath.trim() ||
    rootPath.includes('\0') ||
    relPath.includes('\0')
  ) {
    throw new Error('Отклонено по безопасности: некорректный путь к объекту проекта.');
  }
  if (
    path.isAbsolute(relPath) ||
    /^[a-zA-Z]:/.test(relPath) ||
    relPath.startsWith('/') ||
    relPath.startsWith('\\')
  ) {
    throw new Error('Отклонено по безопасности: ожидался относительный путь внутри проекта.');
  }

  const candidateRoot = path.resolve(rootPath);
  let rootStat;
  try {
    rootStat = fs.lstatSync(candidateRoot);
  } catch (_err) {
    throw new Error('Отклонено по безопасности: корень проекта недоступен.');
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('Отклонено по безопасности: корень проекта недоступен или является ссылкой.');
  }
  const realRoot = fs.realpathSync.native(candidateRoot);
  if (!isSameCanonicalPath(realRoot, candidateRoot)) {
    throw new Error('Отклонено по безопасности: корень проекта содержит точку перенаправления.');
  }

  const candidateTarget = path.resolve(realRoot, relPath);
  const relCheck = path.relative(realRoot, candidateTarget);
  if (
    !relCheck ||
    relCheck === '..' ||
    relCheck.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relCheck)
  ) {
    throw new Error('Отклонено по безопасности: обнаружен выход за пределы директории проекта.');
  }

  // Проверяем каждый сегмент пути и сверяем `realpathSync.native === candidateTarget`,
  // поскольку на Windows у NTFS Directory Junction (`mklink /J`) `isSymbolicLink()` может вернуть `false`,
  // но `realpathSync.native` всегда раскрывает истинный внешний путь за пределами корня.
  const segments = relCheck.split(path.sep).filter(Boolean);
  let currentSeg = realRoot;
  let targetStat = null;
  for (const seg of segments) {
    currentSeg = path.join(currentSeg, seg);
    let segStat;
    try {
      segStat = fs.lstatSync(currentSeg);
    } catch (_err) {
      throw new Error('Целевой объект не найден на диске внутри директории проекта.');
    }
    if (segStat.isSymbolicLink()) {
      throw new Error('Отклонено по безопасности: обнаружена символическая ссылка в пути проекта.');
    }
    targetStat = segStat;
  }

  const realTarget = fs.realpathSync.native(candidateTarget);
  if (!isSameCanonicalPath(realTarget, candidateTarget)) {
    throw new Error('Отклонено по безопасности: обнаружена точка перенаправления (NTFS Junction / Symlink).');
  }

  const relRealCheck = path.relative(realRoot, realTarget);
  if (
    !relRealCheck ||
    relRealCheck === '..' ||
    relRealCheck.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relRealCheck)
  ) {
    throw new Error('Отклонено по безопасности: обнаружен выход за пределы директории проекта.');
  }

  if (!targetStat || (!targetStat.isFile() && !targetStat.isDirectory())) {
    throw new Error('Отклонено по безопасности: целевой объект не является файлом или папкой.');
  }
  return realTarget;
}

function assertTrustedSender(event, getMainWindow) {
  const win = typeof getMainWindow === 'function' ? getMainWindow() : null;
  if (
    !win ||
    win.isDestroyed() ||
    !event ||
    !event.senderFrame ||
    event.sender !== win.webContents ||
    event.senderFrame !== win.webContents.mainFrame
  ) {
    throw new Error('Отклонено шлюзом IPC: недоверенный источник вызова.');
  }
  return win;
}

function registerIpcGateway({
  daemonBaseUrl,
  daemonToken,
  getMainWindow,
  selfRootPath = DEFAULT_SELF_ROOT,
  getInitialProjectDir = () => null,
}) {
  ipcMain.handle('lgraph-app:startup-context', async (event) => {
    assertTrustedSender(event, getMainWindow);
    return {
      selfRootPath,
      initialProjectDir: getInitialProjectDir(),
    };
  });

  ipcMain.handle('lgraph-api:request', async (event, payload) => {
    assertTrustedSender(event, getMainWindow);
    const rawPath = String((payload && payload.path) || '');
    const rawPathname = rawPath.split('?')[0];
    let decodedPathname = rawPathname;
    try {
      decodedPathname = decodeURIComponent(rawPathname);
    } catch (_err) {
      throw new Error('Отклонено шлюзом IPC: некорректное кодирование маршрута.');
    }

    const base = new URL(daemonBaseUrl);
    const parsed = new URL(rawPath, base);
    if (
      !rawPath.startsWith('/api/') ||
      rawPath.includes('..') ||
      decodedPathname.includes('..') ||
      rawPathname.includes('\\') ||
      rawPath.includes('\0') ||
      parsed.origin !== base.origin ||
      !parsed.pathname.startsWith('/api/')
    ) {
      throw new Error('Отклонено шлюзом IPC: разрешены только канонические маршруты /api/*.');
    }

    const method = String((payload && payload.method) || 'GET').toUpperCase();
    const headers = {
      'X-Lgraph-Token': daemonToken,
      Accept: 'application/json',
    };
    const fetchOpts = {
      method,
      headers,
      signal: AbortSignal.timeout(IPC_FETCH_TIMEOUT_MS),
    };
    if (payload && payload.body !== undefined && method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      fetchOpts.body = JSON.stringify(payload.body);
    }

    const res = await fetch(parsed.toString(), fetchOpts);
    const data = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
    if (!res.ok) {
      throw new Error(data.detail || `Ошибка демона Lgraph (${res.status})`);
    }
    return data;
  });

  ipcMain.handle('lgraph-dialog:pick-folder', async (event) => {
    const win = assertTrustedSender(event, getMainWindow);
    const result = await dialog.showOpenDialog(win, {
      title: 'Выберите корневую папку проекта для анализа в Lgraph',
      properties: ['openDirectory'],
    });
    if (result.canceled || !result.filePaths.length) {
      return null;
    }
    return result.filePaths[0];
  });

  ipcMain.handle('lgraph-editor:open-file', async (event, payload) => {
    assertTrustedSender(event, getMainWindow);
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
