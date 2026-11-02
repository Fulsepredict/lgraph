const { ipcMain } = require('electron');

function registerIpcHandlers() {
  ipcMain.handle('app-api:request', async (_event, payload) => {
    return { ok: true, forwarded: payload.path };
  });

  ipcMain.handle('window:open', async (_event, profileId) => {
    return { opened: profileId };
  });
}

module.exports = { registerIpcHandlers };
