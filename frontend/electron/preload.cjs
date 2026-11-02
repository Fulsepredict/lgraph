/**
 * Изолированный мост предзагрузки Electron (preload.cjs).
 *
 * Почему токен демона (`X-Lgraph-Token`) никогда не передаётся сюда в браузерное окно:
 * Рендерер видит только безопасный метод `window.lgraphBridge.apiRequest(...)`,
 * а сам секретный заголовок подставляется внутри главного процесса (`ipcGateway.cjs`).
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('lgraphBridge', {
  apiRequest: (payload) => ipcRenderer.invoke('lgraph-api:request', payload),
  pickProjectFolder: () => ipcRenderer.invoke('lgraph-dialog:pick-folder'),
  openFileInEditor: (payload) => ipcRenderer.invoke('lgraph-editor:open-file', payload),
  getStartupContext: () => ipcRenderer.invoke('lgraph-app:startup-context'),
  onExternalOpenFolder: (callback) => {
    const listener = (_event, folderPath) => callback(folderPath);
    ipcRenderer.on('lgraph-app:open-folder', listener);
    return () => ipcRenderer.removeListener('lgraph-app:open-folder', listener);
  },
});
