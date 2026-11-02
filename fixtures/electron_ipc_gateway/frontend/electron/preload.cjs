const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  apiRequest: (payload) => ipcRenderer.invoke('app-api:request', payload),
  openIsolatedWindow: (profileId) => ipcRenderer.invoke('window:open', profileId),
  runDynamicAction: (channelName, data) => ipcRenderer.invoke(channelName, data),
});
