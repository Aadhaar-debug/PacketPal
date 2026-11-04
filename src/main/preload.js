'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// A small, explicit bridge. The renderer can only do these things —
// no raw Node access, no arbitrary IPC.
contextBridge.exposeInMainWorld('PacketPal', {
  status: () => ipcRenderer.invoke('app:status'),
  listInterfaces: () => ipcRenderer.invoke('ifaces:list'),
  checkPermission: (iface) => ipcRenderer.invoke('perm:check', iface),
  permissionFixCommand: () => ipcRenderer.invoke('perm:fixCommand'),
  startCapture: (iface) => ipcRenderer.invoke('capture:start', iface),
  stopCapture: () => ipcRenderer.invoke('capture:stop'),
  openExternal: (url) => ipcRenderer.invoke('open:external', url),

  onPackets: (cb) => ipcRenderer.on('capture:packets', (_e, batch) => cb(batch)),
  onError: (cb) => ipcRenderer.on('capture:error', (_e, msg) => cb(msg)),
  onStopped: (cb) => ipcRenderer.on('capture:stopped', () => cb()),
});
