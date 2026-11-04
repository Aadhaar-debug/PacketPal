'use strict';

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const {
  isInstalled, tsharkPath, listInterfaces, checkPermission, CaptureSession,
} = require('./capture');

let win = null;
let session = null;

// Batch packets and flush to the renderer on a timer so we never flood IPC.
let packetBatch = [];
let flushTimer = null;
const FLUSH_MS = 250;

function startFlusher() {
  if (flushTimer) return;
  flushTimer = setInterval(() => {
    if (packetBatch.length && win && !win.isDestroyed()) {
      win.webContents.send('capture:packets', packetBatch);
      packetBatch = [];
    }
  }, FLUSH_MS);
}

function stopFlusher() {
  if (flushTimer) { clearInterval(flushTimer); flushTimer = null; }
  packetBatch = [];
}

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: '#0f1420',
    titleBarStyle: 'hiddenInset',
    title: 'PacketPal',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.on('closed', () => { win = null; });
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (session) session.stop();
  stopFlusher();
  if (process.platform !== 'darwin') app.quit();
});

// ---- IPC ----

ipcMain.handle('app:status', async () => ({
  installed: isInstalled(),
  tsharkPath: tsharkPath(),
  platform: process.platform,
}));

ipcMain.handle('ifaces:list', async () => listInterfaces());

ipcMain.handle('perm:check', async (_e, iface) => checkPermission(iface));

// The exact, copy-pasteable command the user runs (with admin rights) to
// grant persistent capture permission via Wireshark's ChmodBPF helper.
ipcMain.handle('perm:fixCommand', async () => 'brew install --cask wireshark-chmodbpf');

ipcMain.handle('capture:start', async (_e, iface) => {
  if (session) session.stop();
  session = new CaptureSession(iface);
  startFlusher();

  session.on('packet', (p) => { packetBatch.push(p); });
  session.on('error', (msg) => {
    if (win && !win.isDestroyed()) win.webContents.send('capture:error', msg);
  });
  session.on('stop', () => {
    stopFlusher();
    if (win && !win.isDestroyed()) win.webContents.send('capture:stopped');
  });

  session.start();
  return { started: true, iface };
});

ipcMain.handle('capture:stop', async () => {
  if (session) session.stop();
  stopFlusher();
  return { stopped: true };
});

ipcMain.handle('open:external', async (_e, url) => {
  if (/^https?:\/\//.test(url)) shell.openExternal(url);
});
