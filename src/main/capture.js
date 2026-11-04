'use strict';

const { spawn, execFile } = require('child_process');
const readline = require('readline');
const { EventEmitter } = require('events');
const { fieldArgs, parseLine } = require('./fields');

// Candidate locations for the Wireshark CLI tools.
const TSHARK_CANDIDATES = [
  '/opt/homebrew/bin/tshark',
  '/usr/local/bin/tshark',
  '/Applications/Wireshark.app/Contents/MacOS/tshark',
];
const DUMPCAP_CANDIDATES = [
  '/opt/homebrew/bin/dumpcap',
  '/usr/local/bin/dumpcap',
  '/Applications/Wireshark.app/Contents/MacOS/dumpcap',
];

const fs = require('fs');
function firstExisting(list) {
  for (const p of list) { try { if (fs.existsSync(p)) return p; } catch (_) {} }
  return null;
}

function tsharkPath() { return firstExisting(TSHARK_CANDIDATES); }
function dumpcapPath() { return firstExisting(DUMPCAP_CANDIDATES); }

// Is Wireshark installed at all?
function isInstalled() { return !!tsharkPath(); }

// List capture interfaces via `tshark -D`. Returns [{id, name, label}].
function listInterfaces() {
  return new Promise((resolve) => {
    const bin = tsharkPath();
    if (!bin) return resolve([]);
    execFile(bin, ['-D'], { timeout: 8000 }, (err, stdout) => {
      if (err || !stdout) return resolve([]);
      const out = [];
      for (const line of stdout.split('\n')) {
        // Format: "1. en0 (Wi-Fi)"
        const m = line.match(/^\s*(\d+)\.\s+(\S+)\s*(?:\(([^)]*)\))?/);
        if (m) {
          const name = m[2];
          const friendly = m[3] || '';
          out.push({ id: name, name, label: friendly ? `${name} — ${friendly}` : name });
        }
      }
      resolve(out);
    });
  });
}

// Can we actually capture? Try a 1-packet, 2s dumpcap on the interface.
// Returns { ok, reason }.
function checkPermission(iface) {
  return new Promise((resolve) => {
    const bin = dumpcapPath();
    if (!bin) return resolve({ ok: false, reason: 'not-installed' });
    const args = ['-i', iface || 'en0', '-c', '1', '-a', 'duration:2', '-w', '/dev/null'];
    execFile(bin, args, { timeout: 7000 }, (err, stdout, stderr) => {
      const text = `${stderr || ''}${stdout || ''}`.toLowerCase();
      if (!err) return resolve({ ok: true, reason: 'ok' });
      if (text.includes('permission') || text.includes('bpf') ||
          text.includes('operation not permitted') || text.includes('are you root')) {
        return resolve({ ok: false, reason: 'permission' });
      }
      // timeout with no packets but no perm error -> treat as ok (quiet link)
      if (err.killed) return resolve({ ok: true, reason: 'ok' });
      resolve({ ok: false, reason: 'unknown', detail: (stderr || '').trim().slice(0, 300) });
    });
  });
}

// A live capture session. Emits 'packet' (parsed object), 'error', 'stop'.
class CaptureSession extends EventEmitter {
  constructor(iface) {
    super();
    this.iface = iface;
    this.proc = null;
    this.running = false;
  }

  start() {
    if (this.running) return;
    const bin = tsharkPath();
    if (!bin) { this.emit('error', 'Wireshark/tshark is not installed.'); return; }

    const args = [
      '-i', this.iface,
      '-l',            // flush stdout after each packet (live)
      '-n',            // no name resolution (fast, no extra DNS)
      '-T', 'fields',
      '-E', 'separator=/t',
      '-E', 'occurrence=f',
      '-E', 'quote=n',
      ...fieldArgs(),
    ];

    this.proc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    this.running = true;

    const rl = readline.createInterface({ input: this.proc.stdout });
    rl.on('line', (line) => {
      if (!line) return;
      try { this.emit('packet', parseLine(line)); } catch (_) {}
    });

    let errBuf = '';
    this.proc.stderr.on('data', (d) => { errBuf += d.toString(); });

    this.proc.on('error', (e) => { this.emit('error', e.message); });
    this.proc.on('close', (code) => {
      this.running = false;
      if (code && code !== 0 && errBuf) {
        const low = errBuf.toLowerCase();
        if (low.includes('permission') || low.includes('bpf')) {
          this.emit('error', 'permission');
        } else {
          this.emit('error', errBuf.trim().slice(0, 400));
        }
      }
      this.emit('stop');
    });
  }

  stop() {
    if (this.proc && this.running) {
      try { this.proc.kill('SIGTERM'); } catch (_) {}
    }
    this.running = false;
  }
}

module.exports = {
  isInstalled, tsharkPath, dumpcapPath,
  listInterfaces, checkPermission, CaptureSession,
};
