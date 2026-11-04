'use strict';
// Generates build/icon.png (1024x1024) with no external deps.
// A rounded gradient tile with a white "network pulse" line — PacketPal's mark.
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const W = 1024, H = 1024;
const buf = Buffer.alloc(W * H * 4); // RGBA

function set(x, y, r, g, b, a) {
  if (x < 0 || y < 0 || x >= W || y >= H) return;
  const i = (y * W + x) * 4;
  // simple alpha-over compositing onto existing
  const ea = buf[i + 3] / 255, na = a / 255;
  const oa = na + ea * (1 - na);
  if (oa === 0) return;
  buf[i]     = Math.round((r * na + buf[i]     * ea * (1 - na)) / oa);
  buf[i + 1] = Math.round((g * na + buf[i + 1] * ea * (1 - na)) / oa);
  buf[i + 2] = Math.round((b * na + buf[i + 2] * ea * (1 - na)) / oa);
  buf[i + 3] = Math.round(oa * 255);
}

const c1 = [79, 140, 255];   // accent blue
const c2 = [165, 121, 255];  // violet
const lerp = (a, b, t) => Math.round(a + (b - a) * t);

// rounded-rect gradient background
const radius = 230;
function inRounded(x, y) {
  const rx = Math.min(x, W - 1 - x), ry = Math.min(y, H - 1 - y);
  if (rx >= radius || ry >= radius) return true;
  const dx = radius - rx, dy = radius - ry;
  return (dx * dx + dy * dy) <= radius * radius;
}
for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    if (!inRounded(x, y)) continue;
    const t = (x + y) / (W + H);
    set(x, y, lerp(c1[0], c2[0], t), lerp(c1[1], c2[1], t), lerp(c1[2], c2[2], t), 255);
  }
}

// network pulse polyline (heartbeat shape)
const pts = [
  [0.10, 0.55], [0.34, 0.55], [0.42, 0.70], [0.50, 0.28],
  [0.58, 0.62], [0.66, 0.55], [0.90, 0.55],
].map(([fx, fy]) => [fx * W, fy * H]);

const half = 20; // half stroke thickness
function dot(cx, cy, rad) {
  for (let y = -rad; y <= rad; y++)
    for (let x = -rad; x <= rad; x++)
      if (x * x + y * y <= rad * rad) set(Math.round(cx + x), Math.round(cy + y), 255, 255, 255, 255);
}
for (let s = 0; s < pts.length - 1; s++) {
  const [x0, y0] = pts[s], [x1, y1] = pts[s + 1];
  const steps = Math.ceil(Math.hypot(x1 - x0, y1 - y0));
  for (let k = 0; k <= steps; k++) {
    const x = x0 + (x1 - x0) * (k / steps);
    const y = y0 + (y1 - y0) * (k / steps);
    dot(x, y, half);
  }
}
// endpoint nodes
dot(pts[0][0], pts[0][1], 30);
dot(pts[pts.length - 1][0], pts[pts.length - 1][1], 30);

// ---- encode PNG ----
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, 'ascii');
  const body = Buffer.concat([t, data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body) >>> 0, 0);
  return Buffer.concat([len, body, crc]);
}
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(b) {
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

const raw = Buffer.alloc((W * 4 + 1) * H);
for (let y = 0; y < H; y++) {
  raw[y * (W * 4 + 1)] = 0; // filter: none
  buf.copy(raw, y * (W * 4 + 1) + 1, y * W * 4, (y + 1) * W * 4);
}
const idat = zlib.deflateSync(raw, { level: 9 });

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', idat),
  chunk('IEND', Buffer.alloc(0)),
]);

const out = path.join(__dirname, '..', 'build', 'icon.png');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, png);
console.log('wrote', out, png.length, 'bytes');
