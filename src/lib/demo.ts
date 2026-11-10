import JSZip from 'jszip';
import { walkPng } from './structure';
import { crc32 } from './utils';

const enc = (s: string) => Uint8Array.from(Array.from(s).map((c) => c.charCodeAt(0) & 0xff));

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function chunk(type: string, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  out.set(enc(type), 4);
  out.set(data, 8);
  dv.setUint32(8 + data.length, crc32(out, 4, 8 + data.length));
  return out;
}

const text = (k: string, v: string) => chunk('tEXt', concat([enc(k), Uint8Array.of(0), enc(v)]));

/** TIFF/EXIF big-endian mínimo con Make, Model, Software y GPS (Madrid). */
export function buildExif(): Uint8Array {
  const buf = new Uint8Array(512);
  const dv = new DataView(buf.buffer);
  let p = 0;
  buf.set([0x4d, 0x4d, 0x00, 0x2a], 0);
  dv.setUint32(4, 8);
  p = 8;
  const ifd0Count = 4;
  const ifd0Size = 2 + ifd0Count * 12 + 4;
  let data = p + ifd0Size;
  const strs: [number, string][] = [
    [0x010f, 'Apple\0'],
    [0x0110, 'iPhone 14 Pro\0'],
    [0x0131, 'Adobe Photoshop 25.1 (Windows)\0'],
  ];
  const gpsIfdOffset = data + strs.reduce((a, [, s]) => a + s.length + (s.length % 2), 0);
  dv.setUint16(p, ifd0Count);
  let e = p + 2;
  for (const [tag, s] of strs) {
    dv.setUint16(e, tag);
    dv.setUint16(e + 2, 2);
    dv.setUint32(e + 4, s.length);
    dv.setUint32(e + 8, data);
    buf.set(enc(s), data);
    data += s.length + (s.length % 2);
    e += 12;
  }
  dv.setUint16(e, 0x8825);
  dv.setUint16(e + 2, 4);
  dv.setUint32(e + 4, 1);
  dv.setUint32(e + 8, gpsIfdOffset);
  e += 12;
  dv.setUint32(e, 0);
  // GPS IFD
  const g = gpsIfdOffset;
  const gpsCount = 4;
  const rat = g + 2 + gpsCount * 12 + 4;
  dv.setUint16(g, gpsCount);
  let ge = g + 2;
  const putAscii = (tag: number, ch: string) => {
    dv.setUint16(ge, tag);
    dv.setUint16(ge + 2, 2);
    dv.setUint32(ge + 4, 2);
    buf[ge + 8] = ch.charCodeAt(0);
    buf[ge + 9] = 0;
    ge += 12;
  };
  const putRat = (tag: number, off: number) => {
    dv.setUint16(ge, tag);
    dv.setUint16(ge + 2, 5);
    dv.setUint32(ge + 4, 3);
    dv.setUint32(ge + 8, off);
    ge += 12;
  };
  const writeRats = (off: number, v: [number, number][]) => v.forEach(([n, d], i) => {
    dv.setUint32(off + i * 8, n);
    dv.setUint32(off + i * 8 + 4, d);
  });
  putAscii(0x0001, 'N');
  putRat(0x0002, rat);
  putAscii(0x0003, 'W');
  putRat(0x0004, rat + 24);
  dv.setUint32(ge, 0);
  writeRats(rat, [[40, 1], [25, 1], [48, 100]]);
  writeRats(rat + 24, [[3, 1], [42, 1], [1368, 100]]);
  return buf.subarray(0, rat + 48);
}

export async function makeDemoFile(): Promise<File> {
  const canvas = document.createElement('canvas');
  canvas.width = 480;
  canvas.height = 300;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#5fb4e6';
  ctx.fillRect(0, 0, 480, 300);
  ctx.fillStyle = '#ffd34d';
  ctx.beginPath();
  ctx.arc(380, 70, 38, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = '#3f9a5a';
  ctx.beginPath();
  ctx.moveTo(0, 300);
  ctx.lineTo(0, 190);
  ctx.quadraticCurveTo(140, 120, 270, 200);
  ctx.quadraticCurveTo(380, 150, 480, 210);
  ctx.lineTo(480, 300);
  ctx.fill();
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 30px sans-serif';
  ctx.fillText('Vacaciones 2024', 24, 54);
  const blob: Blob = await new Promise((res) => canvas.toBlob((b) => res(b!), 'image/png'));
  const png = new Uint8Array(await blob.arrayBuffer());
  const { chunks } = walkPng(png);
  const iend = chunks.find((c) => c.type === 'IEND')!;

  const meta = concat([
    chunk('eXIf', buildExif()),
    chunk('tIME', Uint8Array.of(0x07, 0xe8, 7, 14, 18, 32, 5)),
    text('Author', 'María López Fernández'),
    text('Software', 'Adobe Photoshop 25.1'),
    text('Comment', 'Casa de Jorge - NO publicar. Wifi: casa_jorge_5G'),
    text('Source', 'C:\\Users\\maria.lopez\\Desktop\\privado\\IMG_4412.png'),
  ]);

  const zip = new JSZip();
  zip.file('claves_wifi.txt', 'Red: casa_jorge_5G\npassword: Verano2024!\nrouter admin: 192.168.1.1 / admin1234\n');
  zip.file('nota.txt', 'Contacto: maria.lopez@ejemplo.com');
  const zipBytes = await zip.generateAsync({ type: 'uint8array', compression: 'STORE' });

  const out = concat([png.subarray(0, iend.offset), meta, png.subarray(iend.offset, iend.offset + 12), zipBytes]);
  return new File([out as BlobPart], 'vacaciones.jpg', { type: 'image/jpeg', lastModified: Date.now() - 3 * 86400000 });
}

/* ═══════════ Reto 5: El secreto del vuelo 404 (demostración) ═══════════ */

export const DEMO_FLAG = 'CIBERISTMO{vuelo_404_lsb}';
export const DEMO_MESSAGE =
  'PILOTO 404 - TRANSMISION OCULTA: la torre nunca recibio la ultima senal. ' +
  'El mensaje viaja en los bits menos significativos del canal RGB. ' + DEMO_FLAG;

/** Dibuja una ilustración de avión y esconde un mensaje en el LSB de RGB (cabecera uint32 BE). */
export async function makeChallenge404(): Promise<File> {
  const W = 900;
  const H = 560;
  const canvas = document.createElement('canvas');
  canvas.width = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
  const sky = ctx.createLinearGradient(0, 0, 0, H);
  sky.addColorStop(0, '#5c9ed6');
  sky.addColorStop(1, '#b7d7e8');
  ctx.fillStyle = sky;
  ctx.fillRect(0, 0, W, H);

  ctx.fillStyle = '#ffe39b';
  ctx.beginPath();
  ctx.arc(680, 130, 58, 0, Math.PI * 2);
  ctx.fill();

  const poly = (pts: [number, number][], color: string) => {
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]);
    ctx.closePath();
    ctx.fill();
  };
  // alas y estabilizadores
  poly([[260, 475], [455, 355], [515, 355], [305, 475]], '#d8e7ee');
  poly([[525, 355], [750, 470], [700, 470], [470, 355]], '#d8e7ee');
  poly([[42, 275], [140, 355], [105, 355]], '#d8e7ee');
  poly([[355, 355], [455, 185], [490, 185], [515, 355]], '#dceaf0');
  // fuselaje
  ctx.fillStyle = '#eef4f7';
  ctx.fillRect(72, 355, 758, 42);
  // ventanillas
  ctx.fillStyle = '#1d5470';
  for (let x = 160; x <= 740; x += 65) {
    ctx.beginPath();
    ctx.ellipse(x, 376, 8, 5.5, 0, 0, Math.PI * 2);
    ctx.fill();
  }

  const img = ctx.getImageData(0, 0, W, H);
  const d = img.data;
  // grano fotográfico: hace que los LSB parezcan ruido natural
  let seed = 404404;
  const rnd = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed;
  };
  for (let i = 0; i < d.length; i += 4) {
    const n = (rnd() % 7) - 3;
    d[i] = Math.max(0, Math.min(255, d[i] + n));
    d[i + 1] = Math.max(0, Math.min(255, d[i + 1] + n));
    d[i + 2] = Math.max(0, Math.min(255, d[i + 2] + n));
    d[i + 3] = 255;
  }

  const msg = new TextEncoder().encode(DEMO_MESSAGE);
  const payload = new Uint8Array(4 + msg.length);
  new DataView(payload.buffer).setUint32(0, msg.length, false);
  payload.set(msg, 4);
  let bitIdx = 0;
  const totalBits = payload.length * 8;
  for (let p = 0; p < W * H && bitIdx < totalBits; p++) {
    const o = p * 4;
    for (let c = 0; c < 3 && bitIdx < totalBits; c++) {
      const bit = (payload[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1;
      d[o + c] = (d[o + c] & 0xfe) | bit;
      bitIdx++;
    }
  }
  ctx.putImageData(img, 0, 0);
  const blob: Blob = await new Promise((res) => canvas.toBlob((b) => res(b!), 'image/png'));
  const bytes = new Uint8Array(await blob.arrayBuffer());
  return new File([bytes as BlobPart], 'vuelo_404.png', {
    type: 'image/png',
    lastModified: Date.parse('2024-04-04T04:04:00Z'),
  });
}

/** Un ejecutable camuflado como PDF para comprobar la detección de archivos falsos. */
export function makeDisguisedFile(): File {
  const b = new Uint8Array(1024);
  b.set([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00], 0);
  const dv = new DataView(b.buffer);
  dv.setUint32(0x3c, 0x80, true);
  b.set([0x50, 0x45, 0x00, 0x00, 0x4c, 0x01, 0x02, 0x00], 0x80);
  b.set(new TextEncoder().encode('This program cannot be run in DOS mode. C:\\Users\\contabilidad\\facturas\\factura.pdb'), 0xa0);
  return new File([b as BlobPart], 'factura_enero.pdf', {
    type: 'application/pdf',
    lastModified: Date.now() - 86400000,
  });
}

/* ═══════════ Demo: cualquier palabra oculta en cualquier archivo ═══════════ */

export const DEMO_WORD = 'pulela';

/** Crea un .txt con la misma palabra escondida mediante 6 técnicas distintas. */
export function makeHiddenWordDemo(): File {
  const word = DEMO_WORD;
  const bits = [...new TextEncoder().encode(word)].map((b) => b.toString(2).padStart(8, '0')).join('');
  const zeroWidth = [...bits].map((b) => (b === '0' ? '\u200b' : '\u200c')).join('');
  const note = 'La palabra escondida del caso 404 es pulela. No la compartas con la torre.';
  const b64 = btoa(note);
  const hex = [...new TextEncoder().encode(note)].map((b) => b.toString(16).padStart(2, '0')).join(' ');
  const hexBlob = [...new TextEncoder().encode(note)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const rot13 = word.replace(/[a-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - 97 + 13) % 26) + 97));
  const reversed = word.split('').reverse().join('');
  const xored = Uint8Array.from(new TextEncoder().encode(word), (b) => b ^ 0x2a);
  const wsLines = bits.match(/.{1,8}/g)!.map((chunk) => 'Registro ' + [...chunk].map((b) => (b === '0' ? ' ' : '\t')).join(''));

  const lines = [
    'INFORME DE VUELO 404 — uso interno',
    'Estado: sin novedades aparentes.' + zeroWidth,
    'Adjunto codificado: ' + b64,
    'Suma de verificacion: ' + hex,
    'Bloque hex continuo: ' + hexBlob,
    'Nota del turno (rotada): ' + rot13,
    'Firma del piloto: ' + reversed,
    'Espacios finales de control:',
    ...wsLines,
    'Binario de sesion:',
  ];
  const prefix = new TextEncoder().encode(lines.join('\n') + '\n');
  const out = new Uint8Array(prefix.length + xored.length + 1);
  out.set(prefix);
  out.set(xored, prefix.length);
  out[out.length - 1] = 10;
  return new File([out as BlobPart], 'informe_vuelo.txt', {
    type: 'text/plain',
    lastModified: Date.now() - 2 * 86400000,
  });
}
