import { ascii, crc32, u16be, u16le, u32be, u32le } from './utils';

/* ───────────── JPEG ───────────── */

export interface JpegSeg {
  marker: number;
  name: string;
  offset: number;
  length: number;
  ident: string;
}

const JPEG_NAMES: Record<number, string> = {
  0xc0: 'SOF0 (baseline)',
  0xc1: 'SOF1',
  0xc2: 'SOF2 (progresivo)',
  0xc4: 'DHT (tablas Huffman)',
  0xdb: 'DQT (cuantización)',
  0xdd: 'DRI',
  0xda: 'SOS (datos de imagen)',
  0xfe: 'COM (comentario)',
  0xe0: 'APP0',
  0xe1: 'APP1',
  0xe2: 'APP2',
  0xe3: 'APP3',
  0xe4: 'APP4',
  0xe5: 'APP5',
  0xe6: 'APP6',
  0xe7: 'APP7',
  0xe8: 'APP8',
  0xe9: 'APP9',
  0xea: 'APP10',
  0xeb: 'APP11',
  0xec: 'APP12',
  0xed: 'APP13',
  0xee: 'APP14',
  0xef: 'APP15',
};

export function walkJpeg(b: Uint8Array): { segments: JpegSeg[]; end: number | null } {
  const segments: JpegSeg[] = [];
  const n = b.length;
  if (n < 4 || b[0] !== 0xff || b[1] !== 0xd8) return { segments, end: null };
  let i = 2;
  let end: number | null = null;
  while (i < n - 1 && segments.length < 600) {
    if (b[i] !== 0xff) {
      i++;
      continue;
    }
    const m = b[i + 1];
    if (m === 0xff) {
      i++;
      continue;
    }
    if (m === 0x00 || m === 0x01 || m === 0xd8 || (m >= 0xd0 && m <= 0xd7)) {
      i += 2;
      continue;
    }
    if (m === 0xd9) {
      end = i + 2;
      break;
    }
    if (i + 4 > n) break;
    const len = u16be(b, i + 2);
    let ident = '';
    if (m >= 0xe0 && m <= 0xef) {
      const raw = ascii(b, i + 4, 32);
      const z = raw.indexOf('\u0000');
      ident = (z >= 0 ? raw.slice(0, z) : raw).replace(/[^\x20-\x7e]/g, '');
    }
    segments.push({
      marker: m,
      name: JPEG_NAMES[m] ?? `0xFF${m.toString(16).toUpperCase()}`,
      offset: i,
      length: len + 2,
      ident,
    });
    i += 2 + len;
    if (m === 0xda) {
      while (i < n - 1) {
        if (b[i] === 0xff && b[i + 1] !== 0x00 && !(b[i + 1] >= 0xd0 && b[i + 1] <= 0xd7)) break;
        i++;
      }
    }
  }
  return { segments, end };
}

/* ───────────── PNG ───────────── */

export interface PngChunk {
  type: string;
  offset: number;
  length: number;
  crcOk: boolean | null;
}

export function walkPng(b: Uint8Array): { chunks: PngChunk[]; end: number | null; truncated: boolean } {
  const chunks: PngChunk[] = [];
  const n = b.length;
  let pos = 8;
  let end: number | null = null;
  let truncated = false;
  while (pos + 12 <= n && chunks.length < 5000) {
    const len = u32be(b, pos);
    const type = ascii(b, pos + 4, 4);
    const next = pos + 12 + len;
    if (next > n) {
      truncated = true;
      chunks.push({ type, offset: pos, length: len, crcOk: null });
      break;
    }
    let crcOk: boolean | null = null;
    if (len <= 32 * 1024 * 1024) {
      crcOk = crc32(b, pos + 4, pos + 8 + len) === u32be(b, pos + 8 + len);
    }
    chunks.push({ type, offset: pos, length: len, crcOk });
    pos = next;
    if (type === 'IEND') {
      end = next;
      break;
    }
  }
  return { chunks, end, truncated };
}

/* ───────────── GIF ───────────── */

export function gifEnd(b: Uint8Array): number | null {
  const n = b.length;
  if (n < 13) return null;
  let i = 13;
  if (b[10] & 0x80) i += 3 * (1 << ((b[10] & 7) + 1));
  const skipSub = () => {
    while (i < n) {
      const sz = b[i++];
      if (sz === 0) return;
      i += sz;
    }
  };
  let guard = 0;
  while (i < n && guard++ < 1_000_000) {
    const c = b[i++];
    if (c === 0x3b) return i;
    if (c === 0x21) {
      i++;
      skipSub();
    } else if (c === 0x2c) {
      if (i + 9 > n) return null;
      const flags = b[i + 8];
      i += 9;
      if (flags & 0x80) i += 3 * (1 << ((flags & 7) + 1));
      i++;
      skipSub();
    } else {
      return null;
    }
  }
  return null;
}

/* ───────────── ZIP ───────────── */

export function zipEnd(b: Uint8Array): number | null {
  const n = b.length;
  const min = Math.max(0, n - 22 - 65535);
  for (let i = n - 22; i >= min; i--) {
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) {
      const cl = u16le(b, i + 20);
      if (i + 22 + cl <= n) return i + 22 + cl;
    }
  }
  return null;
}

/* ───────────── PE ───────────── */

export interface PeInfo {
  offset: number;
  machine: string;
  timestamp: number;
  sections: { name: string; vsize: number; rawSize: number; rawPtr: number; entropy?: number }[];
  isDll: boolean;
  subsystem: number;
  overlayStart: number;
  isDotNet: boolean;
  entryPoint: number;
  imageBase: string;
  pe32plus: boolean;
}

const MACHINES: Record<number, string> = {
  0x14c: 'x86 (i386)',
  0x8664: 'x64 (AMD64)',
  0x1c0: 'ARM',
  0xaa64: 'ARM64',
  0x200: 'Itanium',
  0x1c4: 'ARMv7 Thumb-2',
};

export function parsePe(b: Uint8Array): PeInfo | null {
  if (b.length < 0x100 || b[0] !== 0x4d || b[1] !== 0x5a) return null;
  const lfa = u32le(b, 0x3c);
  if (lfa < 0x40 || lfa + 0x80 > b.length) return null;
  if (!(b[lfa] === 0x50 && b[lfa + 1] === 0x45 && b[lfa + 2] === 0 && b[lfa + 3] === 0)) return null;
  const machine = u16le(b, lfa + 4);
  const nsec = u16le(b, lfa + 6);
  const timestamp = u32le(b, lfa + 8);
  const optSize = u16le(b, lfa + 20);
  const chars = u16le(b, lfa + 22);
  const opt = lfa + 24;
  const magic = u16le(b, opt);
  const pe32plus = magic === 0x20b;
  const entryPoint = u32le(b, opt + 16);
  const imageBase = pe32plus
    ? '0x' + (u32le(b, opt + 28).toString(16) + u32le(b, opt + 24).toString(16).padStart(8, '0'))
    : '0x' + u32le(b, opt + 28).toString(16);
  const subsystem = u16le(b, opt + 68);
  const ddOff = opt + (pe32plus ? 112 : 96);
  const clrRva = ddOff + 14 * 8 < b.length ? u32le(b, ddOff + 14 * 8) : 0;
  const sections: PeInfo['sections'] = [];
  let overlayStart = 0;
  let sp = opt + optSize;
  for (let i = 0; i < Math.min(nsec, 96); i++, sp += 40) {
    if (sp + 40 > b.length) break;
    const name = ascii(b, sp, 8).replace(/\u0000+$/, '').replace(/[^\x20-\x7e]/g, '?');
    const vsize = u32le(b, sp + 8);
    const rawSize = u32le(b, sp + 16);
    const rawPtr = u32le(b, sp + 20);
    sections.push({ name, vsize, rawSize, rawPtr });
    overlayStart = Math.max(overlayStart, rawPtr + rawSize);
  }
  return {
    offset: lfa,
    machine: MACHINES[machine] ?? `0x${machine.toString(16)}`,
    timestamp,
    sections,
    isDll: (chars & 0x2000) !== 0,
    subsystem,
    overlayStart,
    isDotNet: clrRva !== 0,
    entryPoint,
    imageBase,
    pe32plus,
  };
}
