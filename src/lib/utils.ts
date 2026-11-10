import type { Finding, Severity, Axis } from './types';

export const u16le = (b: Uint8Array, o: number) => (b[o] | (b[o + 1] << 8)) >>> 0;
export const u32le = (b: Uint8Array, o: number) =>
  (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
export const u16be = (b: Uint8Array, o: number) => ((b[o] << 8) | b[o + 1]) >>> 0;
export const u32be = (b: Uint8Array, o: number) =>
  ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

export function ascii(b: Uint8Array, start: number, len: number): string {
  let s = '';
  const end = Math.min(b.length, start + len);
  for (let i = start; i < end; i++) s += String.fromCharCode(b[i]);
  return s;
}

export function matchAt(b: Uint8Array, off: number, sig: (number | null)[]): boolean {
  if (off < 0 || off + sig.length > b.length) return false;
  for (let i = 0; i < sig.length; i++) {
    const s = sig[i];
    if (s !== null && b[off + i] !== s) return false;
  }
  return true;
}

export function indexOfBytes(b: Uint8Array, pat: number[], from = 0, to = b.length): number {
  const first = pat[0];
  let i = b.indexOf(first, from);
  while (i !== -1 && i + pat.length <= to) {
    let ok = true;
    for (let j = 1; j < pat.length; j++) {
      if (b[i + j] !== pat[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
    i = b.indexOf(first, i + 1);
  }
  return -1;
}

export const strBytes = (s: string) => Array.from(s).map((c) => c.charCodeAt(0));

export function decodeUtf8(b: Uint8Array, start = 0, end = b.length): string {
  return new TextDecoder('utf-8').decode(b.subarray(start, end));
}
export function decodeLatin1(b: Uint8Array, start = 0, end = b.length): string {
  return new TextDecoder('windows-1252').decode(b.subarray(start, end));
}
export function decodeUtf16(b: Uint8Array, start: number, end: number, le = true): string {
  try {
    return new TextDecoder(le ? 'utf-16le' : 'utf-16be').decode(b.subarray(start, end));
  } catch {
    return '';
  }
}

let crcTable: Uint32Array | null = null;
export function crc32(data: Uint8Array, start = 0, end = data.length, seed = 0xffffffff): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = seed;
  for (let i = start; i < end; i++) c = crcTable[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

export function formatDate(ms: number): string {
  if (!isFinite(ms)) return '—';
  return new Date(ms).toLocaleString('es-ES', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export const hex = (n: number, pad = 2) => n.toString(16).toUpperCase().padStart(pad, '0');

export function bytesToHexString(b: Uint8Array, max = 16): string {
  return Array.from(b.subarray(0, max))
    .map((x) => hex(x))
    .join(' ');
}

export function mk(
  id: string,
  axis: Axis,
  severity: Severity,
  title: string,
  detail: string,
  extra: Partial<Pick<Finding, 'offset' | 'recommendation'>> = {},
): Finding {
  return { id, axis, severity, title, detail, ...extra };
}

export const SENSITIVE_RE =
  /gps|latitude|longitude|location|serial|owner|artist|author|creator|last.?modified.?by|last.?author|company|manager|user.?name|^user|host.?name|^host|computer|machine|software|producer|^make$|^model$|camera|lens.?model|device|comment|description|copyright|^city$|e-?mail|phone|address|template|printer|initial-creator|built-by|created-by|generator|encoder|^application$|iso6709|xyz/i;

export const isSensitiveKey = (k: string) => SENSITIVE_RE.test(k);

export function stringify(v: unknown, max = 400): string {
  let s: string;
  if (v === null || v === undefined) s = '';
  else if (v instanceof Date) s = isNaN(v.getTime()) ? String(v) : v.toISOString();
  else if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
    s = `[binario · ${(v as Uint8Array).byteLength} bytes]`;
  } else if (Array.isArray(v)) {
    s = v.map((x) => stringify(x, max)).join(', ');
  } else if (typeof v === 'object') {
    try {
      s = JSON.stringify(v);
    } catch {
      s = String(v);
    }
  } else s = String(v);
  s = s.replace(/\u0000/g, '').trim();
  return s.length > max ? s.slice(0, max) + '…' : s;
}

export function getExt(name: string): string {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i + 1).toLowerCase() : '';
}

export const sleep = (ms = 0) => new Promise<void>((r) => setTimeout(r, ms));

export function download(name: string, data: Blob | string, mime = 'application/octet-stream') {
  const blob = typeof data === 'string' ? new Blob([data], { type: mime }) : data;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
