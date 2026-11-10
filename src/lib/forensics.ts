import SparkMD5 from 'spark-md5';
import type {
  EmbeddedHit,
  Hashes,
  InterestingString,
  Severity,
  StringSample,
  StringsResult,
  TrailingInfo,
  TypeInfo,
} from './types';
import { detectType } from './signatures';
import { gifEnd, parsePe, walkJpeg, walkPng, zipEnd } from './structure';
import { bytesToHexString, matchAt, u16le, u32le } from './utils';

/* ───────────── Hashes ───────────── */

const toHex = (buf: ArrayBuffer) =>
  Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

function sha256Js(data: Uint8Array): string {
  const primes: number[] = [];
  for (let c = 2; primes.length < 64; c++) {
    let p = true;
    for (const q of primes) {
      if (q * q > c) break;
      if (c % q === 0) {
        p = false;
        break;
      }
    }
    if (p) primes.push(c);
  }
  const frac = (x: number) => ((x - Math.floor(x)) * 4294967296) >>> 0;
  const K = primes.map((p) => frac(Math.cbrt(p)));
  const H = primes.slice(0, 8).map((p) => frac(Math.sqrt(p)));
  const l = data.length;
  const total = Math.ceil((l + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(data);
  buf[l] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(total - 8, Math.floor((l * 8) / 4294967296));
  view.setUint32(total - 4, (l * 8) >>> 0);
  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    const v = [a, b, c, d, e, f, g, h];
    for (let i = 0; i < 8; i++) H[i] = (H[i] + v[i]) >>> 0;
  }
  return H.map((x) => x.toString(16).padStart(8, '0')).join('');
}

export async function computeHashes(data: Uint8Array): Promise<Hashes> {
  const ab = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const md5 = SparkMD5.ArrayBuffer.hash(ab);
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return {
      md5,
      sha1: 'No disponible (requiere contexto seguro HTTPS)',
      sha256: sha256Js(data),
      sha512: 'No disponible (requiere contexto seguro HTTPS)',
    };
  }
  const [sha1, sha256, sha512] = await Promise.all([
    subtle.digest('SHA-1', ab),
    subtle.digest('SHA-256', ab),
    subtle.digest('SHA-512', ab),
  ]);
  return { md5, sha1: toHex(sha1), sha256: toHex(sha256), sha512: toHex(sha512) };
}

/* ───────────── Entropía ───────────── */

function shannon(hist: ArrayLike<number>, n: number): number {
  if (n === 0) return 0;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    const c = hist[i];
    if (c > 0) {
      const p = c / n;
      e -= p * Math.log2(p);
    }
  }
  return e;
}

export function entropyOf(b: Uint8Array, start = 0, end = b.length): number {
  const h = new Uint32Array(256);
  for (let i = start; i < end; i++) h[b[i]]++;
  return shannon(h, end - start);
}

export function computeEntropy(b: Uint8Array) {
  const n = b.length;
  const blockSize = Math.max(256, Math.ceil(n / 96));
  const global = new Float64Array(256);
  const hist = new Uint32Array(256);
  const blocks: number[] = [];
  for (let s = 0; s < n; s += blockSize) {
    const e = Math.min(n, s + blockSize);
    hist.fill(0);
    for (let i = s; i < e; i++) hist[b[i]]++;
    blocks.push(shannon(hist, e - s));
    for (let k = 0; k < 256; k++) global[k] += hist[k];
  }
  return { overall: shannon(global, n), blocks, blockSize };
}

/* ───────────── Contenido incrustado ───────────── */

const CAND = new Uint8Array(256);
[0x50, 0x25, 0x52, 0x37, 0x4d, 0x7f, 0x89, 0xff, 0x47, 0xd0, 0x1f].forEach((c) => (CAND[c] = 1));

export function findEmbedded(b: Uint8Array, host: TypeInfo | null): EmbeddedHit[] {
  const hits: EmbeddedHit[] = [];
  if (!host || ['archive', 'unknown', 'data'].includes(host.category)) return hits;
  const n = b.length;
  const isJpeg = host.name === 'JPEG';
  const isGif = host.name === 'GIF';
  const isPdf = host.name === 'PDF';
  const isOle = host.name.startsWith('Documento OLE2');
  const isExe = host.category === 'executable';
  const isMedia = host.category === 'audio' || host.category === 'video';
  let zipSeen = false;
  const add = (offset: number, name: string, severity: Severity, note: string) => {
    if (name === 'ZIP') {
      if (zipSeen) return; // las demás entradas locales pertenecen al mismo archivo
      zipSeen = true;
    }
    hits.push({ offset, name, severity, note });
  };
  for (let i = 1; i < n - 8 && hits.length < 40; i++) {
    const c = b[i];
    if (!CAND[c]) continue;
    switch (c) {
      case 0x50:
        if (!isExe && b[i + 1] === 0x4b && b[i + 2] === 0x03 && b[i + 3] === 0x04 && b[i + 5] === 0 && b[i + 4] >= 10 && b[i + 4] <= 63)
          add(i, 'ZIP', 'high', 'Archivo ZIP incrustado. Típico de polyglots y de datos ocultos anexados a otro archivo.');
        break;
      case 0x25:
        if (!isPdf && !isExe && matchAt(b, i, [0x25, 0x50, 0x44, 0x46, 0x2d, null, 0x2e]) && (b[i + 5] === 0x31 || b[i + 5] === 0x32))
          add(i, 'PDF', 'high', 'Documento PDF incrustado dentro de otro archivo.');
        break;
      case 0x52:
        if (matchAt(b, i, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) && !isExe)
          add(i, 'RAR', 'high', 'Archivo RAR incrustado.');
        break;
      case 0x37:
        if (matchAt(b, i, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) && !isExe)
          add(i, '7-Zip', 'high', 'Archivo 7-Zip incrustado.');
        break;
      case 0x4d:
        if (b[i + 1] === 0x5a && i + 0x40 < n) {
          const lfa = u32le(b, i + 0x3c);
          if (lfa >= 0x40 && lfa < 0x400 && i + lfa + 4 <= n && matchAt(b, i + lfa, [0x50, 0x45, 0, 0]))
            add(i, 'Ejecutable PE (Windows)', isExe ? 'medium' : 'critical', isExe ? 'Otro ejecutable PE dentro de un ejecutable (recurso o dropper).' : 'Ejecutable de Windows oculto dentro de un archivo que no es ejecutable.');
        }
        break;
      case 0x7f:
        if (matchAt(b, i, [0x7f, 0x45, 0x4c, 0x46]) && (b[i + 4] === 1 || b[i + 4] === 2) && (b[i + 5] === 1 || b[i + 5] === 2) && b[i + 6] === 1)
          add(i, 'Ejecutable ELF (Linux)', isExe ? 'medium' : 'critical', 'Binario ELF incrustado.');
        break;
      case 0x89:
        if (!isPdf && !isMedia && !isExe && !isOle && matchAt(b, i, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
          add(i, 'Imagen PNG', 'medium', 'Imagen PNG incrustada tras la cabecera del archivo principal.');
        break;
      case 0xff:
        if (!isJpeg && !isPdf && !isMedia && !isExe && !isOle && b[i + 1] === 0xd8 && b[i + 2] === 0xff && b[i + 3] >= 0xc0 && b[i + 3] < 0xff)
          add(i, 'Imagen JPEG', 'medium', 'Imagen JPEG incrustada en otro archivo.');
        break;
      case 0x47:
        if (!isGif && !isPdf && !isMedia && !isExe && !isOle && matchAt(b, i, [0x47, 0x49, 0x46, 0x38, null, 0x61]) && (b[i + 4] === 0x37 || b[i + 4] === 0x39))
          add(i, 'Imagen GIF', 'medium', 'Imagen GIF incrustada en otro archivo.');
        break;
      case 0xd0:
        if (!isOle && !isExe && matchAt(b, i, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))
          add(i, 'Documento OLE2', 'high', 'Contenedor OLE2 (Office clásico) incrustado.');
        break;
      case 0x1f:
        if (!isExe && b[i + 1] === 0x8b && b[i + 2] === 0x08 && b[i + 3] < 0x20 && (b[i + 8] === 0 || b[i + 8] === 2 || b[i + 8] === 4) && (b[i + 9] <= 13 || b[i + 9] === 255))
          add(i, 'GZIP', 'medium', 'Flujo GZIP incrustado.');
        break;
    }
  }
  return hits;
}

/* ───────────── Datos tras el final lógico ───────────── */

const PADDING = new Set([0x00, 0x0a, 0x0d, 0x20, 0x09]);

export function logicalEnd(b: Uint8Array, host: TypeInfo | null): { end: number; kind: string } | null {
  if (!host) return null;
  const n = b.length;
  switch (host.name) {
    case 'JPEG': {
      const { end } = walkJpeg(b);
      return end ? { end, kind: 'marcador EOI (FFD9)' } : null;
    }
    case 'PNG': {
      const { end } = walkPng(b);
      return end ? { end, kind: 'chunk IEND' } : null;
    }
    case 'GIF': {
      const end = gifEnd(b);
      return end ? { end, kind: 'terminador GIF (0x3B)' } : null;
    }
    case 'ZIP / OOXML / ODF':
    case 'ZIP (vacío)': {
      const end = zipEnd(b);
      return end ? { end, kind: 'directorio central ZIP (EOCD)' } : null;
    }
    case 'PDF': {
      for (let i = n - 5; i >= 0; i--) {
        if (b[i] === 0x25 && b[i + 1] === 0x25 && b[i + 2] === 0x45 && b[i + 3] === 0x4f && b[i + 4] === 0x46) {
          let end = i + 5;
          while (end < n && (b[end] === 0x0a || b[end] === 0x0d)) end++;
          return { end, kind: 'último %%EOF' };
        }
      }
      return null;
    }
    case 'BMP': {
      const declared = u32le(b, 2);
      return declared > 0 && declared <= n ? { end: declared, kind: 'tamaño declarado en cabecera BMP' } : null;
    }
    case 'WebP':
    case 'WAV':
    case 'AVI': {
      const declared = u32le(b, 4) + 8;
      return declared > 12 && declared <= n ? { end: declared + (declared % 2), kind: 'tamaño declarado RIFF' } : null;
    }
    case 'Ejecutable Windows (PE/MZ)': {
      const pe = parsePe(b);
      if (pe && pe.overlayStart > 0 && pe.overlayStart <= n) return { end: pe.overlayStart, kind: 'fin de la última sección PE' };
      return null;
    }
  }
  return null;
}

export function findTrailing(b: Uint8Array, host: TypeInfo | null): TrailingInfo | null {
  const le = logicalEnd(b, host);
  if (!le) return null;
  const { end, kind } = le;
  const size = b.length - end;
  if (size <= 0) return null;
  let allPad = true;
  for (let i = end; i < b.length; i++) {
    if (!PADDING.has(b[i])) {
      allPad = false;
      break;
    }
  }
  if (allPad && size <= 64) return null;
  const slice = b.subarray(end);
  const det = allPad ? null : detectType(slice.subarray(0, Math.min(slice.length, 8192)));
  const detected = det && det.category !== 'text' ? det.name : null;
  let note = `Hay ${size} bytes después del ${kind}. Los visores normales los ignoran, por eso es un lugar habitual para ocultar información.`;
  if (host?.name.startsWith('Ejecutable Windows')) {
    const certType = slice.length > 8 ? u16le(slice, 6) : 0;
    note =
      certType === 2
        ? `Overlay de ${size} bytes tras las secciones PE: probablemente la firma digital Authenticode (certificado).`
        : `Overlay de ${size} bytes tras las secciones PE. Habitual en instaladores y en droppers que esconden su carga útil.`;
  }
  return {
    offset: end,
    size,
    entropy: entropyOf(slice, 0, Math.min(slice.length, 4 * 1024 * 1024)),
    startsWith: bytesToHexString(slice, 12),
    detected,
    note,
  };
}

/* ───────────── Cadenas de texto ───────────── */

interface Detector {
  type: string;
  re: RegExp;
  group?: number;
  filter?: (v: string) => boolean;
  cap: number;
}

const DETECTORS: Detector[] = [
  { type: 'url', re: /\b(?:https?|ftp|wss?):\/\/[^\s"'<>)\]\\]{4,200}/gi, cap: 60 },
  { type: 'email', re: /\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.(?:[a-z]{2,24}|[A-Z]{2,24})/g, cap: 40 },
  {
    type: 'ip',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    filter: (v) => !/^(0\.|127\.|255\.|1\.0\.0\.|0\.0)/.test(v) && v.split('.').every((p) => p === '0' || !p.startsWith('0')),
    cap: 40,
  },
  { type: 'usuario', re: /[A-Za-z]:\\Users\\([^\\/:*?"<>|\r\n]{2,40})\\/gi, group: 1, filter: (v) => !/^(public|default|all users|default user|defaultuser0)$/i.test(v), cap: 15 },
  { type: 'usuario', re: /\/(?:home|Users)\/([A-Za-z0-9._-]{2,32})\//g, group: 1, filter: (v) => !/^(shared|guest|runner|user|root)$/i.test(v), cap: 15 },
  { type: 'ruta', re: /\b[A-Za-z]:\\(?:[\w .$@~()+&#,-]+\\)+[\w .$@~()+&#,-]*/g, filter: (v) => v.length >= 8, cap: 40 },
  { type: 'clave-privada', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, cap: 5 },
  { type: 'credencial', re: /\bAKIA[0-9A-Z]{16}\b/g, cap: 10 },
  { type: 'credencial', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, cap: 10 },
  { type: 'credencial', re: /\b(?:password|passwd|pwd|secret|api[_-]?key|token|contrase(?:ñ|n)a)\s*[=:]\s*["']?[^\s"']{4,}/gi, cap: 20 },
  {
    type: 'sospechoso',
    re: /\b(?:powershell(?:\.exe)?|cmd\.exe|wscript\.shell|mshta|regsvr32|rundll32|certutil|bitsadmin|VirtualAlloc(?:Ex)?|CreateRemoteThread|WriteProcessMemory|URLDownloadToFile|ShellExecute[AW]?|AutoOpen|Document_Open|Workbook_Open|WinExec|IsDebuggerPresent|keylog\w*|ransom\w*|mimikatz|meterpreter|Invoke-Expression|FromBase64String|-EncodedCommand|\/bin\/(?:ba)?sh|nc -e|eval\(|unescape\(|fromCharCode)/gi,
    cap: 40,
  },
];

export function scanText(text: string): InterestingString[] {
  const out: InterestingString[] = [];
  const seen = new Set<string>();
  for (const d of DETECTORS) {
    for (const m of text.matchAll(d.re)) {
      const v = (d.group ? m[d.group] : m[0]).trim();
      if (!v || (d.filter && !d.filter(v))) continue;
      const key = d.type + '|' + v.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ type: d.type, value: v.length > 240 ? v.slice(0, 240) + '…' : v, offset: -1 });
      if (out.length > 100) return out;
    }
  }
  return out;
}

export function extractStrings(b: Uint8Array): StringsResult {
  const MIN = 6;
  const n = b.length;
  const samples: StringSample[] = [];
  const interesting: InterestingString[] = [];
  const seen = new Set<string>();
  const perType: Record<string, number> = {};
  const dec = new TextDecoder('windows-1252');
  let total = 0;
  let budget = 150000;

  const scan = (text: string, offset: number) => {
    if (budget-- <= 0) return;
    for (const d of DETECTORS) {
      if ((perType[d.type] ?? 0) >= 150) continue;
      for (const m of text.matchAll(d.re)) {
        const v = (d.group ? m[d.group] : m[0]).trim();
        if (!v || (d.filter && !d.filter(v))) continue;
        const key = d.type + '|' + v.toLowerCase();
        if (seen.has(key)) continue;
        const count = interesting.filter((x) => x.type === d.type).length;
        if (count >= d.cap) break;
        seen.add(key);
        perType[d.type] = (perType[d.type] ?? 0) + 1;
        interesting.push({ type: d.type, value: v.length > 240 ? v.slice(0, 240) + '…' : v, offset });
      }
    }
  };

  const handle = (text: string, offset: number, wide: boolean) => {
    total++;
    if (samples.length < 2500) samples.push({ offset, text: text.length > 220 ? text.slice(0, 220) + '…' : text, wide });
    scan(text.length > 4000 ? text.slice(0, 4000) : text, offset);
  };

  let s = -1;
  for (let i = 0; i <= n; i++) {
    const c = i < n ? b[i] : 0;
    if ((c >= 0x20 && c < 0x7f) || c === 0x09) {
      if (s < 0) s = i;
    } else {
      if (s >= 0 && i - s >= MIN) handle(dec.decode(b.subarray(s, Math.min(i, s + 4000))), s, false);
      s = -1;
    }
  }
  // UTF-16LE
  let i = 0;
  while (i + 1 < n) {
    if (b[i] >= 0x20 && b[i] < 0x7f && b[i + 1] === 0) {
      let j = i;
      let txt = '';
      while (j + 1 < n && ((b[j] >= 0x20 && b[j] < 0x7f) || b[j] === 0x09) && b[j + 1] === 0 && txt.length < 4000) {
        txt += String.fromCharCode(b[j]);
        j += 2;
      }
      if (txt.length >= MIN) handle(txt, i, true);
      i = Math.max(j, i + 1);
    } else i++;
  }
  samples.sort((x, y) => x.offset - y.offset);
  return { total, samples, interesting };
}
