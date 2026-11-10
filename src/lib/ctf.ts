import type { AnalysisResult } from './types';
import { decodeLatin1, formatBytes, sleep } from './utils';

/* ═══════════════════════════════════════════════════════════════
   Motor de resolución de retos de esteganografía (tipo CTF)
   ═══════════════════════════════════════════════════════════════ */

export const FLAG_RE = /\b([A-Za-z][A-Za-z0-9_]{2,32})\{([^}\r\n]{1,180})\}/g;
export const CHALLENGE_FLAG_RE = /^CIBERISTMO\{.+\}$/i;

const CODE_WORDS = /^(function|return|class|interface|const|object|array|string|number|switch|catch|import|export|require|define|typeof|printf|struct|while|except|lambda|foreach)$/i;
const KNOWN_PREFIX = /^(flag|ctf|ciberistmo|ciber|istmo|picoctf|htb|thm|rootme|crypto|secret|clave|bandera)$/i;

export const CHANNELS = {
  rgb: [0, 1, 2],
  bgr: [2, 1, 0],
  rgba: [0, 1, 2, 3],
  r: [0],
  g: [1],
  b: [2],
  a: [3],
  rg: [0, 1],
  gb: [1, 2],
  br: [2, 0],
} as const;
export type ChannelKey = keyof typeof CHANNELS;

export type Framing = 'raw' | 'u8' | 'u16be' | 'u16le' | 'u32be' | 'u32le';
export const FRAMING_LABEL: Record<string, string> = { raw: 'Texto directo', u8: 'Longitud uint8', u16be: 'Longitud uint16 BE', u16le: 'Longitud uint16 LE', u32be: 'Longitud uint32 BE', u32le: 'Longitud uint32 LE' };

export interface LsbOptions {
  channel: ChannelKey;
  bit: number;
  bitOrder: 'msb' | 'lsb';
  scan: 'xy' | 'yx';
  framing: Framing;
  stride?: number;
  start?: number;
}

export const DEFAULT_LSB: LsbOptions = { channel: 'rgb', bit: 0, bitOrder: 'msb', scan: 'xy', framing: 'raw' };

export interface Candidate {
  id: string;
  text: string;
  looseText: string;
  flags: string[];
  score: number;
  technique: string;
  detail: string;
  lsb?: Omit<LsbOptions, 'framing'> & { framing: string };
  sourceBytes?: Uint8Array;
}

export interface Recovery extends Candidate {
  confidence: number;
}

export interface Check {
  id: string;
  label: string;
  status: 'found' | 'clear' | 'skipped';
  note: string;
}

export interface LsbStream {
  label: string;
  bytes: Uint8Array;
  opts: LsbOptions;
}

export interface ChallengeResult {
  streams: LsbStream[];
  flags: string[];
  recoveries: Recovery[];
  candidates: Candidate[];
  checks: Check[];
  combos: number;
  image: ImageData | null;
  imageNote: string;
  elapsedMs: number;
  trailingBytes: Uint8Array | null;
  trailingOffset: number;
}

export type SolveProgress = (message: string, pct: number) => void;

export function findFlags(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(FLAG_RE)) {
    const prefix = m[1];
    const body = m[2];
    // Descarta ruido binario: los bytes no imprimibles se representan como ·
    if (/[\u0000-\u001f\u007f·\ufffd]/.test(body)) continue;
    if (CODE_WORDS.test(prefix)) continue;
    if (!KNOWN_PREFIX.test(prefix) && (!/^[A-Za-z][A-Za-z_]{3,}$/.test(prefix) || prefix.length < 4)) continue;
    if (body.length > 120 || !/^[A-Za-z0-9_+\-.!?@#$%&/=:;, ()"']+$/.test(body)) continue;
    out.add(m[0]);
  }
  return [...out];
}

const okChar = (c: number) => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127);

export function bytesToText(bytes: Uint8Array, loose = false): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (okChar(c)) s += String.fromCharCode(c);
    else if (loose) s += '·';
    else break;
  }
  return s;
}

export function scoreText(text: string, looseText = text): number {
  const flags = findFlags(looseText);
  let score = 0;
  let printable = 0;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) >= 32 && text.charCodeAt(i) < 127) printable++;
  score += printable * 1.2;
  if (flags.length) score += 800 + flags.reduce((a, f) => a + f.length * 4, 0);
  if (/CIBERISTMO|FLAG|CTF|bandera|flag|secreto|mensaje|piloto|vuelo|clave|password|pista|torre|404/i.test(looseText)) score += 90;
  if (/\s/.test(text)) score += 15;
  if (/[aeiouáéíóú]{2,}/i.test(text) || / the | de | la | el /i.test(text)) score += 12;
  if (printable < 5) score -= 120;
  // Penaliza ruido: demasiados símbolos raros, poca letra o caracteres repetidos
  const weird = (text.match(/[^A-Za-z0-9\s.,:;!?¿¡{}()_\-+@/\\=*"'#$%&áéíóúñÁÉÍÓÚÑ]/g) ?? []).length;
  score -= weird * 3;
  const alnum = (text.match(/[A-Za-z0-9]/g) ?? []).length;
  if (printable > 0 && alnum / printable < 0.6) score -= 220;
  if (/(.)\1{9,}/.test(text)) score -= 180;
  return score;
}

function rot13(s: string) {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function tryBase64(s: string): string | null {
  const t = s.replace(/\s+/g, '');
  if (t.length < 12 || t.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(t)) return null;
  try {
    const bin = atob(t);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0) & 0xff);
    if ((bytes.filter((b) => okChar(b)).length / bytes.length) < 0.85) return null;
    return bytesToText(bytes, true);
  } catch {
    return null;
  }
}

function tryHex(s: string): string | null {
  const t = s.replace(/[\s:,0x]/gi, '');
  if (t.length < 12 || t.length % 2 || !/^[0-9a-f]+$/i.test(t)) return null;
  const bytes = new Uint8Array(t.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(t.slice(i * 2, i * 2 + 2), 16);
  if ((bytes.filter((b) => okChar(b)).length / bytes.length) < 0.85) return null;
  return bytesToText(bytes, true);
}

export function xorBrute(bytes: Uint8Array, limit = 512): { key: number; text: string }[] {
  const out: { key: number; text: string; score: number }[] = [];
  const n = Math.min(bytes.length, limit);
  for (let k = 1; k < 256; k++) {
    const dec = new Uint8Array(n);
    for (let i = 0; i < n; i++) dec[i] = bytes[i] ^ k;
    const t = bytesToText(dec, true);
    const s = scoreText(bytesToText(dec), t);
    if (s > 60) out.push({ key: k, text: t.slice(0, 400), score: s });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 5);
}

/** Aplica transformaciones típicas de CTF a un texto candidato. */
export function transformCandidates(c: Candidate, out: Candidate[], depth = 0) {
  if (depth > 1) return;
  const transforms: [string, string | null][] = [
    ['base64', tryBase64(c.text)],
    ['hex', tryHex(c.text)],
    ['ROT13', rot13(c.text)],
    ['invertido', c.text.split('').reverse().join('')],
  ];
  for (const [name, t] of transforms) {
    if (!t || t === c.text || t.length < 5) continue;
    const flags = findFlags(t);
    if (!flags.length) continue; // solo interesan transformaciones que revelan una bandera
    const nc: Candidate = {
      ...c,
      id: `${c.id}-${name}`,
      text: t,
      looseText: t,
      flags,
      score: scoreText(t, t),
      technique: `${c.technique} → ${name}`,
      detail: `${c.detail} · decodificado como ${name}`,
    };
    out.push(nc);
    transformCandidates(nc, out, depth + 1);
  }
}

/** Extrae bits LSB (o de cualquier plano) de una imagen y los agrupa en bytes. */
export function decodeLsbBytes(img: ImageData, o: LsbOptions, maxBytes = 4096): Uint8Array {
  const { width: w, height: h, data } = img;
  const ch = CHANNELS[o.channel];
  const out = new Uint8Array(maxBytes);
  let outIdx = 0;
  let byte = 0;
  let bits = 0;
  let stop = false;
  const push = (v: number) => {
    const bit = (v >>> o.bit) & 1;
    if (o.bitOrder === 'msb') byte = (byte << 1) | bit;
    else byte |= bit << bits;
    bits++;
    if (bits === 8) {
      out[outIdx++] = byte & 0xff;
      byte = 0;
      bits = 0;
      if (outIdx >= maxBytes) stop = true;
    }
  };
  const stride = Math.max(1, o.stride ?? 1);
  const start = Math.max(0, o.start ?? 0);
  if (o.scan === 'xy') {
    for (let p = start; p < w * h && !stop; p += stride) {
      const i = p * 4;
      for (let c = 0; c < ch.length && !stop; c++) push(data[i + ch[c]]);
    }
  } else {
    for (let p = start; p < w * h && !stop; p += stride) {
      const i = ((p % w) * h + Math.floor(p / w)) * 4; // recorrido por columnas
      if (i + 3 >= data.length) break;
      for (let c = 0; c < ch.length && !stop; c++) push(data[i + ch[c]]);
    }
  }
  return out.subarray(0, outIdx).slice();
}

function framingVariants(bytes: Uint8Array): { key: Framing; framing: string; start: number; len: number }[] {
  const n = bytes.length;
  const u16be = n >= 2 ? (bytes[0] << 8) | bytes[1] : 0;
  const u16le = n >= 2 ? bytes[0] | (bytes[1] << 8) : 0;
  const u32be = n >= 4 ? (((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0) : 0;
  const u32le = n >= 4 ? ((bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0) : 0;
  const v: { key: Framing; framing: string; start: number; len: number }[] = [
    { key: 'raw', framing: 'texto directo', start: 0, len: Math.min(n, 600) },
    { key: 'u8', framing: 'u8 (longitud)', start: 1, len: bytes[0] },
    { key: 'u16be', framing: 'u16 BE', start: 2, len: u16be },
    { key: 'u16le', framing: 'u16 LE', start: 2, len: u16le },
    { key: 'u32be', framing: 'u32 BE', start: 4, len: u32be },
    { key: 'u32le', framing: 'u32 LE', start: 4, len: u32le },
  ];
  return v.filter((x) => x.start <= n && x.len > 0 && x.len < 100_000 && x.start + x.len <= n + 4096);
}

function makeCandidates(bytes: Uint8Array, technique: string, detail: string, lsb?: Omit<LsbOptions, 'framing'>): Candidate[] {
  const out: Candidate[] = [];
  const looseWhole = bytesToText(bytes, true).slice(0, 1200);
  const wholeFlags = findFlags(looseWhole);
  if (wholeFlags.length) {
    const idx = looseWhole.indexOf(wholeFlags[0]);
    const frag = looseWhole.slice(Math.max(0, idx - 80), idx + wholeFlags[0].length + 80);
    out.push({
      id: `${detail}-flag`,
      text: wholeFlags.join(' · '),
      looseText: frag,
      flags: wholeFlags,
      score: 900,
      technique,
      detail: `${detail} · bandera localizada en el flujo`,
      lsb: lsb ? { ...lsb, framing: 'raw' } : undefined,
      sourceBytes: bytes,
    });
  }
  for (const v of framingVariants(bytes)) {
    const slice = bytes.subarray(v.start, Math.min(bytes.length, v.start + Math.min(v.len, 600)));
    const text = bytesToText(slice);
    const loose = bytesToText(slice, true);
    if (text.length < 3) continue;
    const flags = findFlags(loose);
    const sc = scoreText(text, loose);
    if (sc < 35 && !flags.length) continue;
    out.push({
      id: `${detail}-${v.framing}`,
      text: text.slice(0, 600),
      looseText: loose.slice(0, 700),
      flags,
      score: sc,
      technique,
      detail: `${detail} · ${v.framing}`,
      lsb: lsb ? { ...lsb, framing: v.framing } : undefined,
      sourceBytes: slice,
    });
  }
  return out;
}

export async function loadImage(file: File): Promise<{ img: ImageData | null; note: string }> {
  let bmp: ImageBitmap;
  try {
    bmp = await createImageBitmap(file, { premultiplyAlpha: 'none', colorSpaceConversion: 'none' });
  } catch {
    try {
      bmp = await createImageBitmap(file);
    } catch {
      return { img: null, note: 'Este navegador no puede decodificar el archivo como imagen, así que no se puede analizar el plano de bits.' };
    }
  }
  const { width, height } = bmp;
  if (width * height > 16_000_000) {
    bmp.close();
    return { img: null, note: 'La imagen supera los 16 megapíxeles: se omitió el análisis LSB por rendimiento.' };
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true, colorSpace: 'srgb' });
  if (!ctx) {
    bmp.close();
    return { img: null, note: 'No se pudo leer la imagen.' };
  }
  ctx.drawImage(bmp, 0, 0);
  bmp.close();
  const img = ctx.getImageData(0, 0, width, height);
  return { img, note: `${width} × ${height} px` };
}

export async function solveChallenge(
  file: File,
  a: AnalysisResult,
  onProgress: SolveProgress = () => {},
): Promise<ChallengeResult> {
  const t0 = performance.now();
  const flags = new Set<string>();
  const candidates: Candidate[] = [];
  const checks: Check[] = [];
  let trailingBytes: Uint8Array | null = null;
  let trailingOffset = 0;
  let combos = 0;
  const streams: LsbStream[] = [];
  const raw = new Uint8Array(await file.arrayBuffer());

  /* ── 1. Fuentes de texto: cadenas, metadatos y bytes añadidos ── */
  onProgress('1/5 · Buscando la bandera en cadenas y metadatos…', 8);
  const addSource = (text: string, technique: string, detail: string) => {
    if (!text) return;
    const f = findFlags(text);
    if (!f.length) return;
    f.forEach((x) => flags.add(x));
    candidates.push({
      id: `src-${candidates.length}-${detail}`,
      text: f.join(' · '),
      looseText: text.slice(0, 700),
      flags: f,
      score: 950,
      technique,
      detail,
    });
  };
  for (const g of a.metadata) for (const e of g.entries) addSource(e.value, 'Metadatos ocultos', `${g.title} → ${e.key}`);
  for (const s of a.strings.interesting) addSource(s.value, 'Cadena de texto', `${s.type} @0x${Math.max(0, s.offset).toString(16).toUpperCase()}`);
  for (const s of a.strings.samples) addSource(s.text, 'Cadena de texto', `offset 0x${s.offset.toString(16).toUpperCase()}`);
  addSource(decodeLatin1(raw.subarray(0, Math.min(raw.length, 8_000_000))), 'Bytes del archivo', 'búsqueda directa en el archivo');
  const metaCount = candidates.filter((c) => c.technique === 'Metadatos ocultos').length;
  const strCount = candidates.filter((c) => c.technique === 'Cadena de texto').length;
  await sleep();

  /* ── 2. Datos añadidos tras el final lógico ── */
  onProgress('2/5 · Extrayendo datos añadidos al final del archivo…', 22);
  if (a.trailing) {
    trailingOffset = a.trailing.offset;
    trailingBytes = raw.subarray(trailingOffset).slice();
    const t = decodeLatin1(trailingBytes.subarray(0, 2_000_000));
    addSource(t, 'Datos añadidos al final', `0x${trailingOffset.toString(16).toUpperCase()} · ${formatBytes(trailingBytes.length)}`);
    const tb = makeCandidates(trailingBytes, 'Datos añadidos al final', `bytes desde 0x${trailingOffset.toString(16).toUpperCase()}`);
    candidates.push(...tb);
    for (const x of xorBrute(trailingBytes)) {
      const f = findFlags(x.text);
      if (f.length) {
        f.forEach((y) => flags.add(y));
        candidates.push({ id: `xor-${x.key}`, text: x.text, looseText: x.text, flags: f, score: 880, technique: 'XOR de 1 byte', detail: `clave 0x${x.key.toString(16).toUpperCase()}` });
      }
    }
  }
  checks.push({
    id: 'strings',
    label: 'Cadenas de texto, metadatos y bytes en claro',
    status: metaCount + strCount ? 'found' : 'clear',
    note: metaCount + strCount ? `${metaCount + strCount} coincidencia(s) con formato de bandera.` : 'No aparece ninguna bandera legible en el texto del archivo ni en sus metadatos.',
  });
  checks.push({
    id: 'trailing',
    label: 'Datos escondidos después del final de la imagen',
    status: trailingBytes ? (candidates.some((c) => c.technique === 'Datos añadidos al final') ? 'found' : 'clear') : 'clear',
    note: trailingBytes ? `Se extrajeron ${formatBytes(trailingBytes.length)} desde 0x${trailingOffset.toString(16).toUpperCase()}.` : 'No hay bytes añadidos tras el marcador de fin.',
  });
  checks.push({
    id: 'embedded',
    label: 'Otros archivos incrustados (polyglot)',
    status: a.embedded.length ? 'found' : 'clear',
    note: a.embedded.length ? `${a.embedded.length} firma(s): ${[...new Set(a.embedded.map((e) => e.name))].join(', ')}.` : 'No se detectaron archivos dentro del archivo.',
  });
  await sleep();

  /* ── 3. Fuerza bruta LSB ── */
  onProgress('3/5 · Probando combinaciones LSB (canales × planos × orden de bits)…', 40);
  const { img, note } = await loadImage(file);
  if (!img) {
    checks.push({ id: 'lsb', label: 'Esteganografía LSB', status: 'skipped', note });
  } else {
    const planes = [0, 1, 2, 3, 4, 5, 6, 7];
    const chans: ChannelKey[] = ['rgb', 'bgr', 'r', 'g', 'b', 'a', 'rgba', 'rg', 'gb', 'br'];
    const orders: ('msb' | 'lsb')[] = ['msb', 'lsb'];
    const scans: ('xy' | 'yx')[] = ['xy', 'yx'];
    let best = 0;
    let bestLabel = '';
    for (const bit of planes) {
      for (const channel of chans) {
        for (const bitOrder of orders) {
          for (const scan of scans) {
            const opts: LsbOptions = { channel, bit, bitOrder, scan, framing: 'raw' };
            const bytes = decodeLsbBytes(img, opts, 1024);
            combos++;
            const lsb = { channel, bit, bitOrder, scan, framing: 'raw' } as const;
            if (streams.length < 420) streams.push({ label: `LSB · ${channel.toUpperCase()} · plano ${bit} · ${bitOrder.toUpperCase()} · ${scan.toUpperCase()}`, bytes, opts });
            const label = `LSB · ${channel.toUpperCase()} · plano ${bit} · ${bitOrder.toUpperCase()} · ${scan.toUpperCase()}`;
            const cs = makeCandidates(bytes, 'Esteganografía LSB', label, lsb);
            for (const c of cs) {
              if (c.score > best) {
                best = c.score;
                bestLabel = label;
              }
              if (c.flags.length) c.flags.forEach((f) => flags.add(f));
              if (c.score > 45 || c.flags.length) candidates.push(c);
            }
            // XOR de un byte sobre el flujo LSB
            if (bit <= 1 && (channel === 'rgb' || channel === 'bgr' || channel === 'r')) {
              for (const x of xorBrute(bytes, 256)) {
                const f = findFlags(x.text);
                if (f.length) {
                  f.forEach((y) => flags.add(y));
                  candidates.push({ id: `lsb-xor-${combos}-${x.key}`, text: x.text, looseText: x.text, flags: f, score: 860, technique: 'LSB → XOR de 1 byte', detail: `${label} · clave 0x${x.key.toString(16).toUpperCase()}`, lsb });
                }
              }
            }
          }
        }
        await sleep(0);
      }
      onProgress(`3/5 · Plano de bit ${bit}/7 · ${combos} combinaciones probadas…`, 40 + bit * 5);
    }
    checks.push({
      id: 'lsb',
      label: `Esteganografía LSB (${combos} combinaciones)`,
      status: candidates.some((c) => c.technique.startsWith('Esteganografía LSB') && c.flags.length) ? 'found' : 'clear',
      note: candidates.some((c) => c.technique.startsWith('Esteganografía LSB') && c.flags.length)
        ? `Mensaje recuperado con ${bestLabel}.`
        : best > 0
          ? `Se decodificaron ${combos} flujos de bits; el más legible fue ${bestLabel} (puntuación ${Math.round(best)}), sin formato de bandera.`
          : 'Ningún flujo de bits produjo texto legible.',
    });
  }
  await sleep();

  /* ── 4. Transformaciones ── */
  onProgress('4/5 · Probando base64, hexadecimal, ROT13 y texto invertido…', 84);
  const transformed: Candidate[] = [];
  for (const c of [...candidates]) transformCandidates(c, transformed);
  let novelTransforms = 0;
  for (const c of transformed) {
    // Un ROT13 de una bandera ya conocida no es un hallazgo nuevo
    const novel = c.flags.filter((f) => !flags.has(f) && !flags.has(rot13(f)));
    if (c.flags.length && novel.length === 0) continue;
    novelTransforms += novel.length;
    novel.forEach((f) => flags.add(f));
    candidates.push({ ...c, flags: novel });
  }
  checks.push({
    id: 'transforms',
    label: 'Transformaciones (base64 / hex / ROT13 / invertido / XOR)',
    status: novelTransforms ? 'found' : 'clear',
    note: novelTransforms
      ? `${novelTransforms} bandera(s) nueva(s) aparecieron tras decodificar.`
      : 'Se probaron base64, hexadecimal, ROT13, inversión y XOR; no revelaron ninguna bandera nueva.',
  });
  await sleep();

  /* ── 5. Recopilación ── */
  onProgress('5/5 · Ordenando las pruebas y el mensaje recuperado…', 96);
  const seen = new Set<string>();
  const looksLikeMessage = (t: string) => (t.match(/[A-Za-z]/g) ?? []).length >= 8 && /[A-Za-z]{4}/.test(t) && !/(.)\1{9,}/.test(t);
  const recoveries: Recovery[] = candidates
    .filter((c) => c.flags.length || (c.score >= 170 && looksLikeMessage(c.text)))
    .sort((x, y) => (y.flags.length ? 10000 : 0) + y.score - ((x.flags.length ? 10000 : 0) + x.score))
    .filter((c) => {
      const k = c.flags.join('|') || c.text.slice(0, 80);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .slice(0, 40)
    .map((c) => ({ ...c, confidence: c.flags.length ? 99 : Math.min(95, Math.round(c.score / 4)) }));

  const orderedCandidates = candidates
    .sort((x, y) => y.score - x.score)
    .filter((c, i, arr) => arr.findIndex((z) => z.text.slice(0, 90) === c.text.slice(0, 90)) === i)
    .slice(0, 80);

  const allFlags = [...flags].sort((x, y) => (CHALLENGE_FLAG_RE.test(y) ? 1 : 0) - (CHALLENGE_FLAG_RE.test(x) ? 1 : 0));
  checks.forEach((c) => {
    if (c.status === 'clear' && allFlags.length && c.id === 'lsb') c.note += ' La bandera se encontró por otra vía.';
  });
  onProgress('Listo', 100);
  return {
    streams,
    flags: allFlags,
    recoveries,
    candidates: orderedCandidates,
    checks,
    combos,
    image: img,
    imageNote: note,
    elapsedMs: Math.round(performance.now() - t0),
    trailingBytes,
    trailingOffset,
  };
}

export function manualDecode(img: ImageData, o: LsbOptions, maxBytes = 512): { bytes: Uint8Array; text: string; flags: string[] } {
  const bytes = decodeLsbBytes(img, o, maxBytes);
  const v = framingVariants(bytes).find((x) => x.key === o.framing);
  const slice = v ? bytes.subarray(v.start, Math.min(bytes.length, v.start + Math.max(1, v.len))) : bytes;
  const text = bytesToText(slice, true);
  return { bytes: slice, text, flags: findFlags(text) };
}
