import JSZip from 'jszip';
import type { AnalysisResult } from './types';
import {
  decodeLsbBytes, findFlags, type ChallengeResult, type ChannelKey, type LsbOptions,
} from './ctf';
import { decodeLatin1, decodeUtf16, decodeUtf8, formatBytes, sleep } from './utils';
import { inflateZlib } from './xml';

/* ═══════════════════════════════════════════════════════════════════════════
   Buscador universal de palabras / mensajes ocultos (cualquier archivo)
   ═══════════════════════════════════════════════════════════════════════════ */

export interface Stream {
  id: string;
  group: 'Archivo' | 'Contenedor' | 'Metadatos' | 'Texto invisible' | 'Imagen LSB' | 'Decodificación' | 'Transformación';
  label: string;
  detail: string;
  text: string;
  bytes?: Uint8Array;
  offset?: number;
  lsb?: LsbOptions;
  printable: number;
}

export interface Hit {
  id: string;
  word: string;
  context: string;
  variant: string;
  technique: string;
  detail: string;
  group: string;
  kind: 'keyword' | 'flag' | 'word';
  score: number;
  streamId: string;
  streamText: string;
  offset?: number;
  lsb?: LsbOptions;
}

export interface HiddenCheck {
  id: string;
  label: string;
  status: 'found' | 'clear' | 'skipped';
  note: string;
}

export interface HiddenScan {
  streams: Stream[];
  words: Hit[];
  flags: Hit[];
  checks: HiddenCheck[];
  stats: { streams: number; transforms: number; combos: number; bytes: number; elapsedMs: number; transformsProbed: number };
}

export type HiddenProgress = (message: string, pct: number) => void;

const MAX_TEXT = 4000;

/* ───────────── Normalización y variantes ───────────── */

/** Mantiene la longitud original: cada carácter se convierte en letra/dígito minúsculo o espacio. */
export function padded(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    out += c.length === 1 && /[a-z0-9]/.test(c) ? c : ' ';
  }
  return out;
}

export function compact(s: string): string {
  return padded(s).replace(/\s+/g, '');
}

const rotN = (s: string, n: number) =>
  s.replace(/[a-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - 97 + n) % 26) + 97));
const atbash = (s: string) => s.replace(/[a-z]/g, (c) => String.fromCharCode(122 - (c.charCodeAt(0) - 97)));
const leet = (s: string) => s.replace(/[o0]/g, '0').replace(/[il1]/g, '1').replace(/[e3]/g, '3').replace(/[a4]/g, '4').replace(/[s5]/g, '5').replace(/[t7]/g, '7');

export interface Variant {
  v: string;
  label: string;
}

export function keywordVariants(keyword: string): Variant[] {
  const base = compact(keyword);
  if (base.length < 2) return [];
  const map = new Map<string, string>();
  map.set(base, 'tal cual');
  map.set(base.split('').reverse().join(''), 'invertida');
  map.set(atbash(base), 'Atbash');
  map.set(leet(base), 'leet');
  for (let n = 1; n < 26; n++) map.set(rotN(base, n), `ROT${n}`);
  return [...map].filter(([v]) => v.length >= 2).map(([v, label]) => ({ v, label }));
}

export function looseText(bytes: Uint8Array, max = MAX_TEXT): string {
  const n = Math.min(bytes.length, max);
  let s = '';
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    s += c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160 ? String.fromCharCode(c) : ' ';
  }
  return s;
}

function printableRatio(bytes: Uint8Array): number {
  const n = Math.min(bytes.length, 512);
  if (!n) return 0;
  let p = 0;
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) p++;
  }
  return p / n;
}

/* ───────────── Vocabulario para puntuar palabras plausibles ───────────── */

const COMMON = new Set(
  (`de la el los las un una en y a que por para con se su del al como mas pero si no es son fue era este esta eso
    mensaje clave secreto bandera flag pista oculto escondido contrasena password usuario correo nombre pulela
    vuelo avion piloto torre control comunicacion investigacion archivo imagen foto datos texto codigo
    respuesta reto ciberistmo ctf forense esteganografia metadatos hidden secret word magic
    the and for you are with this that from have hidden message secret flag answer code file image data text
    password user email account key token note notes find found here there plane tower pilot plane
    hola mundo casa coche agua fuego cielo mar sol luna noche dia bueno malo grande pequeño
    informe documento foto camara equipo software autor empresa fecha ubicacion gps direccion
    primer ultimo siguiente anterior arriba abajo dentro fuera antes despues siempre nunca
    administrador sistema red servidor cliente error aviso alerta peligro seguro limpio
    rojo verde azul blanco negro amarillo naranja morado gris`).split(/\s+/).filter(Boolean),
);

const STOP = new Set(
  (`http https www com org net html xml xmlns xsi schema version encoding doctype meta head body div span class style script
    function return object string number null true false undefined length width height color type name value data
    adobe photoshop microsoft office windows apple iphone exif jpeg png jfif chunk ihdr idat iend the and for with
    stream endstream obj endobj xref startxref trailer filter flatedecode decode ascii utf utf8 base64 length
    create modify date time zone size offset index count title subject producer creator application content
    word excel powerpoint document workbook presentation package relationships rels core props custom
    from that this have been were are not you your uma para como pero este esta las los del una unos
    none null self item file path user temp tmp default value string array object attrs xmlns
    gzip deflate zlib inflate compress crc chunked tiff tif iptc xmp icc profile
    ffi ff d8 ff d9 ff e0 ff e1 ff c0 ff da`).split(/\s+/).filter(Boolean),
);

function plausibility(w: string): number {
  const l = w.toLowerCase();
  if (l.length < 4 || l.length > 24 || STOP.has(l)) return -1;
  if (!/^[a-záéíóúñü]+$/i.test(l)) return -1;
  const vowels = (l.match(/[aeiouáéíóúü]/gi) ?? []).length;
  const ratio = vowels / l.length;
  if (ratio < 0.18 || ratio > 0.78) return -1;
  if (/([^aeiouáéíóúü])\1{2,}/i.test(l) || /(.)\1{2,}/.test(l)) return -1;
  if (/[bcdfghjklmnpqrstvwxyz]{5,}/i.test(l)) return -1;
  let score = 25 + l.length * 2 + (ratio > 0.3 && ratio < 0.7 ? 20 : 5);
  if (COMMON.has(l)) score += 40;
  if (/[aeiou][bcdfghjklmnpqrstvwxyz][aeiou]/i.test(l)) score += 10;
  return score;
}

/* ───────────── Bits auxiliares (esteganografía de texto) ───────────── */

function bitsToBytes(bits: string): Uint8Array {
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}
const invertBits = (s: string) => s.replace(/[01]/g, (c) => (c === '0' ? '1' : '0'));

async function inflateAny(bytes: Uint8Array): Promise<Uint8Array | null> {
  const direct = await inflateZlib(bytes);
  if (direct) return direct;
  try {
    if (typeof DecompressionStream === 'undefined') return null;
    const ds = new DecompressionStream('gzip');
    const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

/* ───────────── Construcción de flujos ───────────── */

export async function buildStreams(
  file: File,
  a: AnalysisResult,
  challenge: ChallengeResult,
  onProgress: HiddenProgress = () => {},
): Promise<{ streams: Stream[]; checks: HiddenCheck[]; stats: HiddenScan['stats'] }> {
  const t0 = performance.now();
  const raw = new Uint8Array(await file.arrayBuffer());
  const streams: Stream[] = [];
  const checks: HiddenCheck[] = [];
  let transforms = 0;
  let combos = challenge.combos;
  const groupCount = new Map<string, number>();

  const add = (
    group: Stream['group'],
    label: string,
    detail: string,
    source: Uint8Array | string,
    extra: Partial<Stream> = {},
  ) => {
    const bytes = typeof source === 'string' ? new TextEncoder().encode(source) : source;
    if (!bytes.length) return;
    groupCount.set(group, (groupCount.get(group) ?? 0) + 1);
    streams.push({
      id: `s${streams.length}`,
      group,
      label,
      detail,
      text: typeof source === 'string' ? source.slice(0, MAX_TEXT) : looseText(bytes),
      bytes: bytes.length > 8192 ? bytes.subarray(0, 8192) : bytes,
      printable: printableRatio(bytes),
      ...extra,
    });
  };

  /* 1 · El archivo en todas sus codificaciones */
  onProgress('1/7 · Leyendo el archivo en ASCII, UTF-8, Latin-1 y UTF-16…', 5);
  add('Archivo', 'Bytes directos', 'vista byte a byte del archivo completo', raw);
  add('Archivo', 'UTF-8', new TextDecoder('utf-8').decode(raw.subarray(0, 8_000_000)), decodeUtf8(raw, 0, Math.min(raw.length, 8_000_000)));
  add('Archivo', 'Latin-1 / Windows-1252', 'texto de un byte por carácter', decodeLatin1(raw, 0, Math.min(raw.length, 8_000_000)));
  if (raw.length > 4 && raw.length < 24_000_000) {
    add('Archivo', 'UTF-16 LE', 'reinterpretación de los bytes como UTF-16 little-endian', decodeUtf16(raw, 0, Math.min(raw.length, 8_000_000), true));
    add('Archivo', 'UTF-16 BE', 'reinterpretación de los bytes como UTF-16 big-endian', decodeUtf16(raw, 0, Math.min(raw.length, 8_000_000), false));
  }
  await sleep(0);

  /* 2 · Metadatos y cadenas ya extraídas */
  onProgress('2/7 · Incorporando metadatos y cadenas de texto…', 14);
  for (const g of a.metadata.slice(0, 80)) {
    const text = g.entries.map((e) => `${e.key}: ${e.value}`).join('\n');
    add('Metadatos', g.title, `${g.entries.length} campos`, text);
  }
  const intText = a.strings.interesting.map((s) => `${s.type}: ${s.value}`).join('\n');
  if (intText) add('Archivo', 'Indicadores de texto', 'URLs, correos, rutas, credenciales…', intText);
  const samples = a.strings.samples.slice(0, 900).map((s) => `${s.offset.toString(16).toUpperCase()} ${s.text}`).join('\n');
  if (samples) add('Archivo', 'Cadenas ASCII y UTF-16', `${Math.min(900, a.strings.samples.length)} cadenas legibles`, samples);
  if (a.trailing) {
    const t = raw.subarray(a.trailing.offset);
    add('Archivo', 'Datos tras el final lógico', `0x${a.trailing.offset.toString(16).toUpperCase()} · ${formatBytes(t.length)}`, t, { offset: a.trailing.offset });
  }
  for (const e of a.embedded.slice(0, 10)) {
    add('Archivo', `Incrustado: ${e.name}`, `desde 0x${e.offset.toString(16).toUpperCase()}`, raw.subarray(e.offset, e.offset + 16384), { offset: e.offset });
  }
  await sleep(0);

  /* 3 · Contenedores: ZIP/OOXML/ODF/JAR y flujos PDF */
  onProgress('3/7 · Abriendo contenedores comprimidos y flujos internos…', 27);
  let zipEntries = 0;
  if (raw[0] === 0x50 && raw[1] === 0x4b) {
    try {
      const zip = await JSZip.loadAsync(raw);
      const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
      for (const n of names.slice(0, 90)) {
        const f = zip.file(n);
        if (!f) continue;
        const size = (f as unknown as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0;
        if (size > 6_000_000) continue;
        try {
          const u = await f.async('uint8array');
          add('Contenedor', `Entrada: ${n}`, `${formatBytes(u.length)} dentro del paquete`, u);
          zipEntries++;
        } catch {
          /* entry ilegible */
        }
      }
    } catch {
      /* no es un ZIP válido */
    }
  }
  checks.push({
    id: 'containers',
    label: 'Contenedores ZIP / DOCX / XLSX / PPTX / ODF / JAR / APK',
    status: zipEntries ? 'found' : 'clear',
    note: zipEntries ? `${zipEntries} archivo(s) interno(s) descomprimido(s) y analizados por separado.` : 'El archivo no es un contenedor ZIP legible.',
  });

  let pdfStreams = 0;
  if (raw[0] === 0x25 && raw[1] === 0x50 && raw[2] === 0x44 && raw[3] === 0x46) {
    const txt = decodeLatin1(raw);
    const re = /stream\r?\n/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(txt)) && pdfStreams < 40) {
      const s = m.index + m[0].length;
      const e = txt.indexOf('endstream', s);
      if (e < 0 || e - s < 4) break;
      const chunk = raw.subarray(s, Math.min(e, raw.length));
      const inflated = await inflateAny(chunk);
      const out = inflated ?? chunk;
      add('Contenedor', `Flujo PDF ${pdfStreams + 1}`, `0x${s.toString(16).toUpperCase()} · ${inflated ? 'FlateDecode' : 'sin comprimir'} · ${formatBytes(out.length)}`, out, { offset: s });
      pdfStreams++;
      re.lastIndex = e + 9;
    }
  }
  checks.push({
    id: 'pdf',
    label: 'Flujos internos de PDF (FlateDecode)',
    status: pdfStreams ? 'found' : 'clear',
    note: pdfStreams ? `${pdfStreams} flujo(s) PDF descomprimido(s) y analizado(s).` : 'No hay flujos PDF que descomprimir.',
  });

  // Compresión general (gzip / zlib / deflate)
  if (raw.length < 40_000_000 && (raw[0] === 0x1f || raw[0] === 0x78 || raw[0] === 0x1a)) {
    const inf = await inflateAny(raw.subarray(0, Math.min(raw.length, 20_000_000)));
    if (inf && inf.length > 8) {
      add('Decodificación', 'Archivo descomprimido', `gzip/zlib → ${formatBytes(inf.length)}`, inf);
      transforms++;
    }
  }
  await sleep(0);

  /* 4 · Bloques codificados incrustados en el texto (base64, hex, URL, entidades) */
  onProgress('4/7 · Decodificando bloques base64, hexadecimales y URL…', 41);
  const plain = decodeLatin1(raw.subarray(0, Math.min(raw.length, 6_000_000)));
  let blobs = 0;
  for (const m of plain.matchAll(/(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{8,}={0,2})/g)) {
    if (blobs >= 40) break;
    const s = m[1];
    if (s.length % 4 !== 0) continue;
    try {
      const bin = atob(s);
      const b = Uint8Array.from(bin, (c) => c.charCodeAt(0) & 0xff);
      if (printableRatio(b) < 0.35 && blobs > 8) continue;
      add('Decodificación', 'Bloque base64', s.slice(0, 48) + '…', b);
      blobs++;
      transforms++;
    } catch {
      /* noop */
    }
  }
  for (const m of plain.matchAll(/(?:^|[^0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){12,})/g)) {
    if (blobs >= 60) break;
    const h = m[1];
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    add('Decodificación', 'Bloque hexadecimal', h.slice(0, 48) + '…', b);
    blobs++;
    transforms++;
  }
  const urlParts = [...plain.matchAll(/%[0-9A-Fa-f]{2}/g)];
  if (urlParts.length >= 4) {
    try {
      add('Decodificación', 'Texto con %URL', 'secuencias %xx decodificadas', decodeURIComponent(plain.slice(0, 100_000)));
      transforms++;
    } catch {
      /* noop */
    }
  }
  const entities = [...plain.matchAll(/&#(?:x[0-9A-Fa-f]+|\d+);/g)];
  if (entities.length >= 3) {
    const decoded = plain.slice(0, 100_000).replace(/&#x([0-9A-Fa-f]+);/g, (_, x) => String.fromCharCode(parseInt(x, 16))).replace(/&#(\d+);/g, (_, x) => String.fromCharCode(+x));
    add('Decodificación', 'Entidades numéricas', `${entities.length} entidades HTML`, decoded);
    transforms++;
  }
  checks.push({
    id: 'blobs',
    label: 'Bloques codificados (base64 / hex / %URL / entidades HTML)',
    status: blobs ? 'found' : 'clear',
    note: blobs ? `${blobs} bloque(s) decodificado(s) y añadido(s) a la búsqueda.` : 'No se encontraron bloques codificados extensos.',
  });
  await sleep(0);

  /* 5 · Esteganografía de texto: ancho cero, espacios, mayúsculas, acrosticos */
  onProgress('5/7 · Extrayendo texto invisible (ancho cero, espacios, mayúsculas, acrosticos)…', 55);
  const wholeText = decodeUtf8(raw);
  const zw = [...wholeText].filter((c) => '\u200b\u200c\u200d\u2060\ufeff\u180e'.includes(c)).join('');
  if (zw.length >= 16) {
    const a1 = zw.replace(/[\u200b\ufeff\u180e]/g, '0').replace(/[\u200c\u200d\u2060]/g, '1');
    for (const [i, bits] of [a1, invertBits(a1)].entries()) {
      const bytes = bitsToBytes(bits.replace(/[^01]/g, ''));
      add('Texto invisible', 'Caracteres de ancho cero', `${zw.length} caracteres invisibles · polaridad ${i}`, bytes);
    }
    transforms += 2;
  }
  const lines = wholeText.split(/\r?\n/);
  const wsBits = lines.map((l) => (l.match(/[ \t]+$/) ?? [''])[0]).join('').replace(/ /g, '0').replace(/\t/g, '1');
  if (wsBits.length >= 16) {
    for (const [i, bits] of [wsBits, invertBits(wsBits)].entries()) {
      add('Texto invisible', 'Espacios y tabuladores finales', `${wsBits.length} bits · polaridad ${i}`, bitsToBytes(bits));
    }
    transforms += 2;
  }
  const letters = wholeText.replace(/[^A-Za-zÁÉÍÓÚÑÜáéíóúñü]/g, '');
  if (letters.length >= 16) {
    const bits = [...letters].map((c) => (c === c.toUpperCase() ? '1' : '0')).join('');
    for (const [i, b] of [bits, invertBits(bits)].entries()) {
      add('Texto invisible', 'Mayúsculas / minúsculas como bits', `${letters.length} letras · polaridad ${i}`, bitsToBytes(b));
    }
    transforms += 2;
  }
  if (lines.length >= 6) {
    const acrostic = lines.map((l) => (l.match(/[A-Za-zÁÉÍÓÚÑÜ]/) ?? [''])[0]).join('');
    if (acrostic.length >= 5) {
      add('Texto invisible', 'Acrostico (primera letra de cada línea)', `${lines.length} líneas`, acrostic);
      transforms++;
    }
  }
  for (let n = 2; n <= 12; n++) {
    let s = '';
    for (let i = 0; i < wholeText.length && s.length < MAX_TEXT; i += n) s += wholeText[i];
    if (s.replace(/\s/g, '').length >= 8) {
      add('Texto invisible', `Cada ${n}º carácter`, 'mensaje intercalado en el texto', s);
      transforms++;
    }
  }
  const comments = [...wholeText.matchAll(/<!--([\s\S]*?)-->|\/\*([\s\S]*?)\*\/|^[#;]\s?(.+)$/gm)].map((m) => (m[1] ?? m[2] ?? m[3] ?? '').trim()).filter(Boolean);
  if (comments.length) {
    add('Texto invisible', 'Comentarios del código / HTML', `${comments.length} comentario(s)`, comments.join('\n'));
    transforms++;
  }
  checks.push({
    id: 'invisible',
    label: 'Esteganografía de texto (ancho cero / espacios / mayúsculas / acrosticos / cada N)',
    status: wholeText.includes('\u200b') || wsBits.length >= 16 ? 'found' : 'clear',
    note: `${groupCount.get('Texto invisible') ?? 0} flujo(s) alternativo(s) generado(s) a partir del texto.`,
  });
  await sleep(0);

  /* 6 · Flujos LSB (los del barrido forense + muestreos con salto) */
  onProgress('6/7 · Añadiendo los planos de bits de la imagen y sus variantes…', 68);
  for (const st of challenge.streams.slice(0, 420)) {
    add('Imagen LSB', st.label, 'flujo de bits reconstruido', st.bytes, { lsb: st.opts });
  }
  if (challenge.image) {
    const chans: ChannelKey[] = ['rgb', 'bgr', 'r', 'g', 'b'];
    for (const channel of chans) {
      for (const stride of [2, 3, 4, 8]) {
        for (const start of [0, 1]) {
          for (const bitOrder of ['msb', 'lsb'] as const) {
            const opts: LsbOptions = { channel, bit: 0, bitOrder, scan: 'xy', framing: 'raw', stride, start };
            const bytes = decodeLsbBytes(challenge.image, opts, 512);
            combos++;
            add('Imagen LSB', `LSB con salto ${stride}`, `${channel.toUpperCase()} · plano 0 · ${bitOrder.toUpperCase()} · inicio ${start}`, bytes, { lsb: opts });
          }
        }
      }
    }
  }
  checks.push({
    id: 'lsb',
    label: `Planos de bits de imagen (${challenge.combos} + muestreos con salto)`,
    status: challenge.image ? (groupCount.get('Imagen LSB') ? 'found' : 'clear') : 'skipped',
    note: challenge.image
      ? `${groupCount.get('Imagen LSB') ?? 0} flujo(s) de píxeles disponibles para buscar palabras.`
      : 'El archivo no es una imagen decodificable; se analizan el resto de fuentes.',
  });
  await sleep(0);

  /* 7 · Transformaciones sobre los flujos más prometedores */
  onProgress('7/7 · Generando ROT-N, XOR, Atbash, inversión y rotaciones de bits…', 84);
  const priority: Record<Stream['group'], number> = {
    Archivo: 3, Metadatos: 2, Contenedor: 4, 'Texto invisible': 6, 'Imagen LSB': 5, Decodificación: 6, Transformación: 1,
  };
  const base = [...streams]
    .filter((s) => s.bytes && s.bytes.length >= 16)
    .sort((x, y) => (priority[y.group] + y.printable * 3) - (priority[x.group] + x.printable * 3))
    .slice(0, 34);
  for (const s of base) {
    const b = s.bytes!.subarray(0, 1024);
    const txt = looseText(b, 1024);
    // ROT-N y Atbash sobre el texto legible
    for (let n = 1; n < 26; n++) {
      add('Transformación', `ROT${n}`, s.label, rotN(txt, n));
      transforms++;
    }
    add('Transformación', 'Atbash', s.label, atbash(txt));
    add('Transformación', 'Texto invertido', s.label, txt.split('').reverse().join(''));
    transforms += 2;
    // Rotaciones de bits, inversión de bits e intercambio de nibbles
    for (const rot of [1, 2, 3, 4, 5, 6, 7]) {
      const rb = Uint8Array.from(b, (v) => ((v << rot) | (v >>> (8 - rot))) & 0xff);
      add('Transformación', `Rotar bits ${rot}`, s.label, rb);
      transforms++;
    }
    const rev = Uint8Array.from(b, (v) => {
      let x = 0;
      for (let i = 0; i < 8; i++) x = (x << 1) | ((v >>> i) & 1);
      return x;
    });
    add('Transformación', 'Invertir orden de bits', s.label, rev);
    add('Transformación', 'Intercambiar nibbles', s.label, Uint8Array.from(b, (v) => ((v << 4) | (v >>> 4)) & 0xff));
    transforms += 2;
    // XOR de un byte: solo se guardan los resultados con texto muy legible
    let kept = 0;
    for (let k = 1; k < 256 && kept < 2; k++) {
      const x = Uint8Array.from(b, (v) => v ^ k);
      if (printableRatio(x) < 0.94) continue;
      const t = looseText(x, 512);
      if ((t.match(/[A-Za-z]{3}/g) ?? []).length < 3) continue;
      add('Transformación', `XOR 0x${k.toString(16).toUpperCase().padStart(2, '0')}`, s.label, x);
      kept++;
      transforms++;
    }
    // Cada N bytes
    for (const stride of [2, 3, 4, 8]) {
      const sub = new Uint8Array(Math.ceil(b.length / stride));
      let j = 0;
      for (let i = 0; i < b.length; i += stride) sub[j++] = b[i];
      add('Transformación', `Cada ${stride}º byte`, s.label, sub.subarray(0, j));
      transforms++;
    }
  }
  checks.push({
    id: 'transforms',
    label: 'ROT-1…25, Atbash, inversión, XOR, rotación de bits y muestreo de bytes',
    status: transforms ? 'found' : 'clear',
    note: `${transforms} flujo(s) transformado(s) añadidos. La búsqueda por palabra además prueba los 255 XOR y los 25 ROT en vivo.`,
  });

  const ordered = streams
    .sort((x, y) => priority[y.group] + y.printable * 2 - (priority[x.group] + x.printable * 2))
    .slice(0, 1100);
  onProgress('Listo', 100);
  return {
    streams: ordered,
    checks,
    stats: {
      streams: ordered.length,
      transforms,
      combos,
      bytes: raw.length,
      elapsedMs: Math.round(performance.now() - t0),
      transformsProbed: 255 * 34 + 25 * 34,
    },
  };
}

/* ───────────── Búsqueda de una palabra concreta ───────────── */

const transformCache = new WeakMap<Stream, { label: string; text: string }[]>();

function virtualTransformTexts(s: Stream): { label: string; text: string }[] {
  if (!s.bytes) return [];
  const cached = transformCache.get(s);
  if (cached) return cached;
  const out: { label: string; text: string }[] = [];
  const b = s.bytes.subarray(0, 384);
  const txt = looseText(b, 384);
  for (const k of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]) {
    out.push({ label: `ROT${k} en vivo`, text: rotN(txt, k) });
  }
  out.push({ label: 'Atbash en vivo', text: atbash(txt) });
  out.push({ label: 'Invertido en vivo', text: txt.split('').reverse().join('') });
  for (let k = 1; k < 256; k++) {
    let t = '';
    for (let i = 0; i < b.length; i++) {
      const c = b[i] ^ k;
      t += c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160 ? String.fromCharCode(c) : ' ';
    }
    out.push({ label: `XOR 0x${k.toString(16).toUpperCase().padStart(2, '0')} en vivo`, text: t });
  }
  for (const add of [1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 224, 240, 248, 252, 254, 255]) {
    let t = '';
    for (let i = 0; i < b.length; i++) {
      const c = (b[i] + add) & 0xff;
      t += c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160 ? String.fromCharCode(c) : ' ';
    }
    out.push({ label: `Suma +${add} en vivo`, text: t });
  }
  transformCache.set(s, out);
  return out;
}

export function searchKeyword(scan: HiddenScan, keyword: string): Hit[] {
  const variants = keywordVariants(keyword);
  if (!variants.length) return [];
  const hits: Hit[] = [];
  const seen = new Set<string>();

  const test = (s: Stream, text: string, technique: string, detail: string, variantBonus = 0, onlyExact = false) => {
    const pad = padded(text);
    const comp = pad.replace(/\s+/g, '');
    const list = onlyExact ? variants.slice(0, 1) : variants;
    for (const v of list) {
      let idx = pad.indexOf(v.v);
      let inCompact = false;
      if (idx < 0) {
        idx = comp.indexOf(v.v);
        inCompact = idx >= 0;
      }
      if (idx < 0) continue;
      const start = inCompact ? 0 : Math.max(0, idx - 70);
      const context = (inCompact ? text.slice(0, 180) : text.slice(start, idx + v.v.length + 90)).replace(/\s+/g, ' ').trim();
      const normTech = technique
        .replace(/ROT\d+(?: en vivo)?/g, 'ROT-N')
        .replace(/XOR 0x[0-9A-F]+(?: en vivo)?/g, 'XOR de 1 byte')
        .replace(/Suma \+\d+(?: en vivo)?/g, 'Suma de bytes')
        .replace(/Cada \d+º byte/g, 'Muestreo de bytes')
        .replace(/LSB con salto \d+/g, 'LSB con salto')
        .replace(/Bloque (base64|hexadecimal)/g, 'Bloque codificado')
        .replace(/Entrada: .*/g, 'Entrada de contenedor')
        .replace(/Flujo PDF \d+/g, 'Flujo PDF');
      const key = `${s.group}|${normTech}|${v.label}|${s.label}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const groupBonus: Record<string, number> = {
        'Texto invisible': 34, 'Imagen LSB': 30, Decodificación: 26, Transformación: 24, Contenedor: 18, Metadatos: 14, Archivo: 0,
      };
      hits.push({
        id: `k${hits.length}`,
        word: keyword,
        context,
        variant: v.label,
        technique,
        detail: `${s.label} · ${detail}`,
        group: s.group,
        kind: 'keyword',
        score: 100 - variantBonus + (groupBonus[s.group] ?? 0) + s.printable * 8 + (inCompact ? -8 : 0),
        streamId: s.id,
        streamText: text,
        offset: s.offset,
        lsb: s.lsb,
      });
      break;
    }
  };

  for (const s of scan.streams) test(s, s.text, s.group, s.detail);
  // Transformaciones en vivo sobre una muestra de flujos con bytes
  const candidates = scan.streams.filter((s) => s.bytes && s.bytes.length >= 8).slice(0, 48);
  for (const s of candidates) {
    for (const t of virtualTransformTexts(s)) test(s, t.text, `Transformación · ${t.label}`, s.label, 5, true);
    if (hits.length > 400) break;
  }
  return hits.sort((a, b) => b.score - a.score).slice(0, 24);
}

/* ───────────── Detección automática de palabras ocultas ───────────── */

export function autoFind(scan: HiddenScan): { words: Hit[]; flags: Hit[] } {
  const found = new Map<string, { hit: Hit; streams: Set<string> }>();
  const flags = new Map<string, Hit>();
  const groupBonus: Record<string, number> = {
    'Texto invisible': 30, 'Imagen LSB': 28, Decodificación: 24, Transformación: 22, Contenedor: 16, Metadatos: 12, Archivo: 0,
  };
  for (const s of scan.streams) {
    if (s.printable < 0.88) continue; // los flujos con ruido no aportan palabras fiables
    const text = s.text.slice(0, 3000);
    const KNOWN_PREFIX = /^(ciberistmo|flag|ctf|picoctf|htb|thm|secret|clave|bandera|rootme)$/i;
    for (const f of findFlags(text)) {
      const prefix = f.slice(0, Math.max(0, f.indexOf('{')));
      // Las transformaciones ROT-N generan prefijos falsos (PVOREVFGZB…) que no son banderas reales
      if (s.group === 'Transformación' && !KNOWN_PREFIX.test(prefix)) continue;
      const idx = text.indexOf(f);
      const h: Hit = {
        id: `f${flags.size}`, word: f, context: text.slice(Math.max(0, idx - 60), idx + f.length + 60),
        variant: 'bandera', technique: s.group, detail: s.label, group: s.group, kind: 'flag', score: 500,
        streamId: s.id, streamText: text, offset: s.offset, lsb: s.lsb,
      };
      if (!flags.has(f)) flags.set(f, h);
    }
    // Las transformaciones ROT/Atbash/inversión producan falsas «palabras» a partir de base64.
    // La búsqueda por palabra sí las explora; aquí solo queremos texto ya legible.
    if (s.group === 'Transformación') continue;
    for (const m of text.matchAll(/[A-Za-zÁÉÍÓÚÑÜ][A-Za-zÁÉÍÓÚÑÜ]{3,23}/g)) {
      const w = m[0];
      const idx = m.index ?? 0;
      const before = text[idx - 1] ?? ' ';
      const after = text[idx + w.length] ?? ' ';
      // Descarta fragmentos de blobs base64/hex: deben ser palabras separadas
      if (/[A-Za-zÁÉÍÓÚÑÜáéíóúñü0-9+/=]/.test(before) && /[A-Za-zÁÉÍÓÚÑÜáéíóúñü0-9+/=]/.test(after)) continue;
      const lower = w.toLowerCase();
      // Descarta MezClAs de mayúsculas y TODO EN MAYÚSCULAS (nombres de formato)
      if (w.length > 4 && w === w.toUpperCase()) continue;
      if (/[A-Z]/.test(w.slice(1))) continue;
      const p = plausibility(w);
      if (p < 0) continue;
      const score = p + (groupBonus[s.group] ?? 0) + Math.min(15, s.printable * 12) + (COMMON.has(lower) ? 10 : 0);
      const prev = found.get(lower);
      if (prev) {
        prev.streams.add(s.id);
        if (prev.hit.score < score) prev.hit = {
          ...prev.hit, word: w, score, technique: s.group, detail: s.label, group: s.group,
          context: text.slice(Math.max(0, idx - 55), idx + w.length + 55).replace(/\s+/g, ' ').trim(),
          streamId: s.id, streamText: text, offset: s.offset, lsb: s.lsb,
        };
      } else {
        found.set(lower, {
          streams: new Set([s.id]),
          hit: {
            id: `w${found.size}`,
            word: w,
            context: text.slice(Math.max(0, idx - 55), idx + w.length + 55).replace(/\s+/g, ' ').trim(),
            variant: COMMON.has(lower) ? 'palabra conocida' : 'palabra plausible',
            technique: s.group,
            detail: s.label,
            group: s.group,
            kind: 'word',
            score,
            streamId: s.id,
            streamText: text,
            offset: s.offset,
            lsb: s.lsb,
          },
        });
      }
    }
  }
  const words = [...found.values()]
    .map(({ hit, streams }) => ({ hit, streams, score: hit.score + Math.min(40, (streams.size - 1) * 9) }))
    .filter(({ hit, streams, score }) => {
      if (COMMON.has(hit.word.toLowerCase())) return true;
      if (hit.word.length > 9 || streams.size < 2 || score < 120) return false;
      return true;
    })
    .map(({ hit, streams, score }) => ({ ...hit, score, variant: streams.size > 1 ? `en ${streams.size} flujos` : hit.variant }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 60);
  return { words, flags: [...flags.values()].sort((a, b) => b.score - a.score) };
}

export async function scanHidden(
  file: File,
  a: AnalysisResult,
  challenge: ChallengeResult,
  onProgress: HiddenProgress = () => {},
): Promise<HiddenScan> {
  const built = await buildStreams(file, a, challenge, onProgress);
  const found = autoFind({ streams: built.streams, words: [], flags: [], checks: built.checks, stats: built.stats });
  return { ...built, ...found };
}

export function exportStreams(scan: HiddenScan): string {
  return scan.streams
    .map((s) => `=== [${s.group}] ${s.label} · ${s.detail} · legible ${(s.printable * 100).toFixed(0)}% ===\n${s.text}\n`)
    .join('\n');
}
