import type { Extraction, Finding, MetaEntry, MetaGroup, TypeInfo } from './types';
import { entropyOf } from './forensics';
import { parsePe } from './structure';
import {
  ascii,
  decodeLatin1,
  decodeUtf16,
  decodeUtf8,
  formatBytes,
  indexOfBytes,
  isSensitiveKey,
  mk,
  u16le,
  u32be,
  u32le,
} from './utils';
import { flattenXml } from './xml';

/* ═════════════════════════ AUDIO ═════════════════════════ */

const ID3_NAMES: Record<string, [string, boolean]> = {
  TIT2: ['Título', false],
  TPE1: ['Artista', true],
  TPE2: ['Artista del álbum', true],
  TALB: ['Álbum', false],
  TYER: ['Año', false],
  TDRC: ['Fecha de grabación', false],
  TDEN: ['Fecha de codificación', false],
  TDTG: ['Fecha de etiquetado', false],
  TCON: ['Género', false],
  TCOM: ['Compositor', true],
  TENC: ['Codificado por', true],
  TSSE: ['Software / ajustes del codificador', true],
  TCOP: ['Copyright', true],
  TPUB: ['Editor / sello', true],
  TOWN: ['Propietario del archivo', true],
  TRCK: ['Pista', false],
  TSRC: ['ISRC', false],
  TLEN: ['Duración (ms)', false],
};

function synchsafe(b: Uint8Array, o: number) {
  return ((b[o] & 0x7f) << 21) | ((b[o + 1] & 0x7f) << 14) | ((b[o + 2] & 0x7f) << 7) | (b[o + 3] & 0x7f);
}

function id3Dec(b: Uint8Array, enc: number, a: number, e: number): string {
  if (e <= a) return '';
  if (enc === 0) return decodeLatin1(b, a, e);
  if (enc === 3) return decodeUtf8(b, a, e);
  if (enc === 2) return decodeUtf16(b, a, e, false);
  if (b[a] === 0xfe && b[a + 1] === 0xff) return decodeUtf16(b, a + 2, e, false);
  if (b[a] === 0xff && b[a + 1] === 0xfe) return decodeUtf16(b, a + 2, e, true);
  return decodeUtf16(b, a, e, true);
}

const id3Text = (b: Uint8Array, s: number, e: number) => id3Dec(b, b[s], s + 1, e);

export function extractAudio(b: Uint8Array, type: TypeInfo): Extraction {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  const entries: MetaEntry[] = [];

  if (ascii(b, 0, 3) === 'ID3' && b.length > 10) {
    const ver = b[3];
    const end = Math.min(b.length, 10 + synchsafe(b, 6));
    let pos = 10;
    entries.push({ key: 'Versión ID3', value: `2.${ver}` });
    if (ver >= 3) {
      if (b[5] & 0x40) pos += (ver === 4 ? synchsafe(b, pos) : u32be(b, pos) + 4);
      let apic = 0;
      let priv = 0;
      while (pos + 10 <= end) {
        const id = ascii(b, pos, 4);
        if (!/^[A-Z0-9]{4}$/.test(id)) break;
        const sz = ver === 4 ? synchsafe(b, pos + 4) : u32be(b, pos + 4);
        const d = pos + 10;
        if (sz <= 0 || d + sz > b.length) break;
        const known = ID3_NAMES[id];
        if (known) {
          const v = id3Text(b, d, d + sz).split('\u0000').filter(Boolean).join(' / ').trim();
          if (v) entries.push({ key: known[0], value: v.slice(0, 300), sensitive: known[1] });
        } else if (id === 'TXXX') {
          const parts = id3Text(b, d, d + sz).split('\u0000');
          const v = parts.slice(1).join(' ').trim();
          if (v) entries.push({ key: `TXXX · ${parts[0] || 'personalizado'}`, value: v.slice(0, 300), sensitive: true });
        } else if (id === 'COMM' || id === 'USLT') {
          const raw = id3Dec(b, b[d], d + 4, d + sz);
          const v = raw.split('\u0000').filter(Boolean).join(' ').trim();
          if (v) entries.push({ key: id === 'COMM' ? 'Comentario' : 'Letra', value: v.slice(0, 400), sensitive: id === 'COMM' });
        } else if (id === 'WXXX' || /^W[A-Z]{3}$/.test(id)) {
          const v = decodeLatin1(b, d + (id === 'WXXX' ? 1 : 0), d + sz).replace(/\u0000/g, ' ').trim();
          if (v) entries.push({ key: `URL (${id})`, value: v.slice(0, 300), sensitive: true });
        } else if (id === 'APIC') apic++;
        else if (id === 'PRIV') {
          priv++;
          const z = b.indexOf(0, d);
          entries.push({ key: 'PRIV (datos privados de aplicación)', value: `${decodeLatin1(b, d, Math.min(z < 0 ? d : z, d + sz))} · ${formatBytes(sz)}`, sensitive: true });
        } else if (id === 'POPM') {
          const z = b.indexOf(0, d);
          entries.push({ key: 'POPM (valoración / e-mail del usuario)', value: decodeLatin1(b, d, Math.min(z < 0 ? d : z, d + sz)), sensitive: true });
        } else if (id === 'GEOB') {
          entries.push({ key: 'GEOB (objeto general incrustado)', value: formatBytes(sz), sensitive: true });
          findings.push(mk('id3-geob', 'forense', 'medium', 'Objeto general incrustado en ID3 (GEOB)', `Frame GEOB de ${formatBytes(sz)}: puede alojar archivos arbitrarios dentro del audio.`));
        }
        pos = d + sz;
      }
      if (apic) entries.push({ key: 'Carátulas incrustadas (APIC)', value: String(apic) });
      if (priv) findings.push(mk('id3-priv', 'forense', 'low', 'Frames PRIV en ID3', `${priv} frame(s) con datos privados de aplicaciones (p. ej. marcas de agua, identificadores de tienda).`));
    }
  }
  if (b.length > 128 && ascii(b, b.length - 128, 3) === 'TAG') {
    const o = b.length - 128;
    const f = (s: number, l: number) => decodeLatin1(b, o + s, o + s + l).replace(/\u0000/g, '').trim();
    const v1: [string, string][] = [['ID3v1 · Título', f(3, 30)], ['ID3v1 · Artista', f(33, 30)], ['ID3v1 · Álbum', f(63, 30)], ['ID3v1 · Año', f(93, 4)], ['ID3v1 · Comentario', f(97, 30)]];
    for (const [k, v] of v1) if (v) entries.push({ key: k, value: v, sensitive: /Artista|Comentario/.test(k) });
  }

  /* FLAC: Vorbis comments */
  if (type.name === 'FLAC') {
    let pos = 4;
    let last = false;
    while (!last && pos + 4 <= b.length) {
      last = (b[pos] & 0x80) !== 0;
      const t = b[pos] & 0x7f;
      const len = (b[pos + 1] << 16) | (b[pos + 2] << 8) | b[pos + 3];
      const d = pos + 4;
      if (t === 4 && d + len <= b.length) {
        let p = d;
        const vl = u32le(b, p);
        entries.push({ key: 'Codificador (vendor)', value: decodeUtf8(b, p + 4, p + 4 + vl), sensitive: true });
        p += 4 + vl;
        const n = u32le(b, p);
        p += 4;
        for (let i = 0; i < n && p + 4 <= d + len; i++) {
          const l = u32le(b, p);
          const kv = decodeUtf8(b, p + 4, p + 4 + l);
          const eq = kv.indexOf('=');
          if (eq > 0) entries.push({ key: kv.slice(0, eq), value: kv.slice(eq + 1).slice(0, 300), sensitive: isSensitiveKey(kv.slice(0, eq)) });
          p += 4 + l;
        }
      }
      pos = d + len;
    }
  }
  /* WAV: LIST INFO */
  if (type.name === 'WAV') {
    let pos = 12;
    while (pos + 8 <= b.length) {
      const id = ascii(b, pos, 4);
      const sz = u32le(b, pos + 4);
      if (id === 'LIST' && ascii(b, pos + 8, 4) === 'INFO') {
        let p = pos + 12;
        const e = Math.min(b.length, pos + 8 + sz);
        const names: Record<string, string> = { INAM: 'Título', IART: 'Artista', ISFT: 'Software', ICMT: 'Comentario', ICRD: 'Fecha', IENG: 'Ingeniero', ICOP: 'Copyright', ISRC: 'Fuente', IGNR: 'Género', IPRD: 'Producto' };
        while (p + 8 <= e) {
          const sid = ascii(b, p, 4);
          const ssz = u32le(b, p + 4);
          const v = decodeLatin1(b, p + 8, Math.min(e, p + 8 + ssz)).replace(/\u0000/g, '').trim();
          if (v) entries.push({ key: names[sid] ?? sid, value: v, sensitive: /ISFT|IART|ICMT|IENG|ICOP|ISRC/.test(sid) });
          p += 8 + ssz + (ssz % 2);
        }
      }
      pos += 8 + sz + (sz % 2);
      if (sz === 0 && id === '\u0000\u0000\u0000\u0000') break;
    }
  }
  if (entries.length) groups.push({ id: 'audio-tags', title: 'Etiquetas de audio', entries });
  return { groups, findings };
}

/* ═════════════════════════ VÍDEO / MP4 / MOV ═════════════════════════ */

const MP4_EPOCH = 2082844800;
const ILST_NAMES: Record<string, string> = {
  '\u00a9nam': 'Título',
  '\u00a9ART': 'Artista',
  '\u00a9alb': 'Álbum',
  '\u00a9day': 'Fecha',
  '\u00a9cmt': 'Comentario',
  '\u00a9too': 'Herramienta de codificación',
  '\u00a9xyz': 'Ubicación GPS (ISO 6709)',
  '\u00a9mak': 'Fabricante',
  '\u00a9mod': 'Modelo',
  '\u00a9swr': 'Software',
  '\u00a9gen': 'Género',
  '\u00a9wrt': 'Autor',
  '\u00a9grp': 'Grupo',
};

function parseIso6709(s: string): { lat: number; lon: number } | null {
  const m = s.match(/([+-]\d{1,2}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)/);
  if (!m) return null;
  const lat = parseFloat(m[1]);
  const lon = parseFloat(m[2]);
  return isFinite(lat) && isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 ? { lat, lon } : null;
}

export function extractMp4(b: Uint8Array): Extraction {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  const info: MetaEntry[] = [];
  const tags: MetaEntry[] = [];
  let gps: Extraction['gps'] = null;
  const keys: string[] = [];

  const atoms = (s: number, e: number, cb: (type: string, ds: number, de: number) => void) => {
    let p = s;
    let guard = 0;
    while (p + 8 <= e && guard++ < 5000) {
      let size = u32be(b, p);
      const type = ascii(b, p + 4, 4);
      let hdr = 8;
      if (size === 1) {
        size = u32be(b, p + 12);
        hdr = 16;
      } else if (size === 0) size = e - p;
      if (size < hdr || p + size > e + 1) break;
      cb(type, p + hdr, Math.min(e, p + size));
      p += size;
    }
  };
  const iso = (t: number) => (t > MP4_EPOCH ? new Date((t - MP4_EPOCH) * 1000).toISOString() : null);

  if (ascii(b, 4, 4) === 'ftyp') info.push({ key: 'Marca (brand)', value: ascii(b, 8, 4) });

  const handleIlst = (s: number, e: number) => {
    atoms(s, e, (type, ds, de) => {
      let name = ILST_NAMES[type];
      if (!name && keys.length) {
        const idx = u32be(b, ds - 8 + 4);
        if (idx >= 1 && idx <= keys.length) name = keys[idx - 1].replace(/^com\.apple\.quicktime\./, '');
      }
      name = name ?? type;
      atoms(ds, de, (t2, s2, e2) => {
        if (t2 !== 'data' || e2 - s2 < 8) return;
        const flags = u32be(b, s2) & 0xffffff;
        if (flags === 1) {
          const v = decodeUtf8(b, s2 + 8, e2).replace(/\u0000/g, '').trim();
          if (v) {
            tags.push({ key: name!, value: v.slice(0, 300), sensitive: true });
            if (/xyz|iso6709/i.test(type + name!) && !gps) gps = parseIso6709(v);
          }
        }
      });
    });
  };

  const walkMeta = (s: number, e: number) => {
    atoms(s, e, (type, ds, de) => {
      if (type === 'keys') {
        const n = u32be(b, ds + 4);
        let p = ds + 8;
        for (let i = 0; i < n && p + 8 <= de; i++) {
          const sz = u32be(b, p);
          if (sz < 8) break;
          keys.push(decodeUtf8(b, p + 8, p + sz));
          p += sz;
        }
      } else if (type === 'ilst') handleIlst(ds, de);
    });
  };

  atoms(0, b.length, (type, ds, de) => {
    if (type !== 'moov') return;
    atoms(ds, de, (t, s, e) => {
      if (t === 'mvhd') {
        const v = b[s];
        const c = v === 1 ? u32be(b, s + 8) * 4294967296 + u32be(b, s + 12) : u32be(b, s + 4);
        const m = v === 1 ? u32be(b, s + 16) * 4294967296 + u32be(b, s + 20) : u32be(b, s + 8);
        const ts = v === 1 ? u32be(b, s + 24) : u32be(b, s + 12);
        const du = v === 1 ? u32be(b, s + 32) : u32be(b, s + 16);
        if (iso(c)) info.push({ key: 'Fecha de creación', value: iso(c)! });
        if (iso(m)) info.push({ key: 'Fecha de modificación', value: iso(m)! });
        if (ts) info.push({ key: 'Duración', value: `${(du / ts).toFixed(1)} s` });
      } else if (t === 'udta') {
        atoms(s, e, (t2, s2, e2) => {
          if (t2 === 'meta') walkMeta(s2 + 4, e2);
          else if (ILST_NAMES[t2]) {
            // formato QuickTime clásico: size(2) lang(2) texto
            const v = decodeUtf8(b, s2 + 4, e2).replace(/\u0000/g, '').trim();
            if (v) {
              tags.push({ key: ILST_NAMES[t2], value: v.slice(0, 300), sensitive: true });
              if (t2 === '\u00a9xyz' && !gps) gps = parseIso6709(v);
            }
          }
        });
      } else if (t === 'meta') walkMeta(s + 4, e);
    });
  });

  if (info.length) groups.push({ id: 'mp4-info', title: 'Contenedor MP4 / MOV', entries: info });
  if (tags.length) groups.push({ id: 'mp4-tags', title: 'Etiquetas del vídeo (udta / ilst)', entries: tags });
  const g = gps as Extraction['gps'];
  if (g) {
    findings.push(mk('gps', 'privacidad', 'high', 'Ubicación GPS incrustada en el vídeo', `Coordenadas: ${g.lat.toFixed(5)}, ${g.lon.toFixed(5)}. Revela dónde se grabó.`, { recommendation: 'Elimina los metadatos de ubicación antes de publicar el vídeo.' }));
  }
  return { groups, findings, gps: g };
}

/* ═════════════════════════ TEXTO / HTML / SVG ═════════════════════════ */

export function extractText(b: Uint8Array, type: TypeInfo): Extraction {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  const slice = b.subarray(0, Math.min(b.length, 6_000_000));
  let text: string;
  let enc = 'UTF-8 / ASCII';
  if (slice[0] === 0xff && slice[1] === 0xfe) {
    text = decodeUtf16(slice, 2, slice.length, true);
    enc = 'UTF-16 LE (con BOM)';
  } else if (slice[0] === 0xfe && slice[1] === 0xff) {
    text = decodeUtf16(slice, 2, slice.length, false);
    enc = 'UTF-16 BE (con BOM)';
  } else {
    text = decodeUtf8(slice);
    if (slice[0] === 0xef && slice[1] === 0xbb && slice[2] === 0xbf) enc = 'UTF-8 con BOM';
    else if (text.includes('\ufffd')) enc = 'Probable Windows-1252 / Latin-1 (UTF-8 inválido)';
  }
  const info: MetaEntry[] = [{ key: 'Codificación', value: enc }];
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/(?<!\r)\n/g) ?? []).length;
  const cr = (text.match(/\r(?!\n)/g) ?? []).length;
  const eol = crlf && !lf ? 'CRLF (Windows)' : lf && !crlf ? 'LF (Linux / macOS)' : cr && !lf && !crlf ? 'CR (Mac clásico)' : crlf || lf ? 'Mixto (editado en varios sistemas)' : 'sin saltos de línea';
  info.push({ key: 'Fin de línea', value: eol, sensitive: false });
  info.push({ key: 'Líneas', value: String(crlf + lf + cr + 1) });
  groups.push({ id: 'text-info', title: 'Propiedades del texto', entries: info });

  const body = text.replace(/^\ufeff/, '');
  const zw = (body.match(/[\u200b\u200c\u200d\u2060\u180e\ufeff]/g) ?? []).length;
  if (zw >= 6) findings.push(mk('text-zw', 'forense', zw > 40 ? 'high' : 'medium', 'Caracteres invisibles (ancho cero)', `${zw} caracteres de ancho cero. Se usan para esteganografía de texto, marcas de agua invisibles que identifican al filtrador y ataques de suplantación.`, { recommendation: 'Compara el texto con otra copia y elimina los caracteres U+200B/U+200C/U+200D/U+2060.' }));
  const bidi = (body.match(/[\u202a-\u202e\u2066-\u2069]/g) ?? []).length;
  if (bidi) findings.push(mk('text-bidi', 'forense', 'high', 'Caracteres de control bidireccional (Trojan Source)', `${bidi} controles Unicode bidireccionales: pueden hacer que el código/texto se muestre distinto de como se ejecuta o interpreta.`));
  const trailing = (body.match(/[ \t]+$/gm) ?? []).length;
  if (trailing > 20 && trailing / Math.max(1, crlf + lf) > 0.3) findings.push(mk('text-ws', 'forense', 'low', 'Espacios finales sospechosos', `${trailing} líneas terminan en espacios/tabuladores: patrón típico de esteganografía de espacios en blanco (SNOW).`));
  if (/[a-z]+[\u0400-\u04ff]+|[\u0400-\u04ff]+[a-z]+/i.test(body.slice(0, 200_000)))
    findings.push(mk('text-homo', 'forense', 'low', 'Mezcla de alfabetos (homoglifos)', 'Hay palabras que combinan letras latinas y cirílicas: técnica de suplantación (phishing).'));

  if (type.name === 'HTML') {
    const metas: MetaEntry[] = [];
    for (const m of body.matchAll(/<meta\s+[^>]*>/gi)) {
      const n = /(?:name|property|http-equiv)\s*=\s*["']([^"']+)["']/i.exec(m[0])?.[1];
      const c = /content\s*=\s*["']([^"']*)["']/i.exec(m[0])?.[1];
      if (n && c) metas.push({ key: n, value: c.slice(0, 300), sensitive: isSensitiveKey(n) || /generator|author|publisher/i.test(n) });
      if (metas.length > 60) break;
    }
    const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(body)?.[1]?.trim();
    if (title) metas.unshift({ key: 'title', value: title.slice(0, 200) });
    if (metas.length) groups.push({ id: 'html-meta', title: 'Metadatos HTML (<meta>)', entries: metas });
    const comments = [...body.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1].trim()).filter((c) => c && !/^\[if|^<!/.test(c));
    if (comments.length) {
      groups.push({ id: 'html-comments', title: 'Comentarios HTML ocultos', entries: comments.slice(0, 15).map((c, i) => ({ key: `Comentario ${i + 1}`, value: c.slice(0, 300), sensitive: true })) });
      findings.push(mk('html-comments', 'privacidad', 'low', `${comments.length} comentario(s) HTML`, `Los comentarios no se muestran pero cualquiera puede leerlos. «${comments[0].slice(0, 100)}»`));
    }
    if (/<iframe\b[^>]*(?:width\s*=\s*["']?0|height\s*=\s*["']?0|display\s*:\s*none|visibility\s*:\s*hidden)/i.test(body))
      findings.push(mk('html-iframe', 'forense', 'high', 'iframe oculto', 'Se detectó un iframe invisible, técnica frecuente en drive-by downloads y clickjacking.'));
    if (/<script\b[^>]*src\s*=\s*["']https?:\/\//i.test(body)) findings.push(mk('html-ext-script', 'forense', 'low', 'Scripts de dominios externos', 'La página carga JavaScript de terceros.'));
    if (/<input\b[^>]*type\s*=\s*["']?password/i.test(body) && /<form\b[^>]*action\s*=\s*["']https?:\/\//i.test(body))
      findings.push(mk('html-phish', 'forense', 'medium', 'Formulario de contraseña con envío externo', 'Un formulario con contraseña envía datos a una URL absoluta: patrón de phishing.'));
  }

  if (type.name === 'SVG') {
    const e: MetaEntry[] = [];
    const meta = /<metadata[\s\S]*?<\/metadata>/i.exec(body)?.[0];
    if (meta) {
      const wrapped = `<root xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cc="http://creativecommons.org/ns#">${meta}</root>`;
      for (const x of flattenXml(wrapped)) if (!/^(root|metadata)$/i.test(x.key)) e.push(x);
    }
    for (const a of ['inkscape:version', 'sodipodi:docname', 'inkscape:export-filename', 'xmlns:i']) {
      const v = new RegExp(`${a}\\s*=\\s*"([^"]*)"`, 'i').exec(body)?.[1];
      if (v && a !== 'xmlns:i') e.push({ key: a, value: v, sensitive: true });
    }
    const gen = /<!--\s*(Generator:[^>]*?)-->/i.exec(body)?.[1];
    if (gen) e.push({ key: 'Generator', value: gen.trim(), sensitive: true });
    if (e.length) groups.push({ id: 'svg-meta', title: 'Metadatos del SVG', entries: e.slice(0, 40) });
    if (/<script\b|\son(?:load|click|mouseover|error)\s*=/i.test(body))
      findings.push(mk('svg-script', 'forense', 'high', 'SVG con scripts activos', 'Los SVG pueden ejecutar JavaScript al abrirse en un navegador (XSS).'));
    if (/<image\b[^>]*href\s*=\s*["']data:/i.test(body)) findings.push(mk('svg-embedded', 'forense', 'low', 'Imagen incrustada en base64 dentro del SVG', 'Puede ocultar otras imágenes o datos.'));
  }
  return { groups, findings };
}

/* ═════════════════════════ EJECUTABLES ═════════════════════════ */

const SUBSYSTEMS: Record<number, string> = { 1: 'Nativo', 2: 'GUI (ventanas)', 3: 'Consola', 5: 'OS/2', 7: 'POSIX', 9: 'Windows CE', 10: 'EFI', 14: 'Xbox' };
const PACKER_SECTIONS = /^(UPX\d|\.?upx|\.aspack|\.adata|\.themida|\.winlice|\.vmp\d|\.enigma\d|\.petite|\.nsp\d|\.mpress\d|\.pec\d?|\.yP|\.perplex|\.rmnet|\.boom|\.packed|\.svkp|\.neolite)/i;
const utf16 = (s: string) => Array.from(s).flatMap((c) => [c.charCodeAt(0), 0]);

export function extractExecutable(b: Uint8Array, type: TypeInfo): Extraction {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  const leaks: Extraction['leaks'] = [];

  if (type.name.startsWith('Ejecutable Windows')) {
    const pe = parsePe(b);
    if (!pe) {
      findings.push(mk('pe-bad', 'forense', 'medium', 'Cabecera PE inválida', 'El archivo empieza con «MZ» pero no tiene una cabecera PE válida: podría ser DOS, estar corrupto o manipulado.'));
      return { groups, findings };
    }
    const ts = pe.timestamp;
    const tsIso = ts ? new Date(ts * 1000).toISOString() : null;
    const info: MetaEntry[] = [
      { key: 'Arquitectura', value: pe.machine },
      { key: 'Tipo', value: `${pe.isDll ? 'DLL' : 'EXE'} ${pe.pe32plus ? '(PE32+)' : '(PE32)'}` },
      { key: 'Subsistema', value: SUBSYSTEMS[pe.subsystem] ?? String(pe.subsystem) },
      { key: 'Fecha de compilación', value: tsIso ?? '0 (compilación reproducible / borrada)' },
      { key: 'Punto de entrada (RVA)', value: '0x' + pe.entryPoint.toString(16) },
      { key: 'ImageBase', value: pe.imageBase },
      { key: '.NET (CLR)', value: pe.isDotNet ? 'Sí — administrado' : 'No — código nativo' },
    ];
    groups.push({ id: 'pe-header', title: 'Cabecera PE', entries: info });
    if (ts && (ts * 1000 > Date.now() + 86400000 || ts < 694224000))
      findings.push(mk('pe-ts', 'forense', 'medium', 'Fecha de compilación falsificada', `La marca de tiempo (${tsIso}) es imposible. Los autores de malware la modifican para dificultar la atribución.`));

    const secEntries: MetaEntry[] = [];
    let packed = false;
    let highEnt = 0;
    let stub = false;
    for (const s of pe.sections) {
      const ent = s.rawSize > 0 && s.rawPtr + s.rawSize <= b.length ? entropyOf(b, s.rawPtr, s.rawPtr + Math.min(s.rawSize, 8_000_000)) : 0;
      secEntries.push({ key: s.name || '(sin nombre)', value: `raw ${formatBytes(s.rawSize)} · virtual ${formatBytes(s.vsize)} · entropía ${ent.toFixed(2)}` });
      if (PACKER_SECTIONS.test(s.name)) packed = true;
      if (ent > 7.2 && s.rawSize > 4096) highEnt++;
      if (s.rawSize === 0 && s.vsize > 0x10000) stub = true;
    }
    if (secEntries.length) groups.push({ id: 'pe-sections', title: 'Secciones PE', entries: secEntries });
    if (packed) findings.push(mk('pe-packer', 'forense', 'high', 'Ejecutable empaquetado / ofuscado', 'Los nombres de sección delatan un packer o protector (UPX, Themida, VMProtect…). El malware los usa para evadir antivirus.'));
    else if (highEnt || stub)
      findings.push(mk('pe-entropy', 'forense', 'medium', 'Secciones comprimidas o cifradas', `${highEnt ? `${highEnt} sección(es) con entropía > 7.2. ` : ''}${stub ? 'Sección sin datos en disco pero con gran tamaño virtual (patrón de desempaquetado en memoria).' : ''}`));

    // Ruta PDB
    const rsds = indexOfBytes(b, [0x52, 0x53, 0x44, 0x53]);
    if (rsds > 0 && rsds + 24 < b.length) {
      let e = rsds + 24;
      while (e < b.length && e < rsds + 24 + 300 && b[e] !== 0) e++;
      const p = decodeUtf8(b, rsds + 24, e);
      if (p.length > 4 && /^[\x20-\x7e\u00a0-\uffff]+$/.test(p)) {
        groups.push({ id: 'pe-pdb', title: 'Símbolos de depuración (PDB)', entries: [{ key: 'Ruta PDB', value: p, sensitive: true }], note: 'La ruta original de compilación suele contener el nombre de usuario y la estructura de carpetas del desarrollador.' });
        leaks.push({ type: 'ruta', value: p, offset: rsds });
        const um = /(?:Users|home)[\\/]([^\\/]+)[\\/]/i.exec(p);
        if (um) leaks.push({ type: 'usuario', value: um[1], offset: rsds });
        findings.push(mk('pe-pdb', 'privacidad', 'medium', 'Ruta de compilación (PDB) expuesta', `«${p.slice(0, 160)}» revela el entorno del desarrollador.`, { recommendation: 'Compila con /PDBALTPATH o elimina la ruta PDB al distribuir el binario.' }));
      }
    }
    // Info de versión (heurística UTF-16)
    const ver: MetaEntry[] = [];
    for (const key of ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'LegalCopyright', 'OriginalFilename', 'ProductName', 'ProductVersion', 'Comments']) {
      const i = indexOfBytes(b, utf16(key));
      if (i < 0) continue;
      let p = i + key.length * 2 + 2;
      let guard = 0;
      while (p + 1 < b.length && b[p] === 0 && b[p + 1] === 0 && guard++ < 4) p += 2;
      let e = p;
      while (e + 1 < b.length && e < p + 400 && !(b[e] === 0 && b[e + 1] === 0)) e += 2;
      const v = decodeUtf16(b, p, e, true).trim();
      if (v && !/[\u0000-\u0008\u000e-\u001f]/.test(v) && v.length < 200) ver.push({ key, value: v, sensitive: /Company|Copyright|Comments/.test(key) });
    }
    if (ver.length) groups.push({ id: 'pe-version', title: 'Información de versión (recursos)', entries: ver });
    // Firma
    const certOff = pe.offset + 24 + (pe.pe32plus ? 112 : 96) + 4 * 8;
    const certSize = certOff + 8 < b.length ? u32le(b, certOff + 4) : 0;
    groups.push({ id: 'pe-sign', title: 'Firma digital', entries: [{ key: 'Authenticode', value: certSize > 0 ? `Presente (${formatBytes(certSize)}) — verifica la cadena con herramientas del sistema` : 'Sin firma digital' }] });
    if (certSize === 0) findings.push(mk('pe-unsigned', 'forense', 'info', 'Ejecutable sin firma digital', 'No hay firma Authenticode: no se puede verificar el editor ni la integridad.'));
  }

  if (type.name.startsWith('Ejecutable Linux')) {
    const is64 = b[4] === 2;
    const le = b[5] === 1;
    const t = le ? u16le(b, 16) : (b[16] << 8) | b[17];
    const m = le ? u16le(b, 18) : (b[18] << 8) | b[19];
    const machines: Record<number, string> = { 3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'AArch64', 8: 'MIPS', 20: 'PowerPC', 243: 'RISC-V' };
    const types: Record<number, string> = { 1: 'Reubicable (.o)', 2: 'Ejecutable', 3: 'Compartido / PIE', 4: 'Volcado (core)' };
    const e: MetaEntry[] = [
      { key: 'Clase', value: is64 ? '64 bits' : '32 bits' },
      { key: 'Endianness', value: le ? 'Little-endian' : 'Big-endian' },
      { key: 'Tipo', value: types[t] ?? String(t) },
      { key: 'Arquitectura', value: machines[m] ?? String(m) },
    ];
    const gcc = indexOfBytes(b, [0x47, 0x43, 0x43, 0x3a, 0x20, 0x28]);
    if (gcc >= 0) {
      let en = gcc;
      while (en < b.length && en < gcc + 200 && b[en] !== 0) en++;
      const v = ascii(b, gcc, en - gcc);
      e.push({ key: 'Compilador (.comment)', value: v, sensitive: true });
      findings.push(mk('elf-gcc', 'privacidad', 'low', 'Compilador y distribución expuestos', `«${v}» revela el sistema de compilación.`));
    }
    groups.push({ id: 'elf-header', title: 'Cabecera ELF', entries: e });
    if (t === 4) findings.push(mk('elf-core', 'forense', 'medium', 'Volcado de memoria (core dump)', 'Puede contener contraseñas, claves y datos en claro del proceso original.'));
  }
  return { groups, findings, leaks };
}
