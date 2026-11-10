import * as exifr from 'exifr';
import type { Extraction, Finding, MetaEntry, MetaGroup, TypeInfo } from './types';
import { walkJpeg, walkPng } from './structure';
import { decodeLatin1, decodeUtf8, formatBytes, hex, mk, u16be, u32be, ascii } from './utils';
import { inflateZlib, toEntries } from './xml';

const GROUP_TITLES: Record<string, string> = {
  ifd0: 'EXIF · Cámara e imagen (IFD0)',
  exif: 'EXIF · Parámetros de captura',
  gps: 'EXIF · Geolocalización GPS',
  interop: 'EXIF · Interoperabilidad',
  ifd1: 'EXIF · Miniatura incrustada (IFD1)',
  makerNote: 'EXIF · MakerNote del fabricante',
  icc: 'Perfil de color ICC',
  iptc: 'IPTC · Prensa y derechos',
  jfif: 'JFIF',
  ihdr: 'Cabecera PNG (IHDR)',
  tiff: 'TIFF',
};

const KNOWN_APP = /^(JFIF|JFXX|Exif|http:\/\/ns\.adobe\.com\/xap\/1\.0\/|http:\/\/ns\.adobe\.com\/xmp\/extension\/|ICC_PROFILE|MPF|Photoshop 3\.0|Adobe|Ducky|Adobe_CM|Meta|FPXR)/;

const STD_PNG = new Set([
  'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB', 'cICP', 'mDCv', 'cLLi',
  'bKGD', 'hIST', 'pHYs', 'sPLT', 'eXIf', 'tIME', 'iTXt', 'tEXt', 'zTXt', 'acTL', 'fcTL', 'fdAT', 'caBX',
  'oFFs', 'pCAL', 'sCAL', 'sTER', 'gIFg', 'gIFx', 'gIFt', 'dSIG',
]);

const AI_KEYS = /^(parameters|prompt|workflow|dream|sd-metadata|invokeai_metadata|invokeai_graph|negative prompt|generation_data|comfy|ai_?generated)/i;
const AI_SOFT = /stable.?diffusion|midjourney|dall-?e|comfyui|automatic1111|novelai|invoke ?ai|firefly|leonardo|sdxl|flux|bing image creator/i;

export async function extractImage(b: Uint8Array, type: TypeInfo): Promise<Extraction> {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  let gps: Extraction['gps'] = null;
  let hasExif = false;
  let thumb = false;

  /* ── EXIF / IPTC / ICC / JFIF / IHDR vía exifr ── */
  try {
    const opts = {
      mergeOutput: false,
      tiff: true,
      ifd0: {},
      exif: true,
      gps: true,
      interop: true,
      ifd1: true,
      makerNote: true,
      userComment: true,
      xmp: false,
      icc: true,
      iptc: true,
      jfif: true,
      ihdr: false,
      sanitize: true,
      translateKeys: true,
      translateValues: true,
      reviveValues: true,
    };
    const parsed = (await exifr.parse(b as unknown as Uint8Array, opts as never)) as Record<string, Record<string, unknown>> | undefined;
    if (parsed && typeof parsed === 'object') {
      for (const [seg, obj] of Object.entries(parsed)) {
        if (!obj || typeof obj !== 'object' || seg === 'ihdr') continue;
        const entries = toEntries(obj, {
          forceSensitive: seg === 'gps',
          skip: seg === 'ifd1' ? /^(ThumbnailOffset|JPEGInterchangeFormat)$/ : undefined,
        });
        if (!entries.length) continue;
        if (seg === 'ifd0' || seg === 'exif' || seg === 'gps') hasExif = true;
        if (seg === 'ifd1') thumb = entries.some((e) => /Thumbnail|JPEGInterchangeFormatLength/i.test(e.key));
        groups.push({
          id: `exif-${seg}`,
          title: GROUP_TITLES[seg] ?? `EXIF · ${seg}`,
          entries,
          note: seg === 'makerNote' ? 'Datos propietarios del fabricante: pueden incluir número de serie, contador de disparos o modelo exacto del objetivo.' : undefined,
        });
      }
    }
  } catch {
    /* formato sin EXIF */
  }

  try {
    const g = await exifr.gps(b as unknown as Uint8Array);
    if (g && typeof g.latitude === 'number' && typeof g.longitude === 'number' && isFinite(g.latitude) && isFinite(g.longitude)) {
      gps = { lat: g.latitude, lon: g.longitude };
    }
  } catch {
    /* sin GPS */
  }

  if (gps) {
    findings.push(
      mk(
        'gps',
        'privacidad',
        'high',
        'Ubicación GPS exacta incrustada',
        `La imagen revela dónde fue tomada: ${gps.lat.toFixed(6)}, ${gps.lon.toFixed(6)}. Cualquier persona que reciba el archivo puede situar el lugar en un mapa.`,
        { recommendation: 'Elimina los metadatos EXIF/GPS antes de publicar o enviar la imagen (usa «Descargar copia limpia»).' },
      ),
    );
  }

  if (thumb) {
    findings.push(
      mk(
        'exif-thumb',
        'privacidad',
        'low',
        'Miniatura EXIF incrustada',
        'El archivo guarda una miniatura aparte. Si la foto fue recortada o censurada después, la miniatura puede conservar la versión original sin editar.',
        { recommendation: 'Elimina la miniatura junto con los metadatos al limpiar la imagen.' },
      ),
    );
  }

  /* ── JPEG ── */
  if (type.name === 'JPEG') {
    const { segments } = walkJpeg(b);
    const props: MetaEntry[] = [];
    const segEntries: MetaEntry[] = [];
    const comments: MetaEntry[] = [];
    let weird = 0;
    for (const s of segments) {
      if (s.marker >= 0xc0 && s.marker <= 0xc2) {
        const h = u16be(b, s.offset + 5);
        const w = u16be(b, s.offset + 7);
        props.push({ key: 'Dimensiones', value: `${w} × ${h} px` });
        props.push({ key: 'Precisión', value: `${b[s.offset + 4]} bits · ${b[s.offset + 9]} componente(s)` });
        props.push({ key: 'Modo', value: s.marker === 0xc2 ? 'Progresivo' : 'Baseline' });
      }
      if (s.marker === 0xfe) {
        const text = decodeLatin1(b, s.offset + 4, Math.min(b.length, s.offset + s.length)).replace(/\u0000/g, '').trim();
        if (text) comments.push({ key: `Comentario @0x${hex(s.offset, 4)}`, value: text.slice(0, 500), sensitive: true });
      }
      if (s.marker >= 0xe0 && s.marker <= 0xef && s.ident && !KNOWN_APP.test(s.ident) && s.length > 512) weird++;
      if (s.marker !== 0xda && s.marker !== 0xdb && s.marker !== 0xc4)
        segEntries.push({
          key: `${s.name} @0x${s.offset.toString(16).toUpperCase()}`,
          value: `${s.ident ? s.ident + ' · ' : ''}${formatBytes(s.length)}`,
        });
    }
    if (props.length) groups.unshift({ id: 'img-props', title: 'Propiedades de la imagen', entries: props });
    if (comments.length) {
      groups.push({ id: 'jpeg-com', title: 'Comentarios JPEG (COM)', entries: comments });
      findings.push(
        mk('jpeg-com', 'privacidad', 'low', 'Comentarios de texto ocultos en el JPEG', `Se hallaron ${comments.length} comentario(s): «${comments[0].value.slice(0, 120)}»`, {
          recommendation: 'Revisa y elimina los comentarios incrustados antes de compartir.',
        }),
      );
    }
    if (segEntries.length)
      groups.push({ id: 'jpeg-segs', title: 'Estructura interna JPEG (segmentos)', entries: segEntries.slice(0, 80), note: 'Segmentos APPn: contenedores de metadatos. Los valores desconocidos pueden alojar datos ocultos.' });
    if (weird) {
      findings.push(
        mk('jpeg-app-odd', 'forense', 'low', 'Segmentos de aplicación no estándar', `${weird} segmento(s) APPn grandes con identificador desconocido. Pueden ser datos propietarios o carga oculta.`),
      );
    }
    if (!hasExif && segments.length) {
      findings.push(
        mk('no-exif', 'forense', 'info', 'JPEG sin EXIF', 'No hay metadatos de cámara. Es común en capturas de pantalla, imágenes descargadas de redes sociales o archivos previamente «limpiados».'),
      );
    }
  }

  /* ── PNG ── */
  if (type.name === 'PNG') {
    const { chunks, end, truncated } = walkPng(b);
    const textEntries: MetaEntry[] = [];
    const struct: MetaEntry[] = [];
    const props: MetaEntry[] = [];
    let badCrc = 0;
    let privateChunks = 0;
    let aiHit: string | null = null;
    let c2pa = false;
    for (const c of chunks) {
      const d = c.offset + 8;
      const dEnd = Math.min(b.length, d + c.length);
      if (c.type === 'IHDR' && c.length >= 13) {
        props.push({ key: 'Dimensiones', value: `${u32be(b, d)} × ${u32be(b, d + 4)} px` });
        const ct = b[d + 9];
        const ctName = ({ 0: 'Escala de grises', 2: 'RGB', 3: 'Paleta', 4: 'Grises + alfa', 6: 'RGBA' } as Record<number, string>)[ct] ?? String(ct);
        props.push({ key: 'Profundidad / color', value: `${b[d + 8]} bits · ${ctName}${b[d + 12] ? ' · entrelazado' : ''}` });
      }
      if (c.type === 'tEXt' || c.type === 'zTXt' || c.type === 'iTXt') {
        const z = b.indexOf(0, d);
        if (z > d && z < dEnd) {
          const key = decodeLatin1(b, d, z);
          let text = '';
          if (c.type === 'tEXt') text = decodeLatin1(b, z + 1, dEnd);
          else if (c.type === 'zTXt') {
            const inf = await inflateZlib(b.subarray(z + 2, dEnd));
            text = inf ? decodeUtf8(inf) : '[comprimido · no se pudo descomprimir]';
          } else {
            const compressed = b[z + 1] === 1;
            const z2 = b.indexOf(0, z + 3);
            const z3 = z2 >= 0 ? b.indexOf(0, z2 + 1) : -1;
            if (z3 > 0 && z3 < dEnd) {
              if (compressed) {
                const inf = await inflateZlib(b.subarray(z3 + 1, dEnd));
                text = inf ? decodeUtf8(inf) : '[comprimido · no se pudo descomprimir]';
              } else text = decodeUtf8(b, z3 + 1, dEnd);
            }
          }
          text = text.replace(/\u0000/g, '').trim();
          if (key.startsWith('XML:com.adobe.xmp')) {
            // lo gestiona el parser XMP genérico
            struct.push({ key: `${c.type} @0x${c.offset.toString(16).toUpperCase()}`, value: `${key} · ${formatBytes(c.length)}` });
          } else {
            textEntries.push({ key, value: text.length > 600 ? text.slice(0, 600) + '…' : text, sensitive: true });
            if (!aiHit && (AI_KEYS.test(key) || AI_SOFT.test(text.slice(0, 2000)))) aiHit = key;
          }
        }
      } else if (c.type === 'tIME' && c.length === 7) {
        const dt = new Date(Date.UTC((b[d] << 8) | b[d + 1], b[d + 2] - 1, b[d + 3], b[d + 4], b[d + 5], b[d + 6]));
        props.push({ key: 'Última modificación (tIME)', value: dt.toISOString() });
      } else if (c.type === 'caBX') c2pa = true;
      else if (c.type === 'iCCP') {
        const z = b.indexOf(0, d);
        if (z > d) props.push({ key: 'Perfil ICC', value: decodeLatin1(b, d, z) });
      }
      if (c.crcOk === false) badCrc++;
      if (!STD_PNG.has(c.type)) privateChunks++;
      if (!['IDAT', 'fdAT'].includes(c.type) && !(c.type === 'tEXt' || c.type === 'zTXt' || c.type === 'iTXt' || c.type === 'IHDR' || c.type === 'IEND')) {
        struct.push({
          key: `${c.type} @0x${c.offset.toString(16).toUpperCase()}`,
          value: `${formatBytes(c.length)}${c.crcOk === false ? ' · ⚠ CRC inválido' : ''}${!STD_PNG.has(c.type) ? ' · chunk no estándar' : ''}`,
        });
      }
    }
    if (props.length) groups.unshift({ id: 'img-props', title: 'Propiedades de la imagen', entries: props });
    if (textEntries.length) {
      groups.push({ id: 'png-text', title: 'Texto incrustado en PNG (tEXt / zTXt / iTXt)', entries: textEntries, note: 'Los chunks de texto se usan para guardar autor, software, comentarios y —en imágenes de IA— el prompt completo.' });
      const sensitiveKeys = textEntries.filter((e) => /author|artist|comment|copyright|software|description|source|title|creator/i.test(e.key));
      if (sensitiveKeys.length) {
        findings.push(
          mk('png-text', 'privacidad', 'medium', 'Texto personal en chunks PNG', `Campos: ${sensitiveKeys.map((e) => `${e.key} = «${e.value.slice(0, 60)}»`).join(' · ')}`, {
            recommendation: 'Elimina los chunks tEXt/iTXt/zTXt al publicar la imagen.',
          }),
        );
      }
    }
    struct.push({ key: 'Chunks totales', value: String(chunks.length) });
    groups.push({ id: 'png-struct', title: 'Estructura interna PNG (chunks)', entries: struct.slice(0, 80) });
    if (aiHit) {
      findings.push(
        mk('ai-meta', 'forense', 'medium', 'Metadatos de generación con IA', `El campo «${aiHit}» indica que la imagen fue generada con una herramienta de IA (p. ej. Stable Diffusion / ComfyUI). Suele incluir el prompt y los parámetros completos.`, {
          recommendation: 'Si no quieres exponer tu prompt o flujo de trabajo, limpia los metadatos antes de compartir.',
        }),
      );
    }
    if (c2pa) {
      findings.push(mk('c2pa', 'forense', 'info', 'Credenciales de contenido (C2PA)', 'Contiene un manifiesto C2PA con la procedencia criptográfica del archivo (quién lo creó y con qué herramienta).'));
    }
    if (badCrc) {
      findings.push(
        mk('png-crc', 'forense', 'medium', 'CRC inválido en chunks PNG', `${badCrc} chunk(s) no superan la verificación CRC32: el archivo fue modificado a mano, está dañado o se le inyectaron datos.`),
      );
    }
    if (privateChunks) {
      findings.push(
        mk('png-private', 'forense', 'low', 'Chunks PNG no estándar', `${privateChunks} chunk(s) de tipo no estándar. Algunos programas los usan para guardar datos propios; otros, para ocultar información.`),
      );
    }
    if (truncated || (end === null && chunks.length)) {
      findings.push(mk('png-trunc', 'forense', 'medium', 'PNG truncado o sin IEND', 'El archivo termina de forma anormal: puede estar incompleto, corrupto o manipulado.'));
    }
  }

  /* ── GIF ── */
  if (type.name === 'GIF') {
    const w = b[6] | (b[7] << 8);
    const h = b[8] | (b[9] << 8);
    groups.unshift({
      id: 'img-props',
      title: 'Propiedades de la imagen',
      entries: [
        { key: 'Versión', value: ascii(b, 0, 6) },
        { key: 'Dimensiones', value: `${w} × ${h} px` },
      ],
    });
    const comments: MetaEntry[] = [];
    let i = 13;
    if (b[10] & 0x80) i += 3 * (1 << ((b[10] & 7) + 1));
    let guard = 0;
    while (i < b.length && guard++ < 100000) {
      const c = b[i++];
      if (c === 0x3b) break;
      if (c === 0x21) {
        const label = b[i++];
        let txt = '';
        while (i < b.length) {
          const sz = b[i++];
          if (sz === 0) break;
          if (label === 0xfe) txt += decodeLatin1(b, i, i + sz);
          i += sz;
        }
        if (label === 0xfe && txt.trim()) comments.push({ key: 'Comentario GIF', value: txt.trim().slice(0, 500), sensitive: true });
      } else if (c === 0x2c) {
        const flags = b[i + 8];
        i += 9;
        if (flags & 0x80) i += 3 * (1 << ((flags & 7) + 1));
        i++;
        while (i < b.length) {
          const sz = b[i++];
          if (sz === 0) break;
          i += sz;
        }
      } else break;
    }
    if (comments.length) {
      groups.push({ id: 'gif-com', title: 'Comentarios GIF', entries: comments });
      findings.push(mk('gif-com', 'privacidad', 'low', 'Comentario oculto en el GIF', `«${comments[0].value.slice(0, 120)}»`));
    }
  }

  return { groups, findings, gps };
}
