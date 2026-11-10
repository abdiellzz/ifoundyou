import type {
  AnalysisResult,
  Extraction,
  Finding,
  InterestingString,
  MetaEntry,
  MetaGroup,
  Severity,
  TimelineEvent,
  Verdict,
} from './types';
import { checkExtension, detectType } from './signatures';
import {
  computeEntropy,
  computeHashes,
  extractStrings,
  findEmbedded,
  findTrailing,
} from './forensics';
import { extractImage } from './metaImage';
import { extractOle, extractPdf, extractZip } from './metaDocs';
import { extractAudio, extractExecutable, extractMp4, extractText } from './metaMisc';
import { analyzeStego } from './stego';
import { findXmpBlocks, parseXmp } from './xml';
import { formatBytes, getExt, mk, sleep } from './utils';

export const MAX_SIZE = 150 * 1024 * 1024;
export type ProgressFn = (message: string, pct: number) => void;

const WEIGHT: Record<Severity, number> = { info: 0, low: 5, medium: 14, high: 28, critical: 45 };
export const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const score = (fs: Finding[]) => {
  const sum = fs.reduce((a, f) => a + WEIGHT[f.severity], 0);
  return Math.round(100 * (1 - Math.exp(-sum / 60)));
};

const EDITORS = /photoshop|gimp|lightroom|snapseed|canva|affinity|paint\.net|pixlr|picsart|facetune|capture one|luminar|pixelmator|krita|illustrator|acdsee|fotor|photoscape|corel|inkscape/i;
const AI_SOFT = /stable.?diffusion|midjourney|dall-?e|comfyui|automatic1111|novelai|invoke ?ai|firefly|leonardo\.ai|sdxl|bing image creator|openai/i;

type Cat = 'ubicacion' | 'identidad' | 'dispositivo' | 'software' | 'texto';
const CAT_INFO: Record<Cat, { title: string; severity: Severity; why: string; rec: string }> = {
  ubicacion: {
    title: 'Datos de ubicación en los metadatos',
    severity: 'high',
    why: 'Pueden revelar lugares donde se creó o editó el archivo.',
    rec: 'Elimina los datos de ubicación antes de compartir.',
  },
  identidad: {
    title: 'Identidad personal u organizativa expuesta',
    severity: 'medium',
    why: 'Nombres de autor, empresa o cuentas que permiten atribuir el archivo a una persona.',
    rec: 'Borra autor, empresa y «último modificado por» (Archivo → Información → Inspeccionar documento en Office).',
  },
  dispositivo: {
    title: 'Dispositivo o equipo identificable',
    severity: 'medium',
    why: 'Marca, modelo, número de serie, nombre de equipo o impresora: huella del hardware usado.',
    rec: 'Limpia los metadatos para no vincular el archivo a tu equipo.',
  },
  software: {
    title: 'Software y versión de creación revelados',
    severity: 'low',
    why: 'Aplicación y versión exactas con las que se creó o editó el archivo.',
    rec: 'Exporta o convierte el archivo para reducir la huella del software.',
  },
  texto: {
    title: 'Textos libres ocultos en los metadatos',
    severity: 'low',
    why: 'Comentarios, descripciones o etiquetas que el autor no pretendía publicar.',
    rec: 'Revisa el contenido de los campos de texto antes de difundir el archivo.',
  },
};

function classify(key: string): Cat {
  if (/gps|latitude|longitude|location|ubicaci|iso6709|xyz|^city$/i.test(key)) return 'ubicacion';
  if (/creator.?tool|software|producer|aplicaci|application|generator|encoder|codificad|created-by|herramienta|app.?version|compilador|vendor/i.test(key)) return 'software';
  if (/serial|^make$|^model$|fabricante|modelo|camera|lens|device|dispositivo|host|computer|machine|printer|plantilla|template|ruta pdb/i.test(key)) return 'dispositivo';
  if (/author|autor|artist|artista|owner|propietario|creator|last.?modified.?by|last.?author|manager|responsable|company|empresa|user|compositor|editor|copyright|e-?mail|persona|built-by|phone|address/i.test(key)) return 'identidad';
  return 'texto';
}

const SKIP_CLASSIFY = new Set(['png-text', 'office-custom', 'docx-comments', 'docx-tracked', 'jpeg-com', 'gif-com', 'html-comments', 'pptx-authors', 'docx-people', 'office-ext', 'pe-pdb']);

const DATE_KEY = /date|time|created|modified|creation|saved|printed|compil|fecha|guardado|impresi|grabaci|creaci/i;
const CREATED_KEY = /creat|original|creaci|compil|grabaci/i;
const MODIFIED_KEY = /modif|saved|guardado|actualiz/i;

function buildTimeline(groups: MetaGroup[], lastModified: number): TimelineEvent[] {
  const ev: TimelineEvent[] = [];
  const seen = new Set<string>();
  const now = Date.now();
  for (const g of groups) {
    for (const e of g.entries) {
      if (!DATE_KEY.test(e.key) || /timezone|offset|duraci|duration|edit.?time|subsec|stamp$/i.test(e.key)) continue;
      if (!/\d{4}/.test(e.value) || e.value.length > 40) continue;
      const m = e.value.replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3');
      const t = Date.parse(m);
      if (isNaN(t)) continue;
      const y = new Date(t).getUTCFullYear();
      if (y < 1980 || t > now + 400 * 86400000) continue;
      const key = `${t}|${e.key}`;
      if (seen.has(key)) continue;
      seen.add(key);
      ev.push({ time: t, label: e.key, source: g.title });
    }
  }
  if (lastModified) ev.push({ time: lastModified, label: 'Última modificación del archivo', source: 'Sistema de archivos' });
  return ev.sort((a, b) => a.time - b.time);
}

export async function analyzeFile(file: File, onProgress: ProgressFn = () => {}): Promise<AnalysisResult> {
  const t0 = performance.now();
  if (file.size > MAX_SIZE) throw new Error(`«${file.name}» pesa ${formatBytes(file.size)} y supera el límite de ${formatBytes(MAX_SIZE)}.`);
  onProgress('Leyendo archivo…', 3);
  const buf = await file.arrayBuffer();
  const b = new Uint8Array(buf);
  await sleep();

  const ext = getExt(file.name);
  onProgress('Identificando firma real (magic bytes)…', 10);
  const type = detectType(b);

  onProgress('Calculando hashes MD5 · SHA-1 · SHA-256 · SHA-512…', 18);
  const hashes = await computeHashes(b);
  await sleep();

  onProgress('Midiendo entropía…', 28);
  const entropy = computeEntropy(b);
  await sleep();

  onProgress('Buscando archivos incrustados y datos ocultos…', 38);
  const embedded = findEmbedded(b, type);
  const trailing = findTrailing(b, type);
  await sleep();

  onProgress('Extrayendo cadenas de texto…', 50);
  const strings = extractStrings(b);
  await sleep();

  onProgress('Extrayendo metadatos ocultos…', 62);
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  let gps: AnalysisResult['gps'] = null;
  let refined: Extraction | null = null;
  const leaks: InterestingString[] = [];
  const merge = (x: Extraction | null | undefined) => {
    if (!x) return;
    groups.push(...x.groups);
    findings.push(...x.findings);
    if (x.gps && !gps) gps = x.gps;
    if (x.leaks) leaks.push(...x.leaks);
    if (x.label || x.exts) refined = x;
  };
  const tn = type?.name ?? '';
  try {
    if (type) {
      if (['JPEG', 'PNG', 'GIF', 'TIFF', 'WebP', 'HEIC / HEIF', 'AVIF'].includes(tn)) merge(await extractImage(b, type));
      else if (tn === 'PDF') merge(extractPdf(b));
      else if (tn.startsWith('ZIP')) merge(await extractZip(b));
      else if (tn.startsWith('Documento OLE2')) merge(extractOle(b));
      else if (type.category === 'audio' && !/^M4A/.test(tn)) merge(extractAudio(b, type));
      else if (['MP4 (ISO BMFF)', 'QuickTime MOV', '3GP', 'M4A (audio MPEG-4)'].includes(tn)) merge(extractMp4(b));
      else if (type.category === 'executable') merge(extractExecutable(b, type));
      else if (type.category === 'text') merge(extractText(b, type));
    }
  } catch (err) {
    findings.push(mk('extract-error', 'forense', 'info', 'Extracción parcial de metadatos', `No se pudo leer toda la estructura interna (${err instanceof Error ? err.message : 'error desconocido'}). El archivo puede estar dañado o ser atípico.`));
  }

  onProgress('Buscando paquetes XMP…', 74);
  try {
    const xmp = findXmpBlocks(b);
    const seen = new Set<string>();
    xmp.forEach((x, i) => {
      const entries = parseXmp(x).filter((e) => {
        const k = e.key + '|' + e.value;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
      if (entries.length) groups.push({ id: `xmp-${i}`, title: xmp.length > 1 ? `XMP (paquete ${i + 1})` : 'XMP · Metadatos Adobe', entries: entries.slice(0, 120) });
      if (/<xmpMM:History|<stEvt:action/i.test(x)) {
        findings.push(mk('xmp-history', 'privacidad', 'medium', 'Historial de edición XMP', 'El archivo conserva el historial de acciones de edición (aplicación, fechas y cambios), útil para reconstruir su evolución.', { recommendation: 'Elimina el paquete XMP o exporta una copia nueva.' }));
      }
    });
  } catch {
    /* noop */
  }
  await sleep();

  /* Esteganografía en imágenes lossless */
  let stego: AnalysisResult['stego'] = null;
  if (tn === 'PNG' || tn === 'BMP') {
    onProgress('Analizando plano LSB (esteganografía)…', 84);
    try {
      stego = await analyzeStego(file);
    } catch {
      stego = null;
    }
  }

  onProgress('Generando informe…', 94);

  /* ── Refinar tipo y extensión ── */
  const ref = refined as Extraction | null;
  const typeLabel = ref?.label ?? type?.name ?? 'Tipo no reconocido';
  const mm = checkExtension(ext, type, ref?.exts);
  const extMismatch = mm.mismatch;
  if (extMismatch) {
    findings.push(mk('ext-mismatch', 'forense', mm.severity, 'La extensión no coincide con el contenido real', mm.note, { recommendation: 'No confíes en la extensión: abre el archivo solo si conoces su origen y tras analizarlo en un entorno aislado.' }));
  }
  if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rar|mp[34]|csv)\.(exe|scr|bat|cmd|js|jse|vbs|vbe|lnk|com|ps1|hta|msi|jar|wsf)$/i.test(file.name))
    findings.push(mk('double-ext', 'forense', 'high', 'Doble extensión engañosa', `«${file.name}» aparenta ser un documento pero termina en una extensión ejecutable.`));
  if (/[\u202a-\u202e\u2066-\u2069]/.test(file.name))
    findings.push(mk('rtlo', 'forense', 'critical', 'Nombre con carácter de inversión de texto (RTLO)', 'El nombre contiene un control Unicode bidireccional que invierte visualmente la extensión: técnica clásica de suplantación de malware.'));
  if (b.length === 0) findings.push(mk('empty', 'forense', 'info', 'Archivo vacío', 'El archivo tiene 0 bytes.'));
  if (!type && b.length > 0)
    findings.push(mk('unknown-type', 'forense', 'low', 'Tipo de archivo no reconocido', 'La firma no coincide con ningún formato conocido: puede ser un formato propietario, datos cifrados o un archivo corrupto.'));

  /* ── Incrustados ── */
  const byName = new Map<string, number>();
  for (const h of embedded) byName.set(h.name, (byName.get(h.name) ?? 0) + 1);
  const shown = new Map<string, number>();
  for (const h of embedded) {
    const n = (shown.get(h.name) ?? 0) + 1;
    shown.set(h.name, n);
    if (n > 3) continue;
    findings.push(mk(`embedded-${h.name}-${h.offset}`, 'forense', h.severity, `${h.name} oculto en el offset 0x${h.offset.toString(16).toUpperCase()}`, `${h.note}${byName.get(h.name)! > 3 && n === 3 ? ` (+${byName.get(h.name)! - 3} coincidencias más)` : ''}`, { offset: h.offset, recommendation: 'Extrae el contenido incrustado (desde el offset indicado) y analízalo por separado.' }));
  }

  /* ── Datos finales ── */
  if (trailing) {
    const sig = trailing.detected;
    let sev: Severity = 'low';
    if (sig) sev = ['Ejecutable Windows (PE/MZ)', 'Ejecutable Linux (ELF)'].includes(sig) ? 'critical' : 'high';
    else if (trailing.size > 1024 && trailing.entropy > 7.5) sev = 'high';
    else if (trailing.size > 1024) sev = 'medium';
    if (type?.name === 'Ejecutable Windows (PE/MZ)' && !sig) sev = trailing.size > 64 * 1024 && trailing.entropy > 7.5 ? 'medium' : 'low';
    if (type?.name === 'JPEG' && sig === 'JPEG') sev = 'low';
    findings.push(
      mk('trailing', 'forense', sev, `${formatBytes(trailing.size)} de datos tras el final lógico del archivo`, `${trailing.note} ${sig ? `Los datos parecen ser: ${sig}.` : ''} Entropía ${trailing.entropy.toFixed(2)}/8${trailing.entropy > 7.5 ? ' (aspecto de datos cifrados o comprimidos)' : ''}.`, { offset: trailing.offset, recommendation: 'Extrae los bytes sobrantes desde el offset indicado y examínalos.' }),
    );
  }

  /* ── Entropía ── */
  if (type?.category === 'executable' && entropy.overall > 7.3 && !findings.some((f) => f.id === 'pe-entropy' || f.id === 'pe-packer'))
    findings.push(mk('entropy-exe', 'forense', 'medium', 'Entropía global muy alta en el ejecutable', `Entropía ${entropy.overall.toFixed(2)}/8: el binario está comprimido, cifrado o empaquetado.`));
  if (type?.category === 'text' && entropy.overall > 6.2 && b.length > 2048)
    findings.push(mk('entropy-text', 'forense', 'medium', 'Texto con entropía anormal', `Entropía ${entropy.overall.toFixed(2)}/8 para un archivo de texto: probable contenido codificado (base64 largo) o cifrado.`));
  if (!type && b.length > 4096 && entropy.overall > 7.8)
    findings.push(mk('entropy-unknown', 'forense', 'medium', 'Datos de alta entropía sin cabecera', `Entropía ${entropy.overall.toFixed(2)}/8 y sin firma reconocible: patrón típico de contenedores cifrados (VeraCrypt, etc.) o datos comprimidos sin cabecera.`));

  /* ── Esteganografía ── */
  if (stego && stego.applicable) {
    if (stego.pEmbed > 0.99)
      findings.push(mk('stego-lsb', 'forense', 'medium', 'Indicios de esteganografía LSB', `El test chi-cuadrado de pares de valores da una probabilidad de incrustación del ${(stego.pEmbed * 100).toFixed(1)}% y los bits menos significativos están muy equilibrados (${stego.lsbRatio.map((r) => (r * 100).toFixed(1) + '%').join(' / ')}). Es compatible con datos ocultos en el plano LSB, aunque también ocurre en imágenes con mucho ruido.`, { recommendation: 'Inspecciona el plano LSB en la pestaña Forense → Laboratorio de imagen y prueba herramientas como zsteg o StegSolve.' }));
    else if (stego.pEmbed > 0.9)
      findings.push(mk('stego-lsb', 'forense', 'low', 'Posible esteganografía LSB (débil)', `Probabilidad de incrustación ${(stego.pEmbed * 100).toFixed(1)}%. Indicio débil que conviene contrastar visualmente con el plano LSB.`));
  }

  /* ── Cadenas ── */
  for (const l of leaks) {
    if (!strings.interesting.some((s) => s.type === l.type && s.value.toLowerCase() === l.value.toLowerCase())) strings.interesting.push(l);
  }
  const by = (t: string) => strings.interesting.filter((s) => s.type === t);
  const keys = by('clave-privada');
  if (keys.length) findings.push(mk('str-key', 'privacidad', 'critical', 'Clave privada incrustada', `Se encontró un bloque «${keys[0].value}». Cualquiera con el archivo podría suplantar la identidad o descifrar datos asociados.`, { offset: keys[0].offset >= 0 ? keys[0].offset : undefined, recommendation: 'Revoca y rota inmediatamente esa clave.' }));
  const creds = by('credencial');
  if (creds.length) findings.push(mk('str-cred', 'privacidad', 'high', `${creds.length} posible(s) credencial(es) o token(s)`, creds.slice(0, 4).map((c) => c.value.slice(0, 50) + (c.value.length > 50 ? '…' : '')).join(' · '), { offset: creds[0].offset >= 0 ? creds[0].offset : undefined, recommendation: 'Revoca y rota las credenciales expuestas.' }));
  const users = by('usuario');
  if (users.length) findings.push(mk('str-user', 'privacidad', 'medium', 'Nombre de usuario del sistema expuesto', `Rutas del equipo de origen revelan: ${[...new Set(users.map((u) => u.value))].slice(0, 5).join(', ')}.`, { recommendation: 'Evita distribuir archivos generados en tu equipo sin eliminar las rutas locales.' }));
  const emails = by('email');
  if (emails.length) findings.push(mk('str-email', 'privacidad', 'low', `${emails.length} dirección(es) de correo`, emails.slice(0, 5).map((e) => e.value).join(' · ')));
  const ips = by('ip');
  if (ips.length) findings.push(mk('str-ip', 'privacidad', 'low', `${ips.length} dirección(es) IP`, ips.slice(0, 6).map((e) => e.value).join(' · ')));
  const paths = by('ruta');
  if (paths.length && !users.length) findings.push(mk('str-path', 'privacidad', 'low', `${paths.length} ruta(s) del sistema de archivos`, paths.slice(0, 3).map((e) => e.value).join(' · ')));
  const susp = by('sospechoso');
  if (susp.length) {
    const risky = type?.category === 'executable' || type?.category === 'document' || type?.category === 'text' || type?.name.startsWith('ZIP');
    findings.push(mk('str-susp', 'forense', risky && susp.length >= 3 ? 'medium' : 'low', `${susp.length} indicador(es) sospechoso(s) en el contenido`, `Cadenas/APIs asociadas a malware o ejecución de código: ${[...new Set(susp.map((s) => s.value.toLowerCase()))].slice(0, 8).join(', ')}.`, { offset: susp[0].offset >= 0 ? susp[0].offset : undefined }));
  }
  const urls = by('url');
  if (urls.length >= 1 && (type?.category === 'executable' || type?.category === 'document')) findings.push(mk('str-url', 'forense', 'info', `${urls.length} URL(s) incrustadas`, urls.slice(0, 4).map((u) => u.value.slice(0, 80)).join(' · ')));

  /* ── Metadatos sensibles → privacidad ── */
  const sens = new Map<Cat, { g: string; e: MetaEntry }[]>();
  for (const g of groups) {
    if (SKIP_CLASSIFY.has(g.id)) continue;
    for (const e of g.entries) {
      if (!e.sensitive || !e.value || e.value === '0') continue;
      const c = classify(e.key);
      if (c === 'ubicacion' && gps) continue;
      if (!sens.has(c)) sens.set(c, []);
      sens.get(c)!.push({ g: g.title, e });
    }
  }
  (Object.keys(CAT_INFO) as Cat[]).forEach((c) => {
    const list = sens.get(c);
    if (!list?.length) return;
    const info = CAT_INFO[c];
    findings.push(mk(`meta-${c}`, 'privacidad', info.severity, info.title, `${info.why} ${list.slice(0, 4).map((x) => `${x.e.key}: «${x.e.value.slice(0, 50)}»`).join(' · ')}${list.length > 4 ? ` (+${list.length - 4} más)` : ''}`, { recommendation: info.rec }));
  });

  /* ── Edición / IA ── */
  const allEntries = groups.flatMap((g) => g.entries);
  const softVals = allEntries.filter((e) => /software|creator.?tool|producer|application|aplicaci|generator|host.?computer/i.test(e.key)).map((e) => e.value);
  const ed = softVals.find((v) => EDITORS.test(v));
  if (ed && !findings.some((f) => f.id === 'edited'))
    findings.push(mk('edited', 'forense', 'low', 'Indicios de edición con software gráfico', `Los metadatos mencionan «${ed.slice(0, 80)}». El archivo no es una captura original de cámara.`));
  const ai = softVals.find((v) => AI_SOFT.test(v));
  if (ai && !findings.some((f) => f.id === 'ai-meta')) findings.push(mk('ai-soft', 'forense', 'medium', 'Generado o procesado con IA', `Los metadatos mencionan «${ai.slice(0, 80)}».`));

  /* ── Línea temporal y coherencia ── */
  const timeline = buildTimeline(groups, file.lastModified);
  const metaEv = timeline.filter((e) => e.source !== 'Sistema de archivos');
  const created = metaEv.filter((e) => CREATED_KEY.test(e.label) && !MODIFIED_KEY.test(e.label)).map((e) => e.time);
  const modified = metaEv.filter((e) => MODIFIED_KEY.test(e.label)).map((e) => e.time);
  if (created.length && modified.length && !findings.some((f) => /dates$/.test(f.id))) {
    const c = Math.min(...created);
    const m = Math.max(...modified);
    if (m < c - 60_000) findings.push(mk('date-inconsistent', 'forense', 'medium', 'Fechas de metadatos incoherentes', 'La fecha de modificación es anterior a la de creación: indica metadatos manipulados o generados por software defectuoso.'));
  }
  if (timeline.some((e) => e.source !== 'Sistema de archivos' && e.time > Date.now() + 2 * 86400000))
    findings.push(mk('date-future', 'forense', 'medium', 'Fecha en el futuro', 'Algunos metadatos contienen fechas posteriores a hoy: reloj mal configurado o metadatos falsificados.'));

  /* ── Puntuación ── */
  const dedup = new Map<string, Finding>();
  for (const f of findings) if (!dedup.has(f.id)) dedup.set(f.id, f);
  const all = [...dedup.values()].sort((a, c) => SEV_ORDER[c.severity] - SEV_ORDER[a.severity]);
  const fF = all.filter((f) => f.axis === 'forense');
  const fP = all.filter((f) => f.axis === 'privacidad');
  const sF = score(fF);
  const sP = score(fP);
  const total = Math.round(Math.max(sF, sP) * 0.75 + Math.min(sF, sP) * 0.25);
  let verdict: Verdict = 'limpio';
  if (fF.some((f) => f.severity === 'critical') || sF >= 70) verdict = 'peligroso';
  else if (sF >= 35 || sP >= 60) verdict = 'sospechoso';
  else if (all.some((f) => SEV_ORDER[f.severity] >= 1)) verdict = 'precaucion';

  onProgress('Listo', 100);
  return {
    id: `${file.name}-${file.size}-${file.lastModified}-${Math.random().toString(36).slice(2, 8)}`,
    file,
    name: file.name,
    size: file.size,
    ext,
    browserMime: file.type,
    lastModified: file.lastModified,
    hashes,
    type,
    typeLabel,
    extMismatch,
    entropy,
    embedded,
    trailing,
    strings,
    metadata: groups,
    gps,
    stego,
    findings: all,
    scores: { forense: sF, privacidad: sP, total },
    verdict,
    timeline,
    analyzedAt: Date.now(),
    durationMs: Math.round(performance.now() - t0),
    cleanable: tn === 'JPEG' ? 'jpeg' : tn === 'PNG' ? 'png' : null,
  };
}
