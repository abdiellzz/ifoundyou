import JSZip from 'jszip';
import * as exifr from 'exifr';
import type { Extraction, Finding, MetaEntry, MetaGroup } from './types';
import { scanText } from './forensics';
import {
  decodeLatin1,
  decodeUtf16,
  decodeUtf8,
  formatBytes,
  isSensitiveKey,
  mk,
  u16le,
  u32le,
} from './utils';
import { flattenXml } from './xml';

/* ═════════════════════════ PDF ═════════════════════════ */

function pdfStringToText(raw: string): string {
  const bytes: number[] = [];
  if (raw[0] === '<') {
    const h = raw.slice(1, -1).replace(/\s+/g, '');
    for (let i = 0; i < h.length; i += 2) bytes.push(parseInt(h.slice(i, i + 2).padEnd(2, '0'), 16) || 0);
  } else {
    const s = raw.slice(1, -1);
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\') {
        const n = s[++i];
        if (n === undefined) break;
        if (n === 'n') bytes.push(10);
        else if (n === 'r') bytes.push(13);
        else if (n === 't') bytes.push(9);
        else if (n === 'b') bytes.push(8);
        else if (n === 'f') bytes.push(12);
        else if (n >= '0' && n <= '7') {
          let o = n;
          while (o.length < 3 && s[i + 1] >= '0' && s[i + 1] <= '7') o += s[++i];
          bytes.push(parseInt(o, 8) & 0xff);
        } else if (n === '\n' || n === '\r') {
          if (n === '\r' && s[i + 1] === '\n') i++;
        } else bytes.push(n.charCodeAt(0) & 0xff);
      } else bytes.push(c.charCodeAt(0) & 0xff);
    }
  }
  const u = Uint8Array.from(bytes);
  if (u[0] === 0xfe && u[1] === 0xff) return decodeUtf16(u, 2, u.length, false);
  if (u[0] === 0xff && u[1] === 0xfe) return decodeUtf16(u, 2, u.length, true);
  if (u[0] === 0xef && u[1] === 0xbb && u[2] === 0xbf) return decodeUtf8(u, 3);
  return decodeLatin1(u);
}

function pdfDate(s: string): string | null {
  const m = s.match(/^D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([Zz])|([+-])(\d{2})'?(\d{2})?)?/);
  if (!m) return null;
  const [, y, mo, d, h, mi, se, , sign, oh, om] = m;
  let t = Date.UTC(+y, +(mo ?? 1) - 1, +(d ?? 1), +(h ?? 0), +(mi ?? 0), +(se ?? 0));
  if (sign) t -= (sign === '+' ? 1 : -1) * ((+oh || 0) * 60 + (+om || 0)) * 60000;
  return isNaN(t) ? null : new Date(t).toISOString();
}

export function extractPdf(b: Uint8Array): Extraction {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  const text = decodeLatin1(b);
  const encrypted = /\/Encrypt\s/.test(text);

  /* Diccionario Info */
  const re = /\/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate|Company|SourceModified)\s*(\((?:\\[\s\S]|[^\\)])*\)|<[0-9A-Fa-f\s]*>)/g;
  const matches: { key: string; raw: string; idx: number }[] = [];
  for (const m of text.matchAll(re)) matches.push({ key: m[1], raw: m[2], idx: m.index ?? 0 });
  const anchors = matches.filter((m) => /^(Producer|Creator|CreationDate|ModDate|Author)$/.test(m.key)).map((m) => m.idx);
  const entries: MetaEntry[] = [];
  const seen = new Map<string, number>();
  let created: number | null = null;
  let modified: number | null = null;
  for (const m of matches) {
    const near = anchors.some((a) => Math.abs(a - m.idx) < 1500);
    if (!near) continue;
    let value = pdfStringToText(m.raw).replace(/\u0000/g, '').trim();
    if (!value) continue;
    const ctrl = (value.match(/[\x00-\x08\x0e-\x1f]/g) ?? []).length;
    if (ctrl > value.length * 0.2) continue;
    if (m.key === 'CreationDate' || m.key === 'ModDate' || m.key === 'SourceModified') {
      const iso = pdfDate(value);
      if (iso) {
        const ms = Date.parse(iso);
        if (m.key === 'CreationDate') created = created ?? ms;
        if (m.key === 'ModDate') modified = modified ?? ms;
        value = iso;
      }
    }
    const id = `${m.key}|${value}`;
    if (seen.has(id)) continue;
    const n = (seen.get(m.key) ?? 0) + 1;
    seen.set(m.key, n);
    seen.set(id, 1);
    entries.push({ key: n > 1 ? `${m.key} (revisión ${n})` : m.key, value: value.slice(0, 400), sensitive: isSensitiveKey(m.key) });
  }
  if (entries.length) groups.push({ id: 'pdf-info', title: 'Diccionario Info del PDF', entries });
  if (created !== null && modified !== null && modified < created) {
    findings.push(mk('pdf-dates', 'forense', 'medium', 'Fechas incoherentes', 'La fecha de modificación es anterior a la de creación: señal de metadatos alterados o de un generador defectuoso.'));
  }

  /* Estructura y características activas */
  const count = (r: RegExp) => (text.match(r) ?? []).length;
  const version = text.match(/%PDF-(\d\.\d)/)?.[1];
  const eof = count(/%%EOF/g);
  const pages = count(/\/Type\s*\/Page(?![s\w])/g);
  const features: [string, RegExp][] = [
    ['JavaScript', /\/(?:JavaScript|JS)\b/g],
    ['OpenAction', /\/OpenAction\b/g],
    ['Acciones adicionales (AA)', /\/AA\b/g],
    ['Launch (ejecutar programa)', /\/Launch\b/g],
    ['Archivos incrustados', /\/EmbeddedFiles?\b/g],
    ['RichMedia (Flash/3D)', /\/RichMedia\b/g],
    ['Formularios XFA', /\/XFA\b/g],
    ['SubmitForm', /\/SubmitForm\b/g],
    ['Enlaces URI', /\/URI\s*\(/g],
    ['Flujos de objetos (ObjStm)', /\/ObjStm\b/g],
    ['Anotaciones', /\/Annots\b/g],
  ];
  const struct: MetaEntry[] = [];
  if (version) struct.push({ key: 'Versión PDF', value: version });
  if (pages) struct.push({ key: 'Páginas (aprox.)', value: String(pages) });
  struct.push({ key: 'Marcadores %%EOF (revisiones)', value: String(eof) });
  struct.push({ key: 'Cifrado', value: encrypted ? 'Sí (/Encrypt)' : 'No' });
  const found: Record<string, number> = {};
  for (const [name, r] of features) {
    const c = count(r);
    if (c) {
      found[name] = c;
      struct.push({ key: name, value: String(c) });
    }
  }
  groups.push({ id: 'pdf-struct', title: 'Estructura y funciones activas del PDF', entries: struct });

  if (found['JavaScript'])
    findings.push(mk('pdf-js', 'forense', 'high', 'El PDF contiene JavaScript', `Se detectaron ${found['JavaScript']} referencia(s) a JavaScript. Es el vector más usado para explotar lectores PDF.`, { recommendation: 'No abras este PDF en un lector sin sandbox. Analízalo en un entorno aislado.' }));
  if (found['Launch (ejecutar programa)'])
    findings.push(mk('pdf-launch', 'forense', 'high', 'Acción Launch: puede ejecutar programas', 'El documento declara acciones /Launch capaces de lanzar aplicaciones externas.'));
  if (found['OpenAction'] || found['Acciones adicionales (AA)'])
    findings.push(mk('pdf-openaction', 'forense', found['JavaScript'] ? 'high' : 'low', 'Acciones automáticas al abrir', 'El PDF define acciones que se ejecutan al abrirlo o al interactuar (OpenAction / AA).'));
  if (found['Archivos incrustados'])
    findings.push(mk('pdf-embedded', 'forense', 'medium', 'Archivos adjuntos dentro del PDF', 'El PDF incluye ficheros incrustados que pueden contener otros documentos o ejecutables.', { recommendation: 'Extrae y analiza cada adjunto por separado.' }));
  if (found['RichMedia (Flash/3D)'])
    findings.push(mk('pdf-rich', 'forense', 'high', 'Contenido RichMedia (Flash/3D)', 'Formato históricamente explotado para ejecución de código.'));
  if (/\/[A-Za-z]*#[0-9A-Fa-f]{2}[A-Za-z0-9#]*/.test(text.slice(0, 20_000_000)))
    findings.push(mk('pdf-obf', 'forense', 'medium', 'Nombres de objeto ofuscados', 'Se usan secuencias #xx en nombres PDF (/J#61vaScript). Es una técnica de evasión de antivirus.'));
  if (found['Flujos de objetos (ObjStm)'])
    findings.push(mk('pdf-objstm', 'forense', 'info', 'Objetos comprimidos (ObjStm)', 'Parte de la estructura está comprimida y no es visible en este análisis estático; podría haber más funciones activas.'));
  if (eof > 1)
    findings.push(
      mk('pdf-revisions', 'privacidad', 'medium', `El PDF tiene ${eof} revisiones guardadas`, 'Cada guardado incremental conserva versiones anteriores del documento. Texto «borrado» o tachado puede seguir siendo recuperable.', { recommendation: 'Exporta/«Imprime a PDF» el documento para consolidar una sola versión antes de compartirlo.' }),
    );
  if (encrypted) findings.push(mk('pdf-enc', 'forense', 'info', 'PDF cifrado', 'El contenido está protegido con contraseña; parte del análisis puede ser incompleto.'));

  const uris = [...text.matchAll(/\/URI\s*\(((?:\\.|[^\\)])*)\)/g)].map((m) => m[1]).filter((v, i, a) => a.indexOf(v) === i).slice(0, 25);
  if (uris.length) groups.push({ id: 'pdf-uris', title: 'Enlaces incrustados (URI)', entries: uris.map((u, i) => ({ key: `Enlace ${i + 1}`, value: u })) });

  return { groups, findings, label: 'Documento PDF', exts: ['pdf'] };
}

/* ═════════════════════════ ZIP / OOXML / ODF / JAR ═════════════════════════ */

const EXEC_NAMES = /\.(exe|dll|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|msi|com|pif|jar|sh)$/i;

export async function extractZip(b: Uint8Array): Promise<Extraction> {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(b);
  } catch {
    return { groups, findings: [mk('zip-corrupt', 'forense', 'medium', 'Contenedor ZIP ilegible', 'No se pudo leer el directorio central del ZIP: el archivo está dañado, truncado o manipulado.')] };
  }
  const names = Object.keys(zip.files);
  const files = names.filter((n) => !zip.files[n].dir);
  const sizeOf = (n: string) => (zip.files[n] as unknown as { _data?: { uncompressedSize?: number } })._data?.uncompressedSize ?? 0;
  const read = async (n: string, max = 30_000_000): Promise<string | null> => {
    const f = zip.file(n);
    if (!f || sizeOf(n) > max) return null;
    try {
      return await f.async('string');
    } catch {
      return null;
    }
  };
  const has = (prefix: string) => names.some((n) => n === prefix || n.startsWith(prefix));
  let leakText = '';

  let label = 'Archivo ZIP';
  let exts: string[] | undefined;
  let kind: 'docx' | 'xlsx' | 'pptx' | 'odf' | 'jar' | 'apk' | 'epub' | 'zip' = 'zip';
  const ct = await read('[Content_Types].xml');
  const hasVba = has('word/vbaProject.bin') || has('xl/vbaProject.bin') || has('ppt/vbaProject.bin') || names.some((n) => /vbaProject\.bin$/i.test(n));
  const mimetype = (await read('mimetype', 1000))?.trim();
  if (ct && has('word/')) {
    kind = 'docx';
    label = hasVba ? 'Documento Word con macros' : 'Documento Word (DOCX)';
    exts = ['docx', 'docm', 'dotx', 'dotm'];
  } else if (ct && has('xl/')) {
    kind = 'xlsx';
    label = hasVba ? 'Hoja Excel con macros' : 'Hoja de cálculo Excel (XLSX)';
    exts = ['xlsx', 'xlsm', 'xltx', 'xltm', 'xlam'];
  } else if (ct && has('ppt/')) {
    kind = 'pptx';
    label = hasVba ? 'Presentación PowerPoint con macros' : 'Presentación PowerPoint (PPTX)';
    exts = ['pptx', 'pptm', 'potx', 'potm', 'ppsx', 'ppsm', 'ppam'];
  } else if (mimetype?.startsWith('application/vnd.oasis.opendocument')) {
    kind = 'odf';
    const sub = mimetype.split('.').pop() ?? '';
    const map: Record<string, [string, string[]]> = {
      text: ['Documento OpenDocument Texto (ODT)', ['odt', 'ott']],
      spreadsheet: ['Hoja OpenDocument (ODS)', ['ods', 'ots']],
      presentation: ['Presentación OpenDocument (ODP)', ['odp', 'otp']],
      graphics: ['Dibujo OpenDocument (ODG)', ['odg', 'otg']],
    };
    [label, exts] = map[sub] ?? ['Documento OpenDocument', ['odt', 'ods', 'odp', 'odg']];
  } else if (mimetype === 'application/epub+zip') {
    kind = 'epub';
    label = 'Libro electrónico EPUB';
    exts = ['epub'];
  } else if (has('AndroidManifest.xml') && names.some((n) => /^classes\d*\.dex$/.test(n))) {
    kind = 'apk';
    label = 'Aplicación Android (APK)';
    exts = ['apk', 'aab', 'xapk'];
  } else if (has('META-INF/MANIFEST.MF')) {
    kind = 'jar';
    label = 'Paquete Java (JAR)';
    exts = ['jar', 'war', 'ear', 'zip'];
  }

  /* ── Propiedades OOXML ── */
  if (ct) {
    const core = await read('docProps/core.xml');
    if (core) {
      leakText += core + '\n';
      const e = flattenXml(core);
      if (e.length) groups.push({ id: 'office-core', title: 'Propiedades del documento (core.xml)', entries: e });
    }
    const app = await read('docProps/app.xml');
    if (app) {
      leakText += app + '\n';
      const all = flattenXml(app);
      const parts = all.filter((x) => x.key === 'vt:lpstr').map((x) => x.value);
      const e = all.filter((x) => !x.key.startsWith('vt:') && x.key !== 'HeadingPairs' && x.key !== 'TitlesOfParts');
      if (parts.length) e.push({ key: 'Partes (hojas / diapositivas / títulos)', value: parts.slice(0, 30).join(' · ') });
      if (e.length) groups.push({ id: 'office-app', title: 'Propiedades de la aplicación (app.xml)', entries: e });
    }
    const custom = await read('docProps/custom.xml');
    if (custom) {
      leakText += custom + '\n';
      try {
        const doc = new DOMParser().parseFromString(custom, 'application/xml');
        const props = Array.from(doc.getElementsByTagName('property'));
        const e: MetaEntry[] = props
          .map((p) => ({ key: p.getAttribute('name') ?? 'propiedad', value: (p.textContent ?? '').trim().slice(0, 300), sensitive: true }))
          .filter((x) => x.value);
        if (e.length) {
          groups.push({ id: 'office-custom', title: 'Propiedades personalizadas (custom.xml)', entries: e, note: 'Suelen guardar etiquetas de clasificación, identificadores internos, nombres de clientes o proyectos.' });
          findings.push(mk('office-custom', 'privacidad', 'medium', 'Propiedades personalizadas ocultas', `${e.length} propiedad(es): ${e.slice(0, 4).map((x) => `${x.key}=«${x.value.slice(0, 40)}»`).join(' · ')}`, { recommendation: 'Usa «Inspeccionar documento» de Office para eliminar propiedades personalizadas.' }));
        }
      } catch {
        /* noop */
      }
    }

    const get = async (p: string) => (await read(p)) ?? '';
    /* ── Word ── */
    if (kind === 'docx') {
      const doc = await get('word/document.xml');
      const authors = new Set<string>();
      let ins = 0;
      let del = 0;
      for (const m of doc.matchAll(/<w:(ins|del|moveFrom|moveTo)\b[^>]*?w:author="([^"]*)"/g)) {
        if (m[1] === 'ins' || m[1] === 'moveTo') ins++;
        else del++;
        authors.add(m[2]);
      }
      if (ins + del) {
        groups.push({
          id: 'docx-tracked',
          title: 'Control de cambios sin resolver',
          entries: [
            { key: 'Inserciones', value: String(ins) },
            { key: 'Eliminaciones', value: String(del) },
            { key: 'Autores de cambios', value: [...authors].join(' · '), sensitive: true },
          ],
        });
        findings.push(mk('docx-tracked', 'privacidad', 'high', 'Cambios rastreados sin aceptar', `${ins} inserciones y ${del} eliminaciones de: ${[...authors].join(', ')}. El texto eliminado sigue dentro del archivo.`, { recommendation: 'Acepta o rechaza todos los cambios y elimina los comentarios antes de enviar el documento.' }));
      }
      const vanish = (doc.match(/<w:vanish\b/g) ?? []).length;
      if (vanish) findings.push(mk('docx-hidden', 'privacidad', 'medium', 'Texto oculto en el documento', `${vanish} fragmento(s) con formato «oculto» (w:vanish) que no se ven al leer pero siguen en el archivo.`));
      const rsids = new Set([...doc.matchAll(/w:rsid(?:R|RPr|P|RDefault)="([0-9A-Fa-f]{8})"/g)].map((m) => m[1]));
      if (rsids.size) groups.push({ id: 'docx-rsid', title: 'Sesiones de edición (rsid)', entries: [{ key: 'Sesiones de edición distintas', value: String(rsids.size) }], note: 'Cada identificador rsid corresponde a una sesión de edición; permite estimar cuántas veces se editó el documento.' });

      const comments = await get('word/comments.xml');
      if (comments) {
        const cAuthors = new Set([...comments.matchAll(/w:author="([^"]*)"/g)].map((m) => m[1]));
        const n = (comments.match(/<w:comment\b/g) ?? []).length;
        const sample = [...comments.matchAll(/<w:comment\b[\s\S]*?<\/w:comment>/g)].slice(0, 5).map((m) => m[0].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160));
        if (n) {
          groups.push({
            id: 'docx-comments',
            title: 'Comentarios del documento',
            entries: [{ key: 'Autores', value: [...cAuthors].join(' · '), sensitive: true }, ...sample.map((s, i) => ({ key: `Comentario ${i + 1}`, value: s, sensitive: true }))],
          });
          findings.push(mk('docx-comments', 'privacidad', 'medium', `${n} comentario(s) incrustados`, `Autores: ${[...cAuthors].join(', ')}. «${sample[0] ?? ''}»`, { recommendation: 'Elimina todos los comentarios antes de compartir.' }));
        }
      }
      const people = await get('word/people.xml');
      if (people) {
        const pe = [...new Set([...people.matchAll(/w15:author="([^"]*)"/g)].map((m) => m[1]))];
        if (pe.length) groups.push({ id: 'docx-people', title: 'Colaboradores registrados (people.xml)', entries: pe.map((p) => ({ key: 'Persona', value: p, sensitive: true })) });
      }
      const settings = await get('word/settings.xml');
      if (/<w:documentProtection\b/.test(settings)) findings.push(mk('docx-protect', 'forense', 'info', 'Documento con protección de edición', 'Word aplica restricciones de edición (w:documentProtection).'));
    }

    /* ── Excel ── */
    if (kind === 'xlsx') {
      const wb = await get('xl/workbook.xml');
      const sheets = [...wb.matchAll(/<sheet\b([^>]*)\/?>/g)].map((m) => ({
        name: /name="([^"]*)"/.exec(m[1])?.[1] ?? '?',
        state: /state="([^"]*)"/.exec(m[1])?.[1] ?? 'visible',
      }));
      if (sheets.length) {
        groups.push({ id: 'xlsx-sheets', title: 'Hojas del libro', entries: sheets.map((s) => ({ key: s.name, value: s.state === 'visible' ? 'visible' : `⚠ ${s.state === 'veryHidden' ? 'MUY OCULTA (solo accesible por VBA)' : 'oculta'}` })) });
        const hid = sheets.filter((s) => s.state !== 'visible');
        if (hid.length)
          findings.push(mk('xlsx-hidden', 'privacidad', 'high', `${hid.length} hoja(s) oculta(s) en el libro`, `Hojas: ${hid.map((h) => `${h.name} (${h.state})`).join(', ')}. Pueden contener datos que el destinatario no debería ver.`, { recommendation: 'Revisa y elimina las hojas ocultas antes de compartir.' }));
      }
      const dn = (wb.match(/<definedName\b[^>]*hidden="1"/g) ?? []).length;
      if (dn) findings.push(mk('xlsx-names', 'privacidad', 'low', 'Nombres definidos ocultos', `${dn} nombre(s) definido(s) con atributo hidden.`));
      const cmts = names.filter((n) => /^xl\/comments\d*\.xml$|^xl\/threadedComments\//.test(n));
      if (cmts.length) {
        let total = 0;
        const au = new Set<string>();
        for (const c of cmts.slice(0, 30)) {
          const x = await get(c);
          total += (x.match(/<comment\b|<threadedComment\b/g) ?? []).length;
          for (const a of x.matchAll(/<author>([^<]*)<\/author>/g)) au.add(a[1]);
        }
        findings.push(mk('xlsx-comments', 'privacidad', 'medium', `${total} comentario(s) en celdas`, `Autores: ${[...au].join(', ') || 'n/d'}`));
      }
      const ext = names.filter((n) => /^xl\/externalLinks\/externalLink\d+\.xml$/.test(n));
      if (ext.length) findings.push(mk('xlsx-extlinks', 'privacidad', 'medium', 'Vínculos a libros externos', `${ext.length} vínculo(s) externo(s): pueden revelar rutas de red y nombres de usuario de quien creó el archivo.`));
    }

    /* ── PowerPoint ── */
    if (kind === 'pptx') {
      const notes = names.filter((n) => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(n));
      let notesWithText = 0;
      for (const n of notes.slice(0, 200)) {
        const x = await get(n);
        const t = [...x.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map((m) => m[1]).join(' ').trim();
        if (t.replace(/\d+/g, '').trim().length > 2) notesWithText++;
      }
      if (notesWithText) findings.push(mk('pptx-notes', 'privacidad', 'medium', `${notesWithText} diapositiva(s) con notas del orador`, 'Las notas del orador viajan dentro del archivo aunque no se proyecten.', { recommendation: 'Borra las notas del orador antes de distribuir la presentación.' }));
      const slides = names.filter((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n));
      let hidden = 0;
      for (const s of slides.slice(0, 300)) if (/<p:sld\b[^>]*\bshow="0"/.test((await get(s)).slice(0, 2000))) hidden++;
      if (hidden) findings.push(mk('pptx-hidden', 'privacidad', 'medium', `${hidden} diapositiva(s) oculta(s)`, 'Hay diapositivas marcadas como ocultas que siguen incluidas en el archivo.'));
      const ca = await get('ppt/commentAuthors.xml');
      const au = [...new Set([...ca.matchAll(/\bname="([^"]*)"/g)].map((m) => m[1]))];
      if (au.length) {
        groups.push({ id: 'pptx-authors', title: 'Autores de comentarios', entries: au.map((a) => ({ key: 'Autor', value: a, sensitive: true })) });
      }
    }

    /* ── Relaciones externas (plantillas remotas, vínculos, OLE) ── */
    const rels = names.filter((n) => n.endsWith('.rels')).slice(0, 80);
    const externals: { type: string; target: string; source: string }[] = [];
    for (const r of rels) {
      const x = await get(r);
      for (const m of x.matchAll(/<Relationship\b[^>]*>/g)) {
        const tag = m[0];
        if (!/TargetMode="External"/i.test(tag)) continue;
        const target = /Target="([^"]*)"/.exec(tag)?.[1] ?? '';
        const type = (/Type="([^"]*)"/.exec(tag)?.[1] ?? '').split('/').pop() ?? '';
        externals.push({ type, target, source: r });
      }
    }
    if (externals.length) {
      leakText += externals.map((e) => e.target).join('\n') + '\n';
      groups.push({ id: 'office-ext', title: 'Recursos externos referenciados', entries: externals.slice(0, 40).map((e) => ({ key: e.type, value: e.target.slice(0, 300), sensitive: e.type !== 'hyperlink' })), note: 'Los vínculos no-hipervínculo se cargan automáticamente al abrir el archivo y pueden filtrar tu IP o ejecutar contenido remoto.' });
      const danger = externals.filter((e) => /attachedTemplate|oleObject|externalLink|frame|subDocument|slideMaster|image|settings/i.test(e.type) && /^(https?|ftp|file|\\\\)/i.test(e.target));
      if (danger.length) {
        const tmpl = danger.some((d) => /attachedTemplate/i.test(d.type));
        findings.push(
          mk('office-extrefs', 'forense', tmpl ? 'high' : 'medium', tmpl ? 'Plantilla remota adjunta (posible template injection)' : 'Recursos externos cargados automáticamente', `${danger.length} referencia(s): ${danger.slice(0, 3).map((d) => `${d.type} → ${d.target.slice(0, 80)}`).join(' · ')}`, { recommendation: 'No abras el documento con la red conectada; podría descargar contenido remoto o filtrar tu IP.' }),
        );
      }
    }

    /* ── Embeddings, ActiveX, miniatura ── */
    const emb = files.filter((n) => /\/(embeddings|activeX|ink)\//i.test(n) || /oleObject\d*\.bin$/i.test(n));
    if (emb.length) {
      groups.push({ id: 'office-emb', title: 'Objetos incrustados (OLE / ActiveX)', entries: emb.slice(0, 30).map((n) => ({ key: n.split('/').slice(-2).join('/'), value: formatBytes(sizeOf(n)) })) });
      findings.push(mk('office-embedded', 'forense', 'medium', `${emb.length} objeto(s) incrustado(s)`, 'El documento contiene objetos OLE/ActiveX que pueden alojar archivos o ejecutables.', { recommendation: 'Extrae y analiza cada objeto incrustado por separado.' }));
    }
    if (files.some((n) => /^docProps\/thumbnail\./i.test(n)))
      findings.push(mk('office-thumb', 'privacidad', 'low', 'Miniatura de la primera página', 'El archivo guarda una vista previa de la primera página que puede mostrar contenido ya borrado.'));
  }
  if (hasVba)
    findings.push(mk('office-vba', 'forense', 'high', 'Contiene macros VBA (vbaProject.bin)', 'Los documentos con macros son el vector más habitual de malware ofimático.', { recommendation: 'No habilites las macros salvo que confíes plenamente en el origen del archivo.' }));

  /* ── ODF ── */
  if (kind === 'odf') {
    const meta = await read('meta.xml');
    if (meta) {
      leakText += meta + '\n';
      const e = flattenXml(meta).filter((x) => !/document-statistic|^office:/i.test(x.key));
      if (e.length) groups.push({ id: 'odf-meta', title: 'Metadatos OpenDocument (meta.xml)', entries: e });
    }
    const content = (await read('content.xml')) ?? '';
    const ann = (content.match(/<office:annotation\b/g) ?? []).length;
    const tc = (content.match(/<text:changed-region\b/g) ?? []).length;
    const hid = (content.match(/table:display="false"|table:visibility="(?:collapse|filter)"/g) ?? []).length;
    if (ann) findings.push(mk('odf-ann', 'privacidad', 'medium', `${ann} comentario(s) en el documento`, 'Anotaciones de revisión incrustadas.'));
    if (tc) findings.push(mk('odf-tc', 'privacidad', 'high', 'Cambios rastreados sin resolver', `${tc} región(es) de cambios con historial recuperable.`));
    if (hid) findings.push(mk('odf-hid', 'privacidad', 'medium', 'Hojas / filas ocultas', `${hid} elemento(s) marcados como ocultos.`));
  }

  /* ── JAR / APK ── */
  const mf = await read('META-INF/MANIFEST.MF', 2_000_000);
  if (mf) {
    const e: MetaEntry[] = [];
    for (const line of mf.split(/\r?\n/).slice(0, 40)) {
      const m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
      if (m) e.push({ key: m[1], value: m[2].slice(0, 200), sensitive: isSensitiveKey(m[1]) });
      else if (!line.trim() && e.length) break;
    }
    if (e.length) groups.push({ id: 'jar-manifest', title: 'META-INF/MANIFEST.MF', entries: e });
  }

  /* ── Imágenes incrustadas con GPS ── */
  const media = files.filter((n) => /\.(jpe?g|tiff?)$/i.test(n) && /media|images|Pictures|res\//i.test(n)).slice(0, 12);
  const gpsHits: string[] = [];
  for (const m of media) {
    if (sizeOf(m) > 8_000_000) continue;
    try {
      const u8 = await zip.file(m)!.async('uint8array');
      const g = await exifr.gps(u8);
      if (g && isFinite(g.latitude) && isFinite(g.longitude)) gpsHits.push(`${m.split('/').pop()} (${g.latitude.toFixed(4)}, ${g.longitude.toFixed(4)})`);
    } catch {
      /* noop */
    }
  }
  if (gpsHits.length)
    findings.push(mk('zip-media-gps', 'privacidad', 'high', 'Imágenes incrustadas con ubicación GPS', `Dentro del paquete hay imágenes con coordenadas: ${gpsHits.join(', ')}.`, { recommendation: 'Limpia el EXIF de las imágenes antes de insertarlas en documentos.' }));

  /* ── Contenido del paquete ── */
  const zipComment = (zip as unknown as { comment?: string | null }).comment ?? '';
  let uncompressed = 0;
  let minT = Infinity;
  let maxT = -Infinity;
  const listing: MetaEntry[] = [];
  for (const n of files) {
    const sz = sizeOf(n);
    uncompressed += sz;
    const d = zip.files[n].date;
    if (d && !isNaN(d.getTime())) {
      minT = Math.min(minT, d.getTime());
      maxT = Math.max(maxT, d.getTime());
    }
    if (listing.length < 60) listing.push({ key: n, value: `${formatBytes(sz)}${d ? ' · ' + d.toISOString().slice(0, 19).replace('T', ' ') : ''}` });
  }
  const pkgEntries: MetaEntry[] = [{ key: 'Entradas', value: String(files.length) }, { key: 'Tamaño descomprimido', value: formatBytes(uncompressed) }];
  if (isFinite(minT)) pkgEntries.push({ key: 'Fecha más antigua (interna)', value: new Date(minT).toISOString() }, { key: 'Fecha más reciente (interna)', value: new Date(maxT).toISOString() });
  if (zipComment) pkgEntries.push({ key: 'Comentario del ZIP', value: zipComment.slice(0, 400), sensitive: true });
  groups.push({ id: 'zip-pkg', title: 'Contenido del paquete', entries: [...pkgEntries, ...listing] });
  if (zipComment) findings.push(mk('zip-comment', 'privacidad', 'low', 'Comentario oculto en el ZIP', zipComment.slice(0, 160)));

  if (b.length > 0 && uncompressed / b.length > 1000 && uncompressed > 100_000_000)
    findings.push(mk('zip-bomb', 'forense', 'high', 'Posible bomba de descompresión', `El contenido descomprimido (${formatBytes(uncompressed)}) es más de 1000× el tamaño del archivo.`));
  const traversal = names.filter((n) => /(^|\/)\.\.(\/|\\)|^\/|^[A-Za-z]:/.test(n));
  if (traversal.length) findings.push(mk('zip-slip', 'forense', 'high', 'Rutas de escape en el ZIP (Zip Slip)', `Entradas con rutas relativas peligrosas: ${traversal.slice(0, 3).join(', ')}.`));
  if (kind === 'zip' || kind === 'epub') {
    const execs = files.filter((n) => EXEC_NAMES.test(n));
    if (execs.length) findings.push(mk('zip-exec', 'forense', 'medium', `${execs.length} ejecutable(s) o script(s) dentro del archivo`, execs.slice(0, 6).join(', ')));
  }

  const leaks = leakText ? scanText(leakText) : [];
  return { groups, findings, label, exts, leaks };
}

/* ═════════════════════════ OLE2 (doc, xls, ppt, msg) ═════════════════════════ */

interface CfbEntry {
  name: string;
  type: number;
  start: number;
  size: number;
}

function readCfb(b: Uint8Array): { entries: CfbEntry[]; read: (e: CfbEntry) => Uint8Array } | null {
  if (b.length < 512) return null;
  const ss = 1 << u16le(b, 0x1e);
  const mss = 1 << u16le(b, 0x20);
  if ((ss !== 512 && ss !== 4096) || mss > 4096) return null;
  const numFat = u32le(b, 0x2c);
  const dirStart = u32le(b, 0x30);
  const miniCutoff = u32le(b, 0x38);
  const miniFatStart = u32le(b, 0x3c);
  const difStart = u32le(b, 0x44);
  const numDif = u32le(b, 0x48);
  const MAXREG = 0xfffffffa;
  const secOff = (s: number) => (s + 1) * ss;
  const fatSecs: number[] = [];
  for (let i = 0; i < 109 && fatSecs.length < numFat; i++) {
    const s = u32le(b, 0x4c + i * 4);
    if (s < MAXREG) fatSecs.push(s);
  }
  let d = difStart;
  for (let k = 0; k < numDif && d < MAXREG && fatSecs.length < numFat; k++) {
    const o = secOff(d);
    if (o + ss > b.length) break;
    for (let i = 0; i < ss / 4 - 1 && fatSecs.length < numFat; i++) {
      const s = u32le(b, o + i * 4);
      if (s < MAXREG) fatSecs.push(s);
    }
    d = u32le(b, o + ss - 4);
  }
  const fat: number[] = [];
  for (const s of fatSecs) {
    const o = secOff(s);
    if (o + ss > b.length) break;
    for (let i = 0; i < ss / 4; i++) fat.push(u32le(b, o + i * 4));
  }
  const chain = (start: number, table: number[]) => {
    const out: number[] = [];
    let s = start;
    const lim = table.length + 2;
    while (s < MAXREG && out.length < lim) {
      out.push(s);
      s = table[s] ?? 0xfffffffe;
    }
    return out;
  };
  const readChain = (start: number) => {
    const secs = chain(start, fat);
    const out = new Uint8Array(secs.length * ss);
    let n = 0;
    for (const s of secs) {
      const o = secOff(s);
      if (o >= b.length) break;
      out.set(b.subarray(o, Math.min(b.length, o + ss)), n);
      n += ss;
    }
    return out;
  };
  const dir = readChain(dirStart);
  const entries: CfbEntry[] = [];
  for (let o = 0; o + 128 <= dir.length && entries.length < 2000; o += 128) {
    const type = dir[o + 66];
    if (type === 0) continue;
    const nl = Math.max(0, Math.min(64, u16le(dir, o + 64)) - 2);
    entries.push({ name: decodeUtf16(dir, o, o + nl, true), type, start: u32le(dir, o + 116), size: u32le(dir, o + 120) });
  }
  const root = entries.find((e) => e.type === 5);
  const miniStream = root ? readChain(root.start) : new Uint8Array(0);
  const miniFatBytes = readChain(miniFatStart);
  const miniFat: number[] = [];
  for (let i = 0; i + 4 <= miniFatBytes.length; i += 4) miniFat.push(u32le(miniFatBytes, i));
  const read = (e: CfbEntry): Uint8Array => {
    if (e.size === 0 || e.size > 50_000_000) return new Uint8Array(0);
    if (e.size < miniCutoff) {
      const secs = chain(e.start, miniFat);
      const out = new Uint8Array(secs.length * mss);
      let n = 0;
      for (const s of secs) {
        const o = s * mss;
        if (o >= miniStream.length) break;
        out.set(miniStream.subarray(o, Math.min(miniStream.length, o + mss)), n);
        n += mss;
      }
      return out.subarray(0, e.size);
    }
    return readChain(e.start).subarray(0, e.size);
  };
  return { entries, read };
}

function filetimeToIso(lo: number, hi: number): string | null {
  const ms = (hi * 4294967296 + lo) / 10000 - 11644473600000;
  if (!isFinite(ms) || ms < -2.2e12 || ms > 4.1e12) return null;
  return new Date(ms).toISOString();
}

function parsePropSet(d: Uint8Array): Map<number, string> {
  const out = new Map<number, string>();
  if (d.length < 48) return out;
  const off = u32le(d, 44);
  if (off + 8 > d.length) return out;
  const count = Math.min(u32le(d, off + 4), 64);
  for (let i = 0; i < count; i++) {
    const pid = u32le(d, off + 8 + i * 8);
    const po = off + u32le(d, off + 12 + i * 8);
    if (po + 8 > d.length) continue;
    const vt = u16le(d, po);
    if (vt === 30) {
      const len = u32le(d, po + 4);
      if (len > 0 && len < 4096 && po + 8 + len <= d.length) out.set(pid, decodeLatin1(d, po + 8, po + 8 + len).replace(/\u0000+$/g, '').trim());
    } else if (vt === 31) {
      const len = u32le(d, po + 4);
      if (len > 0 && len < 4096 && po + 8 + len * 2 <= d.length) out.set(pid, decodeUtf16(d, po + 8, po + 8 + len * 2, true).replace(/\u0000+$/g, '').trim());
    } else if (vt === 64 && po + 12 <= d.length) {
      const iso = filetimeToIso(u32le(d, po + 4), u32le(d, po + 8));
      if (iso && !iso.startsWith('1601')) out.set(pid, iso);
    } else if (vt === 3 && po + 8 <= d.length) out.set(pid, String(u32le(d, po + 4) | 0));
  }
  return out;
}

export function extractOle(b: Uint8Array): Extraction {
  const groups: MetaGroup[] = [];
  const findings: Finding[] = [];
  const cfb = readCfb(b);
  if (!cfb) return { groups, findings: [mk('ole-bad', 'forense', 'medium', 'Contenedor OLE2 dañado', 'No se pudo interpretar la estructura OLE2; el archivo puede estar corrupto o manipulado.')] };
  const { entries, read } = cfb;
  const names = entries.map((e) => e.name);
  let label = 'Documento OLE2';
  let exts: string[] | undefined;
  if (names.includes('WordDocument')) {
    label = 'Documento Word clásico (.doc)';
    exts = ['doc', 'dot'];
  } else if (names.includes('Workbook') || names.includes('Book')) {
    label = 'Hoja Excel clásica (.xls)';
    exts = ['xls', 'xlt'];
  } else if (names.includes('PowerPoint Document')) {
    label = 'Presentación PowerPoint clásica (.ppt)';
    exts = ['ppt', 'pps', 'pot'];
  } else if (names.some((n) => n.startsWith('__properties_version1.0'))) {
    label = 'Mensaje de Outlook (.msg)';
    exts = ['msg'];
  }

  const leakParts: string[] = [];
  const sum = entries.find((e) => e.name === '\u0005SummaryInformation');
  if (sum) {
    const p = parsePropSet(read(sum));
    const map: [number, string][] = [
      [2, 'Título'], [3, 'Asunto'], [4, 'Autor'], [5, 'Palabras clave'], [6, 'Comentarios'], [7, 'Plantilla'],
      [8, 'Último autor'], [9, 'Nº de revisión'], [11, 'Última impresión'], [12, 'Fecha de creación'], [13, 'Último guardado'], [18, 'Aplicación'],
    ];
    const e: MetaEntry[] = [];
    for (const [pid, key] of map) {
      const v = p.get(pid);
      if (v) {
        e.push({ key, value: v, sensitive: !/revisi|fecha|impresi|guardado/i.test(key) });
        leakParts.push(v);
      }
    }
    if (e.length) groups.push({ id: 'ole-summary', title: 'SummaryInformation (propiedades del documento)', entries: e });
    const c = p.get(12);
    const m = p.get(13);
    if (c && m && Date.parse(m) < Date.parse(c)) findings.push(mk('ole-dates', 'forense', 'medium', 'Fechas incoherentes', 'La fecha de último guardado es anterior a la de creación.'));
  }
  const dsum = entries.find((e) => e.name === '\u0005DocumentSummaryInformation');
  if (dsum) {
    const p = parsePropSet(read(dsum));
    const e: MetaEntry[] = [];
    const map: [number, string][] = [[2, 'Categoría'], [14, 'Responsable (Manager)'], [15, 'Empresa']];
    for (const [pid, key] of map) {
      const v = p.get(pid);
      if (v) {
        e.push({ key, value: v, sensitive: true });
        leakParts.push(v);
      }
    }
    if (e.length) groups.push({ id: 'ole-docsum', title: 'DocumentSummaryInformation', entries: e });
  }
  groups.push({
    id: 'ole-struct',
    title: 'Estructura OLE2 (streams y storages)',
    entries: entries.slice(0, 80).map((e) => ({ key: e.name.replace(/[\u0000-\u001f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`), value: `${e.type === 1 ? 'storage' : e.type === 5 ? 'raíz' : formatBytes(e.size)}` })),
  });

  if (names.some((n) => /^(VBA|_VBA_PROJECT|Macros|_VBA_PROJECT_CUR|PROJECTwm|PROJECT)$/i.test(n)))
    findings.push(mk('ole-vba', 'forense', 'high', 'Contiene macros VBA', 'Se encontró un proyecto VBA dentro del contenedor OLE2. Es el vector clásico de malware en .doc/.xls.', { recommendation: 'No habilites las macros salvo que confíes plenamente en el origen.' }));
  if (names.some((n) => /ObjectPool|Ole10Native|^Package$|EmbeddedObject/i.test(n)))
    findings.push(mk('ole-embedded', 'forense', 'medium', 'Objetos incrustados en el documento', 'Hay objetos OLE/Package que pueden contener ejecutables o archivos adjuntos.'));

  const leaks = leakParts.length ? scanText(leakParts.join('\n')) : [];
  return { groups, findings, label, exts, leaks };
}
