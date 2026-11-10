import type { AnalysisResult, Finding, Severity, Verdict } from './types';
import { formatBytes, formatDate } from './utils';

export const VERDICT_META: Record<Verdict, { label: string; headline: string; hex: string; text: string; bg: string; border: string }> = {
  limpio: {
    label: 'Limpio',
    headline: 'No se detectaron señales relevantes',
    hex: '#34d399',
    text: 'text-emerald-300',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/40',
  },
  precaucion: {
    label: 'Precaución',
    headline: 'Hay datos que conviene revisar',
    hex: '#38bdf8',
    text: 'text-sky-300',
    bg: 'bg-sky-500/10',
    border: 'border-sky-500/40',
  },
  sospechoso: {
    label: 'Sospechoso',
    headline: 'Contiene elementos que no deberían estar ahí',
    hex: '#fb923c',
    text: 'text-orange-300',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/40',
  },
  peligroso: {
    label: 'Peligroso',
    headline: 'Se detectaron indicadores graves',
    hex: '#f87171',
    text: 'text-red-300',
    bg: 'bg-red-500/10',
    border: 'border-red-500/40',
  },
};

export const SEV_LABEL: Record<Severity, string> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Medio',
  low: 'Bajo',
  info: 'Info',
};

const AXIS_LABEL = { forense: 'Forense', privacidad: 'Metadatos / privacidad' } as const;

export function buildSummary(r: AnalysisResult): string[] {
  const out: string[] = [];
  const v = VERDICT_META[r.verdict];
  out.push(
    `«${r.name}» es un archivo ${r.typeLabel} de ${formatBytes(r.size)}${
      r.extMismatch ? `, aunque su extensión (.${r.ext || '—'}) no coincide con su contenido real` : ''
    }. Veredicto global: ${v.label.toUpperCase()} — ${v.headline.toLowerCase()}.`,
  );
  const ff = r.findings.filter((f) => f.axis === 'forense' && f.severity !== 'info');
  const fp = r.findings.filter((f) => f.axis === 'privacidad' && f.severity !== 'info');
  if (ff.length)
    out.push(
      `Análisis forense: ${ff.length} hallazgo(s) (${ff.filter((f) => f.severity === 'critical' || f.severity === 'high').length} de gravedad alta o crítica). Lo más relevante: ${ff
        .slice(0, 3)
        .map((f) => f.title.toLowerCase())
        .join('; ')}.`,
    );
  else out.push('Análisis forense: no se encontraron anomalías estructurales, contenido incrustado ni datos ocultos tras el final del archivo.');
  if (fp.length)
    out.push(
      `Metadatos ocultos: ${fp.length} exposición(es) de información (${fp.filter((f) => f.severity === 'critical' || f.severity === 'high').length} de gravedad alta o crítica). Destacan: ${fp
        .slice(0, 3)
        .map((f) => f.title.toLowerCase())
        .join('; ')}.`,
    );
  else out.push('Metadatos ocultos: no se hallaron datos personales, de ubicación ni de dispositivo en los metadatos del archivo.');
  if (r.gps)
    out.push(`⚠ El archivo puede situarse geográficamente en ${r.gps.lat.toFixed(5)}, ${r.gps.lon.toFixed(5)}.`);
  if (r.verdict === 'limpio')
    out.push('Recuerda: un análisis estático no puede garantizar la ausencia total de riesgo. Si el origen del archivo es dudoso, ábrelo siempre en un entorno aislado.');
  return out;
}

export function buildRecommendations(r: AnalysisResult): string[] {
  const set = new Set<string>();
  for (const f of r.findings) if (f.recommendation && f.severity !== 'info') set.add(f.recommendation);
  if (r.verdict === 'peligroso' || r.verdict === 'sospechoso')
    set.add('Conserva el hash SHA-256 y consúltalo en un servicio de reputación (p. ej. VirusTotal) sin subir el archivo si es confidencial.');
  if (set.size === 0) set.add('No se requieren acciones. Verifica el hash SHA-256 si necesitas comprobar la integridad del archivo en el futuro.');
  return [...set];
}

export function exportJson(r: AnalysisResult): string {
  const { file: _file, ...rest } = r;
  void _file;
  const clean = {
    ...rest,
    strings: { total: r.strings.total, interesting: r.strings.interesting },
    entropy: { overall: r.entropy.overall, blockSize: r.entropy.blockSize, blocks: r.entropy.blocks.map((x) => +x.toFixed(3)) },
    generator: 'FoundYou · Te encontré',
    analyzedAtIso: new Date(r.analyzedAt).toISOString(),
  };
  return JSON.stringify(clean, null, 2);
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const SEV_COLOR: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#0284c7',
  info: '#64748b',
};

export function reportHtml(r: AnalysisResult): string {
  const v = VERDICT_META[r.verdict];
  const findings = (list: Finding[]) =>
    list.length
      ? list
          .map(
            (f) =>
              `<div class="f" style="border-left-color:${SEV_COLOR[f.severity]}"><div class="ft"><span class="sev" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span> <b>${esc(f.title)}</b>${
                f.offset !== undefined ? ` <code>@0x${f.offset.toString(16).toUpperCase()}</code>` : ''
              }</div><p>${esc(f.detail)}</p></div>`,
          )
          .join('')
      : '<p class="muted">Sin hallazgos en esta categoría.</p>';
  const sensitive = r.metadata.flatMap((g) => g.entries.filter((e) => e.sensitive).map((e) => ({ g: g.title, ...e })));
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Informe FoundYou — ${esc(r.name)}</title>
<style>
*{box-sizing:border-box}body{font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;margin:0;padding:32px;max-width:900px;margin:auto}
h1{font-size:26px;margin:0}h2{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0;text-transform:uppercase;letter-spacing:.06em;color:#334155}
.brand{display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid #0891b2;padding-bottom:12px;margin-bottom:20px}
.brand b{font-size:20px}.brand span{color:#0891b2}.muted{color:#64748b}
.verdict{border:2px solid ${v.hex};border-radius:12px;padding:16px 20px;display:flex;gap:24px;align-items:center;margin:16px 0}
.verdict .big{font-size:28px;font-weight:800;color:${v.hex}}
.scores{display:flex;gap:16px;margin-left:auto}.score{text-align:center}.score b{font-size:26px;display:block}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;vertical-align:top}th{background:#f1f5f9;width:30%}
code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.f{border-left:4px solid;background:#f8fafc;padding:8px 12px;margin:8px 0;border-radius:0 6px 6px 0;break-inside:avoid}.f p{margin:4px 0 0;color:#334155}
.sev{color:#fff;font-size:10px;padding:2px 7px;border-radius:99px;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
ul{padding-left:20px}li{margin:4px 0}footer{margin-top:36px;font-size:11px;color:#64748b;border-top:1px solid #e2e8f0;padding-top:10px}
@media print{body{padding:0}}
</style></head><body>
<div class="brand"><div><b>Found<span>You</span></b> <span class="muted" style="color:#64748b">· Te encontré — informe forense y de metadatos ocultos</span></div><div class="muted">${esc(formatDate(r.analyzedAt))}</div></div>
<h1>${esc(r.name)}</h1>
<div class="verdict"><div><div class="muted">Veredicto</div><div class="big">${v.label}</div><div class="muted">${esc(v.headline)}</div></div>
<div class="scores"><div class="score"><b>${r.scores.forense}</b>Riesgo forense</div><div class="score"><b>${r.scores.privacidad}</b>Exposición de privacidad</div></div></div>
${buildSummary(r).map((p) => `<p>${esc(p)}</p>`).join('')}
<h2>Identificación</h2>
<table>
<tr><th>Tipo real detectado</th><td>${esc(r.typeLabel)}${r.type ? ` <span class="muted">(${esc(r.type.mime)})</span>` : ''}</td></tr>
<tr><th>Extensión declarada</th><td>.${esc(r.ext || '—')} ${r.extMismatch ? '<b style="color:#dc2626">— NO coincide con el contenido</b>' : '— coincide'}</td></tr>
<tr><th>Tamaño</th><td>${formatBytes(r.size)} (${r.size.toLocaleString('es-ES')} bytes)</td></tr>
<tr><th>Última modificación (SO)</th><td>${esc(formatDate(r.lastModified))}</td></tr>
<tr><th>Entropía global</th><td>${r.entropy.overall.toFixed(3)} / 8</td></tr>
<tr><th>MD5</th><td class="mono">${esc(r.hashes.md5)}</td></tr>
<tr><th>SHA-1</th><td class="mono">${esc(r.hashes.sha1)}</td></tr>
<tr><th>SHA-256</th><td class="mono">${esc(r.hashes.sha256)}</td></tr>
<tr><th>SHA-512</th><td class="mono">${esc(r.hashes.sha512)}</td></tr>
</table>
<h2>Hallazgos forenses</h2>${findings(r.findings.filter((f) => f.axis === 'forense'))}
<h2>Hallazgos de metadatos y privacidad</h2>${findings(r.findings.filter((f) => f.axis === 'privacidad'))}
${
  sensitive.length
    ? `<h2>Datos sensibles encontrados</h2><table>${sensitive
        .slice(0, 80)
        .map((s) => `<tr><th>${esc(s.key)}<br><span class="muted" style="font-weight:400">${esc(s.g)}</span></th><td class="mono">${esc(s.value)}</td></tr>`)
        .join('')}</table>`
    : ''
}
${
  r.gps
    ? `<h2>Ubicación</h2><p><b>${r.gps.lat.toFixed(6)}, ${r.gps.lon.toFixed(6)}</b> — <a href="https://www.openstreetmap.org/?mlat=${r.gps.lat}&mlon=${r.gps.lon}#map=16/${r.gps.lat}/${r.gps.lon}">ver en mapa</a></p>`
    : ''
}
${
  r.timeline.length
    ? `<h2>Línea temporal</h2><table>${r.timeline.map((t) => `<tr><th>${esc(formatDate(t.time))}</th><td>${esc(t.label)} <span class="muted">· ${esc(t.source)}</span></td></tr>`).join('')}</table>`
    : ''
}
<h2>Recomendaciones</h2><ul>${buildRecommendations(r).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
<footer>Generado por FoundYou en el navegador del usuario; el archivo no fue enviado a ningún servidor. Los resultados son indicios técnicos de un análisis estático y no constituyen una pericia forense certificada.</footer>
</body></html>`;
}

export { AXIS_LABEL };
