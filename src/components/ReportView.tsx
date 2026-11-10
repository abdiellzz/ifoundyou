import { useState } from 'react';
import { Braces, Clock, Copy, Download, FileText, Lightbulb, Printer, Eraser, MapPin, Check, Flag, Crosshair } from 'lucide-react';
import type { AnalysisResult, Severity } from '../lib/types';
import { buildRecommendations, buildSummary, exportJson, reportHtml, VERDICT_META } from '../lib/report';
import { cleanJpeg, cleanPng } from '../lib/cleaner';
import { download, formatBytes, formatDate } from '../lib/utils';
import { Card, CopyButton, FindingCard, Gauge, SectionTitle, SEV } from './ui';
import { cn } from '../utils/cn';

function printHtml(html: string) {
  const iframe = document.createElement('iframe');
  iframe.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  document.body.appendChild(iframe);
  const doc = iframe.contentDocument;
  if (!doc) return;
  doc.open();
  doc.write(html);
  doc.close();
  setTimeout(() => {
    iframe.contentWindow?.focus();
    iframe.contentWindow?.print();
    setTimeout(() => iframe.remove(), 4000);
  }, 350);
}

export default function ReportView({ r, onTab, flags = [] }: { r: AnalysisResult; flags?: string[]; onTab: (t: 'resolver' | 'forense' | 'metadatos') => void }) {
  const v = VERDICT_META[r.verdict];
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const summary = buildSummary(r);
  const recs = buildRecommendations(r);
  const base = r.name.replace(/\.[^.]+$/, '');
  const forense = r.findings.filter((f) => f.axis === 'forense' && f.severity !== 'info');
  const priv = r.findings.filter((f) => f.axis === 'privacidad' && f.severity !== 'info');
  const sensitive = r.metadata.flatMap((g) => g.entries.filter((e) => e.sensitive && !/Ref$/.test(e.key)).map((e) => ({ g: g.title, ...e })));
  const counts = (['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => ({ s, n: r.findings.filter((f) => f.severity === s).length }));
  const LIM = 4;

  const clean = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const bytes = new Uint8Array(await r.file.arrayBuffer());
      const out = r.cleanable === 'jpeg' ? await cleanJpeg(bytes) : cleanPng(bytes);
      if (!out) throw new Error('No se pudo reescribir el archivo.');
      const ext = r.cleanable === 'jpeg' ? 'jpg' : 'png';
      download(`${base}_limpio.${ext}`, new Blob([out as BlobPart], { type: r.cleanable === 'jpeg' ? 'image/jpeg' : 'image/png' }));
      setMsg(`Copia limpia generada: ${formatBytes(out.length)} (se eliminaron ${formatBytes(Math.max(0, r.size - out.length))} de metadatos y datos añadidos).`);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Error al limpiar el archivo.');
    }
    setBusy(false);
  };

  const btn = 'inline-flex items-center justify-center gap-2 rounded-lg border px-3.5 py-2 text-sm font-medium transition disabled:opacity-50';

  return (
    <div className="space-y-6">
      {flags.length > 0 && (
        <section className="flex flex-wrap items-center gap-4 rounded-2xl border-2 border-emerald-400/50 bg-emerald-400/[0.07] p-5">
          <Flag className="h-6 w-6 shrink-0 text-emerald-300" />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-bold uppercase tracking-[0.2em] text-emerald-300/80">Mensaje oculto recuperado</div>
            <code className="mt-1 block break-all font-mono text-lg font-semibold text-emerald-200 sm:text-xl">{flags.join(' · ')}</code>
          </div>
          <button type="button" onClick={() => onTab('resolver')} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/50 px-3 py-2 text-xs font-semibold text-emerald-100 hover:bg-emerald-400/15">
            <Crosshair className="h-3.5 w-3.5" /> Ver cómo se resolvió
          </button>
        </section>
      )}

      {/* Veredicto */}
      <section className={cn('relative overflow-hidden rounded-2xl border p-6 sm:p-8', v.border)} style={{ background: `radial-gradient(900px 300px at 0% 0%, ${v.hex}1f, transparent 60%), #0b0f16` }}>
        <div className="grid items-center gap-8 lg:grid-cols-[1.3fr_auto]">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500">Informe final · veredicto</div>
            <h2 className="mt-2 text-5xl font-extrabold tracking-tight sm:text-6xl" style={{ color: v.hex, textShadow: `0 0 40px ${v.hex}55` }}>
              {v.label}
            </h2>
            <p className="mt-2 text-lg text-slate-200">{v.headline}</p>
            <p className="mt-1 truncate font-mono text-xs text-slate-500" title={r.name}>{r.name}</p>
            <div className="mt-5 flex flex-wrap gap-2">
              {counts.map(({ s, n }) => (
                <span key={s} className={cn('inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs', n ? [SEV[s].bg, SEV[s].border, SEV[s].text] : 'border-slate-800 text-slate-600')}>
                  <span className="font-mono text-base font-bold">{n}</span>
                  {s === 'critical' ? 'críticos' : s === 'high' ? 'altos' : s === 'medium' ? 'medios' : 'bajos'}
                </span>
              ))}
            </div>
          </div>
          <div className="flex items-center justify-center gap-6 sm:gap-10">
            <Gauge value={r.scores.forense} label="Riesgo forense" sub="integridad y seguridad" />
            <Gauge value={r.scores.privacidad} label="Exposición" sub="metadatos y privacidad" />
          </div>
        </div>
      </section>

      {/* Resumen + acciones */}
      <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <Card>
          <SectionTitle icon={<FileText className="h-4 w-4" />} title="Resumen ejecutivo" />
          <div className="space-y-3 p-5 text-[14px] leading-relaxed text-slate-300">
            {summary.map((p, i) => (
              <p key={i} className={cn(p.startsWith('⚠') && 'rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-red-200')}>
                {p}
              </p>
            ))}
          </div>
        </Card>
        <Card>
          <SectionTitle icon={<Download className="h-4 w-4" />} title="Llévate el resultado" />
          <div className="grid gap-2.5 p-5">
            {r.cleanable && (
              <button type="button" disabled={busy} onClick={clean} className={cn(btn, 'border-emerald-400/50 bg-emerald-400/15 text-emerald-100 hover:bg-emerald-400/25')}>
                <Eraser className="h-4 w-4" /> {busy ? 'Limpiando…' : 'Descargar copia limpia (sin metadatos)'}
              </button>
            )}
            <button type="button" onClick={() => download(`foundyou_${base}.html`, reportHtml(r), 'text/html')} className={cn(btn, 'border-cyan-400/50 bg-cyan-400/15 text-cyan-100 hover:bg-cyan-400/25')}>
              <FileText className="h-4 w-4" /> Descargar informe (HTML)
            </button>
            <button type="button" onClick={() => printHtml(reportHtml(r))} className={cn(btn, 'border-slate-700 text-slate-200 hover:border-cyan-400/50')}>
              <Printer className="h-4 w-4" /> Imprimir / guardar como PDF
            </button>
            <button type="button" onClick={() => download(`foundyou_${base}.json`, exportJson(r), 'application/json')} className={cn(btn, 'border-slate-700 text-slate-200 hover:border-cyan-400/50')}>
              <Braces className="h-4 w-4" /> Exportar datos (JSON)
            </button>
            <CopyBtn text={summary.join('\n\n') + `\n\nSHA-256: ${r.hashes.sha256}`} className={btn} />
            {msg && (
              <p className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-xs leading-relaxed text-emerald-200">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {msg}
              </p>
            )}
          </div>
        </Card>
      </div>

      {/* Hallazgos principales */}
      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <SectionTitle
            title="Análisis forense · lo más importante"
            right={<button type="button" onClick={() => onTab('forense')} className="text-xs font-medium text-cyan-300 hover:underline">Ver herramienta →</button>}
          />
          <div className="space-y-3 p-5">
            {forense.length === 0 && <p className="text-sm text-slate-400">Sin anomalías forenses relevantes.</p>}
            {(showAll ? forense : forense.slice(0, LIM)).map((f) => (
              <FindingCard key={f.id} f={f} />
            ))}
          </div>
        </Card>
        <Card>
          <SectionTitle
            title="Metadatos ocultos · lo más importante"
            right={<button type="button" onClick={() => onTab('metadatos')} className="text-xs font-medium text-cyan-300 hover:underline">Ver herramienta →</button>}
          />
          <div className="space-y-3 p-5">
            {priv.length === 0 && <p className="text-sm text-slate-400">Sin exposición de privacidad relevante.</p>}
            {(showAll ? priv : priv.slice(0, LIM)).map((f) => (
              <FindingCard key={f.id} f={f} />
            ))}
          </div>
        </Card>
      </div>
      {(forense.length > LIM || priv.length > LIM) && (
        <div className="-mt-2 text-center">
          <button type="button" onClick={() => setShowAll(!showAll)} className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-300 hover:border-cyan-400/50">
            {showAll ? 'Mostrar solo los principales' : 'Mostrar todos los hallazgos'}
          </button>
        </div>
      )}

      {/* Datos sensibles + ubicación */}
      {(sensitive.length > 0 || r.gps) && (
        <Card>
          <SectionTitle icon={<MapPin className="h-4 w-4" />} title="Datos sensibles que se llevaría quien reciba este archivo" />
          <div className="divide-y divide-slate-800/60">
            {r.gps && (
              <div className="grid gap-1 px-5 py-2.5 sm:grid-cols-[220px_1fr]">
                <span className="font-mono text-[12px] text-red-300">Ubicación GPS</span>
                <span className="font-mono text-[12px] text-red-200">{r.gps.lat.toFixed(6)}, {r.gps.lon.toFixed(6)}</span>
              </div>
            )}
            {sensitive.slice(0, 14).map((s, i) => (
              <div key={i} className="grid gap-1 px-5 py-2.5 sm:grid-cols-[220px_1fr]">
                <div>
                  <div className="break-all font-mono text-[12px] text-slate-400">{s.key}</div>
                  <div className="text-[10px] text-slate-600">{s.g}</div>
                </div>
                <div className="whitespace-pre-wrap break-words font-mono text-[12px] text-amber-100">{s.value}</div>
              </div>
            ))}
          </div>
          {sensitive.length > 14 && (
            <button type="button" onClick={() => onTab('metadatos')} className="w-full border-t border-slate-800/70 px-5 py-3 text-left text-xs font-medium text-cyan-300 hover:bg-slate-800/30">
              +{sensitive.length - 14} campos sensibles más → verlos en Metadatos ocultos
            </button>
          )}
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recomendaciones */}
        <Card>
          <SectionTitle icon={<Lightbulb className="h-4 w-4" />} title="Qué hacer ahora" />
          <ol className="space-y-3 p-5">
            {recs.map((x, i) => (
              <li key={i} className="flex gap-3 text-sm leading-relaxed text-slate-300">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyan-400/15 font-mono text-xs font-bold text-cyan-300">{i + 1}</span>
                <span>{x}</span>
              </li>
            ))}
          </ol>
        </Card>

        {/* Timeline */}
        <Card>
          <SectionTitle icon={<Clock className="h-4 w-4" />} title="Línea temporal" hint="Fechas encontradas dentro del archivo, ordenadas cronológicamente." />
          <div className="max-h-[360px] overflow-auto p-5">
            {r.timeline.length === 0 ? (
              <p className="text-sm text-slate-500">No se hallaron fechas en los metadatos.</p>
            ) : (
              <ol className="relative space-y-4 border-l border-slate-800 pl-5">
                {r.timeline.map((t, i) => (
                  <li key={i} className="relative">
                    <span className={cn('absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full ring-4 ring-[#0b0f16]', t.source === 'Sistema de archivos' ? 'bg-slate-500' : 'bg-cyan-400')} />
                    <div className="font-mono text-xs text-cyan-200">{formatDate(t.time)}</div>
                    <div className="text-sm text-slate-200">{t.label}</div>
                    <div className="text-[11px] text-slate-500">{t.source}</div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </Card>
      </div>

      <Card className="p-5">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500">SHA-256</span>
          <code className="min-w-0 flex-1 break-all font-mono text-xs text-cyan-100/90">{r.hashes.sha256}</code>
          <CopyButton text={r.hashes.sha256} />
        </div>
        <p className="mt-4 text-[11px] leading-relaxed text-slate-500">
          Informe generado en tu navegador: el archivo no se ha enviado a ningún servidor. Los resultados son indicios técnicos de un análisis estático y no constituyen una pericia forense certificada. La ausencia de hallazgos no garantiza que un archivo sea seguro.
        </p>
      </Card>
    </div>
  );
}

function CopyBtn({ text, className }: { text: string; className: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      type="button"
      className={cn(className, 'border-slate-700 text-slate-200 hover:border-cyan-400/50')}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
        } catch {
          /* noop */
        }
        setOk(true);
        setTimeout(() => setOk(false), 1500);
      }}
    >
      {ok ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />} {ok ? 'Resumen copiado' : 'Copiar resumen'}
    </button>
  );
}
