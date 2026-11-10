import { useMemo, useState } from 'react';
import { ChevronDown, Eye, EyeOff, ExternalLink, EyeClosed, MapPin, Search } from 'lucide-react';
import type { AnalysisResult } from '../lib/types';
import { Card, EmptyOk, FindingCard, SectionTitle } from './ui';
import { cn } from '../utils/cn';

export default function MetadataView({ r }: { r: AnalysisResult }) {
  const [q, setQ] = useState('');
  const [onlySens, setOnlySens] = useState(false);
  const [map, setMap] = useState(false);
  const priv = r.findings.filter((f) => f.axis === 'privacidad');
  const total = r.metadata.reduce((a, g) => a + g.entries.length, 0);
  const sens = r.metadata.reduce((a, g) => a + g.entries.filter((e) => e.sensitive).length, 0);
  const ql = q.trim().toLowerCase();

  const groups = useMemo(
    () =>
      r.metadata
        .map((g) => ({
          ...g,
          shown: g.entries.filter((e) => (!onlySens || e.sensitive) && (!ql || e.key.toLowerCase().includes(ql) || e.value.toLowerCase().includes(ql) || g.title.toLowerCase().includes(ql))),
        }))
        .filter((g) => g.shown.length > 0),
    [r, ql, onlySens],
  );

  const g = r.gps;
  const d = 0.008;

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-3">
        <Card className="p-4">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Campos de metadatos</div>
          <div className="mt-1 font-mono text-2xl font-semibold text-slate-50">{total}</div>
          <div className="text-xs text-slate-400">en {r.metadata.length} bloque(s)</div>
        </Card>
        <Card className={cn('p-4', sens > 0 && 'border-amber-400/40')}>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Campos sensibles</div>
          <div className={cn('mt-1 font-mono text-2xl font-semibold', sens ? 'text-amber-300' : 'text-emerald-300')}>{sens}</div>
          <div className="text-xs text-slate-400">autor, equipo, ubicación, software…</div>
        </Card>
        <Card className={cn('p-4', g && 'border-red-500/50 bg-red-500/5')}>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Geolocalización</div>
          <div className={cn('mt-1 text-2xl font-semibold', g ? 'text-red-300' : 'text-emerald-300')}>{g ? 'Presente' : 'No hay'}</div>
          <div className="truncate font-mono text-xs text-slate-400">{g ? `${g.lat.toFixed(5)}, ${g.lon.toFixed(5)}` : 'sin coordenadas GPS'}</div>
        </Card>
      </div>

      {g && (
        <Card className="border-red-500/40">
          <SectionTitle icon={<MapPin className="h-4 w-4" />} title="Este archivo revela dónde estuvo" hint="Las coordenadas están incrustadas en los metadatos. Cualquiera que reciba el archivo puede localizarlas." />
          <div className="grid gap-4 p-5 md:grid-cols-[1fr_1.4fr]">
            <div className="space-y-3">
              <div className="font-mono text-lg text-red-200">{g.lat.toFixed(6)}, {g.lon.toFixed(6)}</div>
              <div className="flex flex-wrap gap-2">
                <a href={`https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=17/${g.lat}/${g.lon}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-cyan-400/60">
                  <ExternalLink className="h-3.5 w-3.5" /> OpenStreetMap
                </a>
                <a href={`https://www.google.com/maps?q=${g.lat},${g.lon}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-cyan-400/60">
                  <ExternalLink className="h-3.5 w-3.5" /> Google Maps
                </a>
              </div>
              <p className="text-xs leading-relaxed text-slate-500">Para preservar tu privacidad, el mapa solo se carga si pulsas el botón (se conectará a openstreetmap.org).</p>
            </div>
            <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
              {map ? (
                <iframe title="Mapa" className="h-56 w-full" src={`https://www.openstreetmap.org/export/embed.html?bbox=${g.lon - d * 1.6}%2C${g.lat - d}%2C${g.lon + d * 1.6}%2C${g.lat + d}&layer=mapnik&marker=${g.lat}%2C${g.lon}`} />
              ) : (
                <button type="button" onClick={() => setMap(true)} className="flex h-56 w-full flex-col items-center justify-center gap-2 text-sm text-slate-300 hover:bg-slate-800/50">
                  <MapPin className="h-6 w-6 text-red-400" />
                  Mostrar mapa de ubicación
                </button>
              )}
            </div>
          </div>
        </Card>
      )}

      <Card>
        <SectionTitle icon={<EyeClosed className="h-4 w-4" />} title="Exposición de privacidad" hint="Lo que este archivo cuenta de ti sin que lo veas: quién lo hizo, con qué equipo, desde dónde y qué se editó." right={<span className="rounded-full bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">{priv.length}</span>} />
        <div className="space-y-3 p-5">
          {priv.length ? priv.map((f) => <FindingCard key={f.id} f={f} />) : <EmptyOk><b>Sin exposición relevante.</b> No se encontraron datos personales, de dispositivo ni de ubicación en los metadatos.</EmptyOk>}
        </div>
      </Card>

      <Card>
        <SectionTitle
          icon={<Eye className="h-4 w-4" />}
          title="Todos los metadatos extraídos"
          hint="Los campos marcados con el ojo ámbar se consideran sensibles."
          right={
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
                <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filtrar…" className="w-40 rounded-lg border border-slate-800 bg-slate-900/70 py-1.5 pl-8 pr-2 text-xs text-slate-200 placeholder:text-slate-600" />
              </div>
              <button type="button" onClick={() => setOnlySens(!onlySens)} className={cn('inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium', onlySens ? 'border-amber-400/60 bg-amber-400/10 text-amber-200' : 'border-slate-700 text-slate-400 hover:text-slate-200')}>
                {onlySens ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />} Solo sensibles
              </button>
            </div>
          }
        />
        <div className="space-y-3 p-5">
          {groups.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">
              {r.metadata.length === 0 ? 'Este archivo no contiene metadatos legibles. Es buena señal para tu privacidad.' : 'Ningún campo coincide con el filtro.'}
            </p>
          ) : (
            groups.map((gr, i) => (
              <details key={gr.id + i} open={i < 4 || !!ql} className="group overflow-hidden rounded-xl border border-slate-800 bg-slate-900/30">
                <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-3 hover:bg-slate-800/30 [&::-webkit-details-marker]:hidden">
                  <ChevronDown className="h-4 w-4 shrink-0 text-slate-500 transition group-open:rotate-180" />
                  <span className="min-w-0 flex-1 truncate text-sm font-semibold text-slate-100">{gr.title}</span>
                  {gr.entries.some((e) => e.sensitive) && <span className="rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-0.5 text-[10px] font-bold text-amber-300">{gr.entries.filter((e) => e.sensitive).length} sensibles</span>}
                  <span className="font-mono text-xs text-slate-500">{gr.shown.length}</span>
                </summary>
                {gr.note && <p className="border-t border-slate-800/70 bg-slate-900/50 px-4 py-2 text-xs leading-relaxed text-slate-400">{gr.note}</p>}
                <div className="divide-y divide-slate-800/60 border-t border-slate-800/70">
                  {gr.shown.map((e, j) => (
                    <div key={j} className="grid gap-x-4 gap-y-0.5 px-4 py-2 sm:grid-cols-[minmax(140px,230px)_1fr]">
                      <div className="flex items-start gap-1.5 break-all font-mono text-[12px] text-slate-400">
                        {e.sensitive ? <Eye className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" /> : <span className="w-3.5 shrink-0" />}
                        {e.key}
                      </div>
                      <div className={cn('whitespace-pre-wrap break-words font-mono text-[12px]', e.sensitive ? 'text-amber-100' : 'text-slate-200')}>{e.value}</div>
                    </div>
                  ))}
                </div>
              </details>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
