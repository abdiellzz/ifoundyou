import { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import type { AnalysisResult } from '../lib/types';
import { cn } from '../utils/cn';

const TYPE: Record<string, { label: string; cls: string }> = {
  url: { label: 'URL', cls: 'border-sky-400/40 bg-sky-400/10 text-sky-300' },
  email: { label: 'E-mail', cls: 'border-violet-400/40 bg-violet-400/10 text-violet-300' },
  ip: { label: 'IP', cls: 'border-teal-400/40 bg-teal-400/10 text-teal-300' },
  usuario: { label: 'Usuario', cls: 'border-amber-400/40 bg-amber-400/10 text-amber-300' },
  ruta: { label: 'Ruta', cls: 'border-slate-500/50 bg-slate-500/10 text-slate-300' },
  credencial: { label: 'Credencial', cls: 'border-red-400/50 bg-red-500/10 text-red-300' },
  'clave-privada': { label: 'Clave privada', cls: 'border-red-400/50 bg-red-500/10 text-red-300' },
  sospechoso: { label: 'Sospechoso', cls: 'border-orange-400/50 bg-orange-500/10 text-orange-300' },
};

export default function StringsExplorer({ r, onOffset }: { r: AnalysisResult; onOffset: (o: number) => void }) {
  const [mode, setMode] = useState<'int' | 'all'>(r.strings.interesting.length ? 'int' : 'all');
  const [q, setQ] = useState('');
  const [type, setType] = useState<string | null>(null);
  const [limit, setLimit] = useState(150);

  const counts = useMemo(() => {
    const m: Record<string, number> = {};
    r.strings.interesting.forEach((s) => (m[s.type] = (m[s.type] ?? 0) + 1));
    return m;
  }, [r]);

  const ql = q.trim().toLowerCase();
  const interesting = r.strings.interesting.filter((s) => (!type || s.type === type) && (!ql || s.value.toLowerCase().includes(ql)));
  const samples = useMemo(() => (ql ? r.strings.samples.filter((s) => s.text.toLowerCase().includes(ql)) : r.strings.samples), [r, ql]);

  return (
    <div className="p-5">
      <div className="flex flex-wrap items-center gap-3">
        <div className="inline-flex rounded-lg border border-slate-800 bg-slate-900/60 p-1">
          <button type="button" onClick={() => setMode('int')} className={cn('rounded-md px-3 py-1.5 text-xs font-semibold', mode === 'int' ? 'bg-cyan-400/20 text-cyan-200' : 'text-slate-400')}>
            Indicadores ({r.strings.interesting.length})
          </button>
          <button type="button" onClick={() => setMode('all')} className={cn('rounded-md px-3 py-1.5 text-xs font-semibold', mode === 'all' ? 'bg-cyan-400/20 text-cyan-200' : 'text-slate-400')}>
            Todas las cadenas ({r.strings.total.toLocaleString('es-ES')})
          </button>
        </div>
        <div className="relative min-w-[200px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input value={q} onChange={(e) => { setQ(e.target.value); setLimit(150); }} placeholder="Buscar en las cadenas…" className="w-full rounded-lg border border-slate-800 bg-slate-900/70 py-2 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-600" />
        </div>
      </div>

      {mode === 'int' && Object.keys(counts).length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" onClick={() => setType(null)} className={cn('rounded-full border px-2.5 py-1 text-[11px] font-semibold', !type ? 'border-cyan-400/60 bg-cyan-400/15 text-cyan-200' : 'border-slate-700 text-slate-400')}>
            Todos
          </button>
          {Object.entries(counts).map(([t, n]) => (
            <button key={t} type="button" onClick={() => setType(type === t ? null : t)} className={cn('rounded-full border px-2.5 py-1 text-[11px] font-semibold', TYPE[t]?.cls, type === t && 'ring-2 ring-cyan-400/50')}>
              {TYPE[t]?.label ?? t} · {n}
            </button>
          ))}
        </div>
      )}

      <div className="mt-4 max-h-[420px] overflow-auto rounded-xl border border-slate-800 bg-[#080b11]">
        {mode === 'int' ? (
          interesting.length ? (
            <ul className="divide-y divide-slate-800/70">
              {interesting.slice(0, limit).map((s, i) => (
                <li key={i} className="flex items-start gap-3 px-3 py-2">
                  <span className={cn('mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide', TYPE[s.type]?.cls)}>{TYPE[s.type]?.label ?? s.type}</span>
                  <span className="min-w-0 flex-1 break-all font-mono text-[12px] text-slate-200">{s.value}</span>
                  {s.offset >= 0 && (
                    <button type="button" onClick={() => onOffset(s.offset)} className="shrink-0 font-mono text-[11px] text-cyan-400/80 hover:text-cyan-300">
                      0x{s.offset.toString(16).toUpperCase()}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="p-5 text-sm text-slate-500">No se encontraron URLs, correos, IPs, rutas ni credenciales en el contenido legible.</p>
          )
        ) : samples.length ? (
          <ul className="divide-y divide-slate-800/60">
            {samples.slice(0, limit).map((s, i) => (
              <li key={i} className="flex items-start gap-3 px-3 py-1.5">
                <button type="button" onClick={() => onOffset(s.offset)} className="w-20 shrink-0 text-left font-mono text-[11px] text-slate-600 hover:text-cyan-300">
                  {s.offset.toString(16).toUpperCase().padStart(8, '0')}
                </button>
                <span className="min-w-0 flex-1 break-all font-mono text-[12px] text-slate-300">{s.text}</span>
                {s.wide && <span className="shrink-0 text-[10px] text-slate-600">UTF-16</span>}
              </li>
            ))}
          </ul>
        ) : (
          <p className="p-5 text-sm text-slate-500">No hay cadenas que coincidan.</p>
        )}
      </div>
      {(mode === 'int' ? interesting.length : samples.length) > limit && (
        <button type="button" onClick={() => setLimit(limit + 300)} className="mt-3 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-cyan-400/50">
          Mostrar más
        </button>
      )}
    </div>
  );
}
