import { AlertTriangle, Flag, Loader2, Plus, X } from 'lucide-react';
import type { AnalysisResult } from '../lib/types';
import { VERDICT_META } from '../lib/report';
import { formatBytes } from '../lib/utils';
import { cn } from '../utils/cn';
import { gaugeColor } from './ui';

export interface Job {
  id: string;
  name: string;
  size: number;
  progress: number;
  message: string;
  error?: string;
}

interface Props {
  results: AnalysisResult[];
  jobs: Job[];
  selected: string | null;
  solvedFlags: Record<string, string[]>;
  onSelect: (id: string) => void;
  onRemove: (id: string) => void;
  onDismissJob: (id: string) => void;
  onAdd: () => void;
}

export default function Sidebar({ results, jobs, selected, solvedFlags, onSelect, onRemove, onDismissJob, onAdd }: Props) {
  return (
    <aside className="space-y-3 lg:sticky lg:top-20 lg:self-start">
      <div className="flex items-center justify-between px-1">
        <h2 className="text-[11px] font-bold uppercase tracking-[0.18em] text-slate-500">Archivos · {results.length + jobs.length}</h2>
        <button type="button" onClick={onAdd} className="inline-flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 text-[11px] font-medium text-slate-300 hover:border-cyan-400/60 hover:text-cyan-200">
          <Plus className="h-3.5 w-3.5" /> Añadir
        </button>
      </div>

      <div className="max-h-[60vh] space-y-2 overflow-y-auto pr-1 lg:max-h-[calc(100vh-10rem)]">
        {jobs.map((j) => (
          <div key={j.id} className={cn('rounded-xl border p-3', j.error ? 'border-red-500/40 bg-red-500/5' : 'border-cyan-400/25 bg-cyan-400/[0.04]')}>
            <div className="flex items-start gap-2">
              {j.error ? <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" /> : <Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-cyan-300" />}
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-slate-100" title={j.name}>{j.name}</div>
                <div className={cn('mt-0.5 text-[11px] leading-snug', j.error ? 'text-red-300' : 'text-slate-400')}>{j.error ?? j.message}</div>
              </div>
              {j.error && (
                <button type="button" onClick={() => onDismissJob(j.id)} className="text-slate-500 hover:text-slate-200" aria-label="Descartar"><X className="h-4 w-4" /></button>
              )}
            </div>
            {!j.error && (
              <div className="mt-2 h-1 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full rounded-full bg-cyan-400 transition-all duration-300" style={{ width: `${j.progress}%` }} />
              </div>
            )}
          </div>
        ))}

        {results.map((r) => {
          const v = VERDICT_META[r.verdict];
          const active = r.id === selected;
          return (
            <div key={r.id} className={cn('group relative rounded-xl border transition', active ? 'border-cyan-400/50 bg-cyan-400/[0.06] shadow-[0_0_0_1px_rgba(34,211,238,.15)]' : 'border-slate-800/90 bg-[#0b0f16]/80 hover:border-slate-600')}>
              <button type="button" onClick={() => onSelect(r.id)} className="block w-full p-3 text-left">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: v.hex, boxShadow: `0 0 8px ${v.hex}` }} />
                  <span className="truncate pr-5 text-sm font-medium text-slate-100" title={r.name}>{r.name}</span>
                </div>
                <div className="mt-1 truncate pl-4 text-[11px] text-slate-500">{r.typeLabel} · {formatBytes(r.size)}</div>
                <div className="mt-2 flex items-center gap-1.5 pl-4">
                  <span className="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" style={{ color: v.hex, background: `${v.hex}1a` }}>{v.label}</span>
                  <Chip label="F" v={r.scores.forense} />
                  <Chip label="M" v={r.scores.privacidad} />
                  {(solvedFlags[r.id]?.length ?? 0) > 0 && (
                    <span title={`Bandera: ${solvedFlags[r.id][0]}`} className="inline-flex items-center gap-1 rounded border border-emerald-400/40 bg-emerald-400/10 px-1.5 py-0.5 text-[10px] font-bold text-emerald-300">
                      <Flag className="h-2.5 w-2.5" /> FLAG
                    </span>
                  )}
                </div>
              </button>
              <button type="button" onClick={() => onRemove(r.id)} aria-label={`Quitar ${r.name}`} className="absolute right-2 top-2 rounded p-1 text-slate-600 opacity-0 transition hover:bg-slate-800 hover:text-slate-200 focus:opacity-100 group-hover:opacity-100">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </aside>
  );
}

function Chip({ label, v }: { label: string; v: number }) {
  return (
    <span title={label === 'F' ? 'Riesgo forense' : 'Exposición de metadatos'} className="inline-flex items-center gap-1 rounded border border-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
      {label}
      <b style={{ color: gaugeColor(v) }}>{v}</b>
    </span>
  );
}
