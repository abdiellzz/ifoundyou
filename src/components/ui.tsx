import { useState, type ReactNode } from 'react';
import { Check, Copy, Lightbulb } from 'lucide-react';
import type { Finding, Severity, Verdict } from '../lib/types';
import { SEV_LABEL, VERDICT_META } from '../lib/report';
import { cn } from '../utils/cn';

export const SEV: Record<Severity, { text: string; bg: string; border: string; dot: string; ring: string }> = {
  critical: { text: 'text-red-300', bg: 'bg-red-500/10', border: 'border-red-500/50', dot: 'bg-red-500', ring: 'ring-red-500/30' },
  high: { text: 'text-orange-300', bg: 'bg-orange-500/10', border: 'border-orange-500/50', dot: 'bg-orange-500', ring: 'ring-orange-500/30' },
  medium: { text: 'text-amber-300', bg: 'bg-amber-400/10', border: 'border-amber-400/50', dot: 'bg-amber-400', ring: 'ring-amber-400/30' },
  low: { text: 'text-sky-300', bg: 'bg-sky-400/10', border: 'border-sky-400/40', dot: 'bg-sky-400', ring: 'ring-sky-400/30' },
  info: { text: 'text-slate-300', bg: 'bg-slate-400/10', border: 'border-slate-500/40', dot: 'bg-slate-400', ring: 'ring-slate-400/20' },
};

export function SeverityBadge({ s, className }: { s: Severity; className?: string }) {
  const c = SEV[s];
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider', c.bg, c.border, c.text, className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', c.dot)} />
      {SEV_LABEL[s]}
    </span>
  );
}

export function VerdictBadge({ v, className }: { v: Verdict; className?: string }) {
  const m = VERDICT_META[v];
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-bold uppercase tracking-wider', m.bg, m.border, m.text, className)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: m.hex }} />
      {m.label}
    </span>
  );
}

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={cn('rounded-2xl border border-slate-800/90 bg-[#0b0f16]/90 backdrop-blur', className)}>{children}</section>;
}

export function SectionTitle({ icon, title, hint, right }: { icon?: ReactNode; title: string; hint?: string; right?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/80 px-5 py-4">
      <div className="flex items-start gap-3">
        {icon && <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">{icon}</div>}
        <div>
          <h3 className="text-[15px] font-semibold tracking-tight text-slate-100">{title}</h3>
          {hint && <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-slate-400">{hint}</p>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function CopyButton({ text, className, label }: { text: string; className?: string; label?: string }) {
  const [ok, setOk] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    setOk(true);
    setTimeout(() => setOk(false), 1400);
  };
  return (
    <button
      type="button"
      onClick={copy}
      title="Copiar"
      className={cn('inline-flex items-center gap-1.5 rounded-md border border-slate-700/80 bg-slate-800/50 px-2 py-1 text-[11px] font-medium text-slate-300 transition hover:border-cyan-400/50 hover:text-cyan-200', className)}
    >
      {ok ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {label && <span>{ok ? 'Copiado' : label}</span>}
    </button>
  );
}

export function gaugeColor(v: number) {
  return v < 15 ? '#34d399' : v < 35 ? '#38bdf8' : v < 60 ? '#fb923c' : '#f87171';
}

export function Gauge({ value, label, size = 128, sub }: { value: number; label: string; size?: number; sub?: string }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const col = gaugeColor(value);
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
          <circle cx="64" cy="64" r={r} fill="none" stroke="#1a2330" strokeWidth="10" />
          <circle cx="64" cy="64" r={r} fill="none" stroke={col} strokeWidth="10" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c - (c * Math.max(2, value)) / 100} style={{ transition: 'stroke-dashoffset 1s ease', filter: `drop-shadow(0 0 6px ${col}66)` }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-3xl font-semibold tabular-nums text-slate-50">{value}</span>
          <span className="text-[10px] uppercase tracking-widest text-slate-500">/ 100</span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-sm font-semibold text-slate-200">{label}</div>
        {sub && <div className="text-[11px] text-slate-500">{sub}</div>}
      </div>
    </div>
  );
}

export function FindingCard({ f, onOffset }: { f: Finding; onOffset?: (o: number) => void }) {
  const c = SEV[f.severity];
  return (
    <div className={cn('rounded-xl border-l-4 border-y border-r bg-slate-900/40 p-4', c.border, 'border-y-slate-800/80 border-r-slate-800/80')}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge s={f.severity} />
        <h4 className="text-sm font-semibold text-slate-100">{f.title}</h4>
        {f.offset !== undefined && f.offset >= 0 && (
          <button
            type="button"
            onClick={() => onOffset?.(f.offset!)}
            className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300 transition hover:border-cyan-400/60"
            title="Ver en el visor hexadecimal"
          >
            @0x{f.offset.toString(16).toUpperCase()}
          </button>
        )}
      </div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-slate-300/90">{f.detail}</p>
      {f.recommendation && (
        <p className="mt-2 flex items-start gap-1.5 text-xs leading-relaxed text-slate-400">
          <Lightbulb className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300/80" />
          <span>{f.recommendation}</span>
        </p>
      )}
    </div>
  );
}

export function EmptyOk({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-4 text-sm text-emerald-200/90">
      <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
      <div>{children}</div>
    </div>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="none" aria-hidden>
      <circle cx="16" cy="16" r="9" stroke="currentColor" strokeWidth="2" />
      <circle cx="16" cy="16" r="3.2" fill="currentColor" />
      <path d="M16 2.5v6M16 23.5v6M2.5 16h6M23.5 16h6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}
