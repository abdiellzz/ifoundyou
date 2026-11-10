import type { AnalysisResult } from '../lib/types';

const color = (e: number) => (e < 4.5 ? '#38bdf8' : e < 6.5 ? '#34d399' : e < 7.4 ? '#fbbf24' : '#f87171');

export default function EntropyChart({ r, onOffset }: { r: AnalysisResult; onOffset: (o: number) => void }) {
  const { blocks, blockSize } = r.entropy;
  const W = 720;
  const H = 150;
  const pad = { l: 26, r: 6, t: 8, b: 18 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;
  const bw = iw / Math.max(1, blocks.length);
  const y = (e: number) => pad.t + ih - (e / 8) * ih;
  const trailingBlock = r.trailing ? Math.floor(r.trailing.offset / blockSize) : -1;
  return (
    <div>
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full min-w-[520px]" role="img" aria-label="Entropía por bloques">
          {[0, 2, 4, 6, 8].map((v) => (
            <g key={v}>
              <line x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} stroke="#1a2330" strokeDasharray={v === 0 ? undefined : '3 4'} />
              <text x={pad.l - 6} y={y(v) + 3} textAnchor="end" fontSize="9" fill="#64748b" fontFamily="monospace">{v}</text>
            </g>
          ))}
          <line x1={pad.l} x2={W - pad.r} y1={y(7.5)} y2={y(7.5)} stroke="#f87171" strokeOpacity=".35" strokeDasharray="2 3" />
          {blocks.map((e, i) => (
            <g key={i} onClick={() => onOffset(i * blockSize)} className="cursor-pointer">
              <rect x={pad.l + i * bw + 0.5} y={y(e)} width={Math.max(1, bw - 1)} height={Math.max(1, (e / 8) * ih)} fill={color(e)} fillOpacity={i >= trailingBlock && trailingBlock >= 0 ? 1 : 0.8} rx="1">
                <title>{`Bloque ${i + 1} · offset 0x${(i * blockSize).toString(16).toUpperCase()} · entropía ${e.toFixed(2)}`}</title>
              </rect>
            </g>
          ))}
          {trailingBlock >= 0 && (
            <g>
              <line x1={pad.l + trailingBlock * bw} x2={pad.l + trailingBlock * bw} y1={pad.t} y2={pad.t + ih} stroke="#f472b6" strokeWidth="1.5" strokeDasharray="4 3" />
              <text x={pad.l + trailingBlock * bw + 4} y={pad.t + 9} fontSize="9" fill="#f472b6" fontFamily="monospace">fin lógico →</text>
            </g>
          )}
          {r.embedded.slice(0, 20).map((h, i) => (
            <path key={i} d={`M${pad.l + (h.offset / blockSize) * bw - 4},${H - 2} l4,-7 l4,7 z`} fill="#fb923c">
              <title>{`${h.name} @0x${h.offset.toString(16).toUpperCase()}`}</title>
            </path>
          ))}
        </svg>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] text-slate-400">
        <Legend c="#38bdf8" t="< 4.5 estructurado / texto" />
        <Legend c="#34d399" t="4.5 – 6.5 código / mixto" />
        <Legend c="#fbbf24" t="6.5 – 7.4 comprimido" />
        <Legend c="#f87171" t="> 7.4 cifrado / aleatorio" />
        {r.embedded.length > 0 && <span className="flex items-center gap-1.5 text-orange-300">▲ archivo incrustado</span>}
      </div>
    </div>
  );
}

function Legend({ c, t }: { c: string; t: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-2.5 w-2.5 rounded-sm" style={{ background: c }} />
      {t}
    </span>
  );
}
