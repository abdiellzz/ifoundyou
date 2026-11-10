import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';
import { hex } from '../lib/utils';

const PAGE = 512;

export default function HexViewer({ file, offset, onOffset, mark }: { file: File; offset: number; onOffset: (o: number) => void; mark?: number[] }) {
  const [bytes, setBytes] = useState<Uint8Array>(new Uint8Array());
  const [input, setInput] = useState('0');
  const max = Math.max(0, file.size - 1);
  const base = Math.min(Math.max(0, offset - (offset % 16)), max - (max % 16));

  useEffect(() => {
    let alive = true;
    file
      .slice(base, base + PAGE)
      .arrayBuffer()
      .then((b) => alive && setBytes(new Uint8Array(b)));
    return () => {
      alive = false;
    };
  }, [file, base]);

  useEffect(() => setInput(base.toString(16).toUpperCase()), [base]);

  const go = (o: number) => onOffset(Math.min(Math.max(0, o), max));
  const rows: number[] = [];
  for (let i = 0; i < bytes.length; i += 16) rows.push(i);
  const marks = new Set(mark ?? []);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 px-5 py-3">
        <div className="flex items-center gap-1">
          <button type="button" className="hexbtn" onClick={() => go(0)} title="Inicio"><ChevronsLeft className="h-4 w-4" /></button>
          <button type="button" className="hexbtn" onClick={() => go(base - PAGE)} title="Anterior"><ChevronLeft className="h-4 w-4" /></button>
          <button type="button" className="hexbtn" onClick={() => go(base + PAGE)} title="Siguiente"><ChevronRight className="h-4 w-4" /></button>
          <button type="button" className="hexbtn" onClick={() => go(max - PAGE + 1)} title="Final"><ChevronsRight className="h-4 w-4" /></button>
        </div>
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const v = parseInt(input.replace(/^0x/i, ''), 16);
            if (!isNaN(v)) go(v);
          }}
        >
          <label className="text-xs text-slate-400">Ir al offset 0x</label>
          <input value={input} onChange={(e) => setInput(e.target.value)} className="w-28 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-xs text-cyan-200" spellCheck={false} />
          <button className="rounded-md bg-cyan-400/15 px-2.5 py-1 text-xs font-medium text-cyan-200 hover:bg-cyan-400/25">Ir</button>
        </form>
        <span className="ml-auto font-mono text-[11px] text-slate-500">
          {base.toLocaleString('es-ES')} – {(base + bytes.length).toLocaleString('es-ES')} de {file.size.toLocaleString('es-ES')} B
        </span>
      </div>
      <div className="overflow-x-auto px-5 py-4">
        <table className="font-mono text-[12px] leading-6">
          <tbody>
            {rows.map((r) => {
              const hi = offset >= base + r && offset < base + r + 16;
              return (
                <tr key={r} className={hi ? 'bg-cyan-400/10' : undefined}>
                  <td className="select-none pr-4 text-slate-600">{hex(base + r, 8)}</td>
                  <td className="pr-4">
                    {Array.from({ length: 16 }, (_, i) => {
                      const v = bytes[r + i];
                      const abs = base + r + i;
                      return (
                        <span key={i} className={`inline-block w-[1.55em] text-center ${v === undefined ? 'text-transparent' : v === 0 ? 'text-slate-700' : marks.has(abs) || (hi && abs === offset) ? 'font-bold text-cyan-300' : v > 31 && v < 127 ? 'text-slate-200' : 'text-slate-500'} ${i === 7 ? 'mr-2' : ''}`}>
                          {v === undefined ? '00' : hex(v)}
                        </span>
                      );
                    })}
                  </td>
                  <td className="whitespace-pre text-slate-400">
                    {Array.from(bytes.subarray(r, r + 16))
                      .map((v) => (v > 31 && v < 127 ? String.fromCharCode(v) : '·'))
                      .join('')}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <style>{`.hexbtn{display:inline-flex;align-items:center;justify-content:center;height:28px;width:28px;border-radius:6px;border:1px solid #243041;background:#0f1623;color:#94a3b8}.hexbtn:hover{border-color:#22d3ee80;color:#67e8f9}`}</style>
    </div>
  );
}
