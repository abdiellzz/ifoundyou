import { useEffect, useRef, useState } from 'react';
import type { StegoResult } from '../lib/types';
import { cn } from '../utils/cn';

type Mode = 'orig' | 'ela' | 'lsb';
type Chan = 'rgb' | 'r' | 'g' | 'b';

const EXPLAIN: Record<Mode, string> = {
  orig: 'Vista de la imagen tal y como la decodifica el navegador.',
  ela: 'Error Level Analysis: la imagen se recomprime en JPEG (75 %) y se amplifica la diferencia. Las zonas pegadas, retocadas o añadidas suelen mostrar un nivel de error distinto al del resto. Interprétalo con cautela: bordes y texturas finas también brillan.',
  lsb: 'Plano de bits menos significativos (LSB). En una foto natural debería parecer ruido uniforme. Patrones, texto legible, franjas ordenadas o bloques lisos junto a bloques ruidosos son señal de datos ocultos (esteganografía).',
};

export default function ImageLab({ file, stego }: { file: File; stego: StegoResult | null }) {
  const [mode, setMode] = useState<Mode>('orig');
  const [ela, setEla] = useState(20);
  const [chan, setChan] = useState<Chan>('rgb');
  const [bit, setBit] = useState(0);
  const [bmp, setBmp] = useState<ImageBitmap | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let alive = true;
    setBmp(null);
    setErr(null);
    createImageBitmap(file, { premultiplyAlpha: 'none', colorSpaceConversion: 'none' })
      .then((x) => {
        if (alive) setBmp(x);
        else x.close();
      })
      .catch(() => alive && setErr('Este navegador no puede decodificar este formato de imagen, por lo que no es posible mostrar el laboratorio visual.'));
    return () => {
      alive = false;
    };
  }, [file]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !bmp) return;
    let cancelled = false;
    (async () => {
      setBusy(true);
      const big = bmp.width * bmp.height > 12_000_000;
      const maxW = mode === 'lsb' ? (big ? 2000 : 4096) : 1000;
      const scale = Math.min(1, maxW / bmp.width);
      const cw = Math.max(1, Math.round(bmp.width * scale));
      const ch = Math.max(1, Math.round(bmp.height * scale));
      canvas.width = cw;
      canvas.height = ch;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return;
      ctx.drawImage(bmp, 0, 0, cw, ch);
      if (mode === 'orig') {
        setBusy(false);
        return;
      }
      const src = ctx.getImageData(0, 0, cw, ch);
      const d = src.data;
      if (mode === 'lsb') {
        const m = 1 << bit;
        for (let i = 0; i < d.length; i += 4) {
          const R = d[i] & m ? 255 : 0;
          const G = d[i + 1] & m ? 255 : 0;
          const B = d[i + 2] & m ? 255 : 0;
          if (chan === 'rgb') {
            d[i] = R;
            d[i + 1] = G;
            d[i + 2] = B;
          } else {
            const v = chan === 'r' ? R : chan === 'g' ? G : B;
            d[i] = d[i + 1] = d[i + 2] = v;
          }
          d[i + 3] = 255;
        }
        ctx.putImageData(src, 0, 0);
      } else {
        const blob: Blob | null = await new Promise((res) => canvas.toBlob(res, 'image/jpeg', 0.75));
        if (!blob || cancelled) return;
        const re = await createImageBitmap(blob);
        const tmp = document.createElement('canvas');
        tmp.width = cw;
        tmp.height = ch;
        const tctx = tmp.getContext('2d', { willReadFrequently: true })!;
        tctx.drawImage(re, 0, 0);
        re.close();
        const rec = tctx.getImageData(0, 0, cw, ch).data;
        if (cancelled) return;
        for (let i = 0; i < d.length; i += 4) {
          d[i] = Math.min(255, Math.abs(d[i] - rec[i]) * ela);
          d[i + 1] = Math.min(255, Math.abs(d[i + 1] - rec[i + 1]) * ela);
          d[i + 2] = Math.min(255, Math.abs(d[i + 2] - rec[i + 2]) * ela);
          d[i + 3] = 255;
        }
        ctx.putImageData(src, 0, 0);
      }
      if (!cancelled) setBusy(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [bmp, mode, ela, chan, bit]);

  if (err) return <p className="px-5 py-6 text-sm text-slate-400">{err}</p>;

  const seg = (active: boolean) =>
    cn('rounded-md px-3 py-1.5 text-xs font-semibold transition', active ? 'bg-cyan-400/20 text-cyan-200 shadow-[inset_0_0_0_1px_rgba(34,211,238,.4)]' : 'text-slate-400 hover:text-slate-200');

  return (
    <div className="grid gap-5 p-5 lg:grid-cols-[1fr_300px]">
      <div className="min-w-0">
        <div className="relative flex min-h-[220px] items-center justify-center overflow-hidden rounded-xl border border-slate-800 bg-[conic-gradient(at_50%_50%,#0b0f16_25%,#0f1520_0_50%,#0b0f16_0_75%,#0f1520_0)] bg-[length:18px_18px] p-2">
          <canvas ref={canvasRef} className={cn('max-h-[520px] max-w-full rounded', mode === 'lsb' && '[image-rendering:pixelated]')} />
          {(busy || !bmp) && <div className="absolute inset-0 flex items-center justify-center bg-black/40 text-xs text-slate-300">Procesando…</div>}
        </div>
        <p className="mt-3 text-xs leading-relaxed text-slate-400">{EXPLAIN[mode]}</p>
      </div>
      <div className="space-y-4">
        <div className="inline-flex w-full rounded-lg border border-slate-800 bg-slate-900/60 p-1">
          <button type="button" className={cn(seg(mode === 'orig'), 'flex-1')} onClick={() => setMode('orig')}>Original</button>
          <button type="button" className={cn(seg(mode === 'ela'), 'flex-1')} onClick={() => setMode('ela')}>ELA</button>
          <button type="button" className={cn(seg(mode === 'lsb'), 'flex-1')} onClick={() => setMode('lsb')}>Plano LSB</button>
        </div>
        {mode === 'ela' && (
          <label className="block text-xs text-slate-400">
            Amplificación ×{ela}
            <input type="range" min={5} max={60} value={ela} onChange={(e) => setEla(+e.target.value)} className="mt-2 w-full accent-cyan-400" />
          </label>
        )}
        {mode === 'lsb' && (
          <div className="space-y-3">
            <div>
              <div className="mb-1.5 text-xs text-slate-400">Canal</div>
              <div className="grid grid-cols-4 gap-1">
                {(['rgb', 'r', 'g', 'b'] as Chan[]).map((c) => (
                  <button key={c} type="button" onClick={() => setChan(c)} className={cn('rounded-md border px-2 py-1.5 text-xs font-semibold uppercase', chan === c ? 'border-cyan-400/60 bg-cyan-400/15 text-cyan-200' : 'border-slate-800 text-slate-400 hover:text-slate-200')}>
                    {c}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <div className="mb-1.5 text-xs text-slate-400">Bit</div>
              <div className="grid grid-cols-4 gap-1">
                {[0, 1, 2, 3].map((n) => (
                  <button key={n} type="button" onClick={() => setBit(n)} className={cn('rounded-md border px-2 py-1.5 text-xs font-semibold', bit === n ? 'border-cyan-400/60 bg-cyan-400/15 text-cyan-200' : 'border-slate-800 text-slate-400 hover:text-slate-200')}>
                    {n === 0 ? 'LSB' : `+${n}`}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
        {bmp && (
          <dl className="space-y-1.5 rounded-lg border border-slate-800 bg-slate-900/50 p-3 text-xs">
            <Row k="Resolución" v={`${bmp.width} × ${bmp.height} px`} />
            {stego?.applicable ? (
              <>
                <Row k="Bits LSB = 1 (R/G/B)" v={stego.lsbRatio.map((x) => (x * 100).toFixed(1) + '%').join(' · ')} />
                <Row k="Prob. de incrustación" v={`${(stego.pEmbed * 100).toFixed(1)} %`} warn={stego.pEmbed > 0.9} />
              </>
            ) : (
              <Row k="Test estadístico LSB" v="No aplicable (imagen con pérdida o muy pequeña)" />
            )}
          </dl>
        )}
      </div>
    </div>
  );
}

function Row({ k, v, warn }: { k: string; v: string; warn?: boolean }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500">{k}</dt>
      <dd className={cn('text-right font-mono', warn ? 'text-orange-300' : 'text-slate-200')}>{v}</dd>
    </div>
  );
}
