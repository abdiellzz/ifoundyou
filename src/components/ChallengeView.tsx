import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, Binary, Check, ChevronDown, Crosshair, Download, Eye, Flag, Image as ImageIcon, KeyRound,
  Lightbulb, Loader2, RefreshCw, Search, Terminal, X,
} from 'lucide-react';
import type { AnalysisResult } from '../lib/types';
import {
  CHALLENGE_FLAG_RE, CHANNELS, DEFAULT_LSB, FRAMING_LABEL, manualDecode, solveChallenge,
  type ChallengeResult, type ChannelKey, type Framing, type LsbOptions,
} from '../lib/ctf';
import { bytesToHexString, download, formatBytes } from '../lib/utils';
import { scanHidden, type HiddenScan } from '../lib/hidden';
import HiddenSearch from './HiddenSearch';
import { Card, CopyButton, SectionTitle } from './ui';
import { cn } from '../utils/cn';

const CH_LABEL: Record<ChannelKey, string> = {
  rgb: 'RGB', bgr: 'BGR', rgba: 'RGBA', r: 'Rojo (R)', g: 'Verde (G)', b: 'Azul (B)', a: 'Alfa (A)', rg: 'RG', gb: 'GB', br: 'BR',
};
const FRAMINGS: Framing[] = ['raw', 'u8', 'u16be', 'u16le', 'u32be', 'u32le'];

function framingFromLabel(label?: string): Framing {
  if (!label) return 'raw';
  if (/u8/i.test(label)) return 'u8';
  if (/u16\s*BE/i.test(label)) return 'u16be';
  if (/u16\s*LE/i.test(label)) return 'u16le';
  if (/u32\s*BE/i.test(label)) return 'u32be';
  if (/u32\s*LE/i.test(label)) return 'u32le';
  return 'raw';
}

const selectCls = 'rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-2 text-xs text-slate-200';

export default function ChallengeView({ r, onFlags, onTab }: { r: AnalysisResult; onFlags: (id: string, flags: string[]) => void; onTab: (t: 'forense' | 'metadatos' | 'informe') => void }) {
  const [res, setRes] = useState<ChallengeResult | null>(null);
  const [hidden, setHidden] = useState<HiddenScan | null>(null);
  const [keyword, setKeyword] = useState('');
  const [hitCount, setHitCount] = useState(0);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState({ message: 'Preparando…', pct: 0 });
  const [error, setError] = useState<string | null>(null);
  const [answer, setAnswer] = useState('');
  const [showStatement, setShowStatement] = useState(false);
  const [openRecovery, setOpenRecovery] = useState<string | null>(null);
  const [manual, setManual] = useState<LsbOptions>(DEFAULT_LSB);
  const [manualBytes, setManualBytes] = useState(512);
  const [planeChannel, setPlaneChannel] = useState<ChannelKey>('rgb');
  const [planes, setPlanes] = useState<string[]>([]);
  const last = useRef<string | null>(null);

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    setProgress({ message: 'Iniciando…', pct: 0 });
    try {
      const out = await solveChallenge(r.file, r, (message, pct) => setProgress({ message, pct: pct * 0.5 }));
      setRes(out);
      onFlags(r.id, out.flags);
      const scan = await scanHidden(r.file, r, out, (message, pct) => setProgress({ message, pct: 50 + pct * 0.5 }));
      setHidden(scan);
      const best = out.recoveries.find((c) => c.flags.length && c.lsb) ?? out.candidates.find((c) => c.flags.length && c.lsb);
      if (best?.lsb) setManual((m) => ({ ...m, ...best.lsb!, framing: framingFromLabel(best.lsb!.framing) }));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'No se pudo completar el análisis.');
    }
    setRunning(false);
  }, [r, onFlags]);

  useEffect(() => {
    if (last.current === r.id) return;
    last.current = r.id;
    void run();
  }, [r.id, run]);

  const manualOut = useMemo(() => (res?.image ? manualDecode(res.image, manual, manualBytes) : null), [res, manual, manualBytes]);

  /* Planos de bits */
  useEffect(() => {
    if (!res?.image) return;
    const img = res.image;
    const src = document.createElement('canvas');
    src.width = img.width;
    src.height = img.height;
    src.getContext('2d')!.putImageData(img, 0, 0);
    const scale = Math.min(1, 420 / img.width);
    const w = Math.max(1, Math.round(img.width * scale));
    const h = Math.max(1, Math.round(img.height * scale));
    const small = document.createElement('canvas');
    small.width = w;
    small.height = h;
    const sctx = small.getContext('2d', { willReadFrequently: true })!;
    sctx.drawImage(src, 0, 0, w, h);
    const data = sctx.getImageData(0, 0, w, h).data;
    const urls: string[] = [];
    for (let bit = 0; bit < 8; bit++) {
      const c = document.createElement('canvas');
      c.width = w;
      c.height = h;
      const ctx = c.getContext('2d')!;
      const out = ctx.createImageData(w, h);
      const ch = CHANNELS[planeChannel];
      for (let i = 0; i < data.length; i += 4) {
        if (planeChannel.length > 3 || planeChannel === 'a') {
          const v = ((data[i + ch[0]] >>> bit) & 1) * 255;
          out.data[i] = out.data[i + 1] = out.data[i + 2] = v;
        } else {
          for (let k = 0; k < 3; k++) out.data[i + k] = ((data[i + ch[k % ch.length]] >>> bit) & 1) * 255;
        }
        out.data[i + 3] = 255;
      }
      ctx.putImageData(out, 0, 0);
      urls.push(c.toDataURL('image/png'));
    }
    setPlanes(urls);
  }, [res, planeChannel]);

  const lossless = ['PNG', 'BMP', 'TIFF'].includes(r.type?.name ?? '');
  const riskyImage = r.type?.category === 'image' && !lossless;
  const answerValid = CHALLENGE_FLAG_RE.test(answer.trim());
  const wordFlags = hidden?.flags.map((h) => h.word) ?? [];
  const allFlags = [...new Set([...(res?.flags ?? []), ...wordFlags])];
  const mainFlag = allFlags.find((f) => CHALLENGE_FLAG_RE.test(f)) ?? allFlags[0] ?? null;
  const bestRecovery = res?.recoveries.find((c) => c.flags.length) ?? null;
  const keywordHits = keyword.trim().length >= 2 ? hitCount : 0;
  const isChallenge = r.type?.category === 'image' && /vuelo|404|avion|plane|img|photo|foto/i.test(r.name);

  return (
    <div className="space-y-6">
      {/* Enunciado del reto */}
      <Card className="overflow-hidden border-indigo-400/30">
        <button type="button" onClick={() => setShowStatement(!showStatement)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-slate-800/20">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-indigo-400/30 bg-indigo-400/10 text-indigo-300"><Crosshair className="h-4 w-4" /></div>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-slate-100">{isChallenge ? 'Reto 5 · El secreto del vuelo 404' : `Caso abierto · ¿qué esconde ${r.name}?`}</h2>
            <p className="text-xs text-slate-400">{isChallenge ? 'Recuperar un mensaje oculto en una fotografía y entregar la bandera' : `Buscar cualquier palabra o mensaje oculto en ${r.typeLabel}`}</p>
          </div>
          <code className="hidden rounded-md border border-indigo-400/30 bg-indigo-400/10 px-2 py-1 font-mono text-xs text-indigo-200 sm:block">CIBERISTMO&#123;respuesta&#125;</code>
          <ChevronDown className={cn('h-4 w-4 text-slate-500 transition', showStatement && 'rotate-180')} />
        </button>
        {showStatement && (
          <div className="border-t border-slate-800/80 px-5 py-4 text-[13px] leading-relaxed text-slate-300">
            <p>Durante una investigación se recuperó una fotografía enviada por un piloto antes de perder comunicación con la torre. A simple vista es un avión normal, pero contiene un mensaje escondido con técnicas de esteganografía.</p>
            <p className="mt-2"><b className="text-slate-100">Tu misión:</b> descargar la imagen, investigar cómo se oculta información en los píxeles, recuperar el mensaje y entregar la bandera con el formato <code className="font-mono text-cyan-200">CIBERISTMO&#123;respuesta&#125;</code>.</p>
            <p className="mt-3 text-xs text-slate-500">Esta herramienta no necesita el enunciado para funcionar: analiza cualquier imagen que subas. El botón «Probar con el vuelo 404» de la portada genera una imagen de demostración con una bandera ficticia.</p>
          </div>
        )}
      </Card>

      {riskyImage && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-400/40 bg-amber-400/[0.07] p-4 text-[13px] leading-relaxed text-amber-100">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <div>
            <b>Importante para retos LSB:</b> este archivo es {r.type?.name} (compresión con pérdida o paleta). Al guardarlo se reescriben los bits menos significativos de los píxeles, así que el mensaje original puede haberse destruido. Si es una captura de pantalla del enunciado, <b>no es el archivo del reto</b>: necesitas descargar el PNG/BMP original. Si el mensaje se insertó con <code className="font-mono">steghide</code>, usa los comandos que aparecen más abajo.
          </div>
        </div>
      )}

      {/* Acción principal */}
      <section className="relative overflow-hidden rounded-2xl border border-cyan-400/30 bg-[#0b0f16] p-6" style={{ backgroundImage: 'radial-gradient(700px 220px at 0% 0%, rgba(34,211,238,.12), transparent 65%)' }}>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-[11px] font-bold uppercase tracking-[0.2em] text-cyan-300/80">Paso 1 · Resolver</div>
            <h2 className="mt-1 text-2xl font-bold tracking-tight text-white">Buscar el mensaje oculto</h2>
            <p className="mt-1 max-w-xl text-sm text-slate-400"><b className="text-slate-200">Cualquier archivo, cualquier palabra.</b> Abre contenedores, lee metadatos, decodifica flujos, prueba planos de bits y cientos de transformaciones. No hace falta que sea una imagen ni que el mensaje tenga formato de bandera.</p>
          </div>
          <button type="button" disabled={running} onClick={run} className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-60">
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            {running ? 'Analizando…' : res ? 'Volver a analizar' : 'Buscar bandera'}
          </button>
        </div>
        <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-slate-800">
          <div className="h-full rounded-full bg-cyan-400 transition-all duration-300" style={{ width: `${progress.pct}%` }} />
        </div>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
          <span className={cn(running && 'text-cyan-200')}>{progress.message}</span>
          {res && <span className="font-mono text-slate-500">{res.combos} combinaciones LSB · {res.elapsedMs} ms · {res.imageNote}</span>}
        </div>
        {error && <p className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-200">{error}</p>}
      </section>

      <HiddenSearch scan={hidden} keyword={keyword} setKeyword={setKeyword} onHitCount={setHitCount} />

      {/* Resultado */}
      {res && (
        <section className={cn('rounded-2xl border-2 p-6', mainFlag ? 'border-emerald-400/50 bg-emerald-400/[0.06]' : 'border-amber-400/40 bg-amber-400/[0.05]')}>
          <div className="flex flex-wrap items-center gap-3">
            {mainFlag ? <Flag className="h-6 w-6 text-emerald-300" /> : <Search className="h-6 w-6 text-amber-300" />}
            <div>
              <div className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Paso 2 · Resultado</div>
              <h3 className={cn('text-xl font-bold', mainFlag ? 'text-emerald-200' : 'text-amber-200')}>{mainFlag ? 'Bandera recuperada' : keywordHits ? 'Sin bandera, pero tu palabra sí aparece' : 'No apareció una bandera en claro'}</h3>
            </div>
          </div>
          {mainFlag ? (
            <>
              <div className="mt-5 flex flex-wrap items-center gap-3 rounded-xl border border-emerald-400/40 bg-[#060b0c] p-4">
                <code className="min-w-0 flex-1 break-all font-mono text-lg font-semibold text-emerald-300 sm:text-2xl">{mainFlag}</code>
                <CopyButton text={mainFlag} label="Copiar bandera" />
              </div>
              {bestRecovery && (
                <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                  <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-cyan-300"><KeyRound className="h-3.5 w-3.5" /> Cómo se resolvió</div>
                  <p className="mt-2 text-sm text-slate-200">{bestRecovery.technique}</p>
                  <p className="mt-1 font-mono text-xs leading-relaxed text-slate-400">{bestRecovery.detail}</p>
                  <p className="mt-2 text-xs leading-relaxed text-slate-400">{explain(bestRecovery.technique)}</p>
                </div>
              )}
              {res.flags.length > 1 && (
                <div className="mt-3 text-xs text-slate-400">
                  Otras banderas detectadas: {res.flags.filter((f) => f !== mainFlag).map((f) => <code key={f} className="ml-1 font-mono text-cyan-200">{f}</code>)}
                </div>
              )}
            </>
          ) : (
            <div className="mt-4 space-y-3 text-sm text-slate-300">
              <p>El barrido automático terminó sin encontrar una cadena con formato de bandera.{keywordHits ? ` Eso no significa que no haya nada: la búsqueda universal encontró ${keywordHits} coincidencia(s) con «${keyword}» más arriba.` : ' Usa el buscador de palabras de más arriba, el decodificador LSB manual y la galería de planos de bits: en muchos retos el texto solo se ve en un plano concreto o bajo una contraseña.'}</p>
              {!keywordHits && <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-300"><Terminal className="h-4 w-4" /> Si el mensaje fue insertado con steghide u otra herramienta externa</div>
                <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-cyan-200">{`strings -n 6 imagen.png | grep -i CIBERISTMO\nexiftool imagen.png\nzsteg -a imagen.png                 # PNG / BMP\nsteghide extract -sf imagen.jpg -p ""   # JPEG, contraseña vacía\nstegseek imagen.jpg /usr/share/wordlists/rockyou.txt\nbinwalk -e imagen.png               # archivos añadidos`}</pre>
              </div>}
            </div>
          )}
        </section>
      )}

      {/* Comprobar respuesta */}
      <Card className="p-5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="min-w-0 flex-1">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-500">Paso 3 · Comprobar la respuesta antes de entregarla · o busca cualquier palabra más arriba</label>
            <input
              value={answer}
              onChange={(e) => setAnswer(e.target.value)}
              placeholder="CIBERISTMO{lo_que_encontraste}"
              className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 font-mono text-sm text-slate-100 placeholder:text-slate-600"
            />
          </div>
          {answer.trim() && (
            <div className={cn('mt-6 inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold', answerValid ? 'border-emerald-400/50 bg-emerald-400/10 text-emerald-200' : 'border-red-400/50 bg-red-400/10 text-red-200')}>
              {answerValid ? <Check className="h-4 w-4" /> : <X className="h-4 w-4" />}
              {answerValid ? 'Formato válido' : 'Debe empezar por CIBERISTMO{ y cerrar con }'}
            </div>
          )}
          {mainFlag && (
            <button type="button" onClick={() => setAnswer(mainFlag)} className="mt-6 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/60">
              Rellenar con la bandera encontrada
            </button>
          )}
        </div>
      </Card>

      {/* Checklist */}
      {res && (
        <Card>
          <SectionTitle icon={<Check className="h-4 w-4" />} title="Pruebas realizadas" hint="Cada técnica que se ha probado y qué ha dado, para que sepas por dónde seguir si no hay resultado." />
          <div className="divide-y divide-slate-800/70">
            {res.checks.map((c) => (
              <div key={c.id} className="flex items-start gap-3 px-5 py-3">
                <span className={cn('mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold', c.status === 'found' ? 'border-emerald-400/60 bg-emerald-400/15 text-emerald-300' : c.status === 'skipped' ? 'border-slate-600 text-slate-500' : 'border-slate-700 bg-slate-800/50 text-slate-400')}>
                  {c.status === 'found' ? '✓' : c.status === 'skipped' ? '–' : '·'}
                </span>
                <div className="min-w-0">
                  <div className={cn('text-sm font-medium', c.status === 'found' ? 'text-emerald-200' : 'text-slate-200')}>{c.label}</div>
                  <div className="mt-0.5 text-xs leading-relaxed text-slate-400">{c.note}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Mensajes recuperados */}
      {res && res.recoveries.length > 0 && (
        <Card>
          <SectionTitle icon={<Lightbulb className="h-4 w-4" />} title="Mensajes y fragmentos recuperados" hint="Texto legible extraído por cada técnica. Pulsa para ver el fragmento completo y copiarlo." right={<span className="rounded-full bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">{res.recoveries.length}</span>} />
          <div className="divide-y divide-slate-800/70">
            {res.recoveries.slice(0, 18).map((c) => (
              <div key={c.id} className="px-5 py-3">
                <button type="button" onClick={() => setOpenRecovery(openRecovery === c.id ? null : c.id)} className="flex w-full items-start gap-3 text-left">
                  <span className={cn('mt-0.5 rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase', c.flags.length ? 'border-emerald-400/50 bg-emerald-400/10 text-emerald-300' : 'border-slate-700 text-slate-400')}>
                    {c.flags.length ? 'BANDERA' : `${c.confidence}%`}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[13px] text-slate-100">{c.flags.length ? c.flags.join(' · ') : c.text.slice(0, 140)}</div>
                    <div className="mt-0.5 truncate text-[11px] text-slate-500">{c.technique} · {c.detail}</div>
                  </div>
                  <ChevronDown className={cn('mt-1 h-4 w-4 shrink-0 text-slate-500 transition', openRecovery === c.id && 'rotate-180')} />
                </button>
                {openRecovery === c.id && (
                  <div className="mt-3 rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                    <div className="flex justify-end"><CopyButton text={c.text} label="Copiar texto" /></div>
                    <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-[12px] leading-relaxed text-slate-200">{c.looseText || c.text}</pre>
                    {c.sourceBytes && <div className="mt-2 break-all border-t border-slate-800 pt-2 font-mono text-[10px] text-slate-600">HEX: {bytesToHexString(c.sourceBytes, 48)}…</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Decodificador manual */}
      {res?.image && (
        <Card>
          <SectionTitle icon={<Binary className="h-4 w-4" />} title="Decodificador LSB manual" hint="Ajusta el canal, el plano de bit, el orden de los bits, la dirección de lectura y la cabecera de longitud. El texto se actualiza en vivo." />
          <div className="grid gap-5 p-5 lg:grid-cols-[320px_minmax(0,1fr)]">
            <div className="space-y-3">
              <Field label="Canal / orden de canales">
                <select className={cn(selectCls, 'w-full')} value={manual.channel} onChange={(e) => setManual({ ...manual, channel: e.target.value as ChannelKey })}>
                  {(Object.keys(CHANNELS) as ChannelKey[]).map((c) => <option key={c} value={c}>{CH_LABEL[c]}</option>)}
                </select>
              </Field>
              <Field label="Plano de bit (0 = LSB)">
                <select className={cn(selectCls, 'w-full')} value={manual.bit} onChange={(e) => setManual({ ...manual, bit: +e.target.value })}>
                  {[0, 1, 2, 3, 4, 5, 6, 7].map((b) => <option key={b} value={b}>Bit {b} {b === 0 ? '(menos significativo)' : b === 7 ? '(más significativo)' : ''}</option>)}
                </select>
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Orden de bits">
                  <select className={cn(selectCls, 'w-full')} value={manual.bitOrder} onChange={(e) => setManual({ ...manual, bitOrder: e.target.value as 'msb' | 'lsb' })}>
                    <option value="msb">MSB primero</option>
                    <option value="lsb">LSB primero</option>
                  </select>
                </Field>
                <Field label="Recorrido">
                  <select className={cn(selectCls, 'w-full')} value={manual.scan} onChange={(e) => setManual({ ...manual, scan: e.target.value as 'xy' | 'yx' })}>
                    <option value="xy">Por filas (XY)</option>
                    <option value="yx">Por columnas (YX)</option>
                  </select>
                </Field>
              </div>
              <Field label="Cómo se indica la longitud">
                <select className={cn(selectCls, 'w-full')} value={manual.framing} onChange={(e) => setManual({ ...manual, framing: e.target.value as Framing })}>
                  {FRAMINGS.map((f) => <option key={f} value={f}>{FRAMING_LABEL[f]}</option>)}
                </select>
              </Field>
              <Field label={`Bytes a leer: ${manualBytes}`}>
                <input type="range" min={64} max={4096} step={64} value={manualBytes} onChange={(e) => setManualBytes(+e.target.value)} className="w-full accent-cyan-400" />
              </Field>
              <button type="button" onClick={() => setManual(DEFAULT_LSB)} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/60">Restablecer a RGB · bit 0 · MSB · XY</button>
            </div>
            <div>
              {manualOut && (
                <>
                  {manualOut.flags.length > 0 && (
                    <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-emerald-400/40 bg-emerald-400/10 p-3">
                      <Flag className="h-4 w-4 text-emerald-300" />
                      <code className="min-w-0 flex-1 break-all font-mono text-sm text-emerald-200">{manualOut.flags.join(' · ')}</code>
                      <CopyButton text={manualOut.flags.join('\n')} />
                    </div>
                  )}
                  <div className="relative rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                    <div className="absolute right-2 top-2"><CopyButton text={manualOut.text} /></div>
                    <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words pr-10 font-mono text-[12px] leading-relaxed text-slate-200">{manualOut.text.slice(0, 4000) || '(sin texto legible con esta configuración)'}</pre>
                  </div>
                  <div className="mt-2 break-all rounded-lg border border-slate-800 bg-slate-950/50 p-2 font-mono text-[10px] text-slate-500">HEX: {bytesToHexString(manualOut.bytes, 64)}</div>
                  <button type="button" onClick={() => download(`lsb_${manual.channel}_b${manual.bit}.bin`, new Blob([manualOut.bytes as BlobPart]))} className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/60">
                    <Download className="h-3.5 w-3.5" /> Descargar bytes decodificados
                  </button>
                </>
              )}
            </div>
          </div>
        </Card>
      )}

      {/* Planos de bits */}
      {res?.image && (
        <Card>
          <SectionTitle icon={<ImageIcon className="h-4 w-4" />} title="Galería de planos de bits" hint="Si el mensaje se dibujó como texto en un plano, aparecerá visible aquí. El plano 0 (LSB) de una foto natural debería parecer ruido uniforme." right={
            <select className={selectCls} value={planeChannel} onChange={(e) => setPlaneChannel(e.target.value as ChannelKey)}>
              {(['rgb', 'r', 'g', 'b', 'a'] as ChannelKey[]).map((c) => <option key={c} value={c}>{CH_LABEL[c]}</option>)}
            </select>
          } />
          <div className="grid grid-cols-2 gap-3 p-5 sm:grid-cols-4">
            {planes.map((url, bit) => (
              <div key={bit} className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/50">
                <img src={url} alt={`Plano de bit ${bit} del canal ${planeChannel}`} className="aspect-[3/2] w-full object-contain [image-rendering:pixelated]" />
                <div className="flex items-center justify-between border-t border-slate-800 px-2 py-1.5">
                  <span className="font-mono text-[11px] text-slate-300">Bit {bit}{bit === 0 ? ' · LSB' : ''}</span>
                  <a href={url} download={`plano_${planeChannel}_bit${bit}.png`} className="text-slate-500 hover:text-cyan-300" title="Descargar plano"><Download className="h-3.5 w-3.5" /></a>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Datos recuperables */}
      <Card>
        <SectionTitle icon={<Download className="h-4 w-4" />} title="Extraer lo que el visor no te muestra" hint="Bytes añadidos tras el final de la imagen y otros archivos incrustados: descárgalos para analizarlos por separado." />
        <div className="space-y-3 p-5">
          {res?.trailingBytes && (
            <div className="rounded-xl border border-pink-400/30 bg-pink-400/5 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-pink-200">{formatBytes(res.trailingBytes.length)} añadidos tras el final lógico</div>
                  <div className="font-mono text-xs text-slate-400">offset 0x{res.trailingOffset.toString(16).toUpperCase()} · {res.trailingBytes[0]?.toString(16).padStart(2, '0').toUpperCase()} {res.trailingBytes[1]?.toString(16).padStart(2, '0').toUpperCase()} {res.trailingBytes[2]?.toString(16).padStart(2, '0').toUpperCase()}…</div>
                </div>
                <button type="button" onClick={() => download('datos_ocultos.bin', new Blob([res!.trailingBytes! as BlobPart]))} className="inline-flex items-center gap-1.5 rounded-lg border border-pink-400/50 bg-pink-400/10 px-3 py-2 text-xs font-semibold text-pink-100 hover:bg-pink-400/20">
                  <Download className="h-3.5 w-3.5" /> Extraer bytes
                </button>
              </div>
              <pre className="mt-3 max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-950/60 p-2 font-mono text-[11px] text-slate-300">{new TextDecoder('windows-1252').decode(res.trailingBytes.subarray(0, 1200))}</pre>
            </div>
          )}
          {r.embedded.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/70 text-[10px] uppercase tracking-wider text-slate-500"><tr><th className="px-3 py-2">Offset</th><th className="px-3 py-2">Archivo</th><th className="px-3 py-2">Acción</th></tr></thead>
                <tbody className="divide-y divide-slate-800/70">
                  {r.embedded.slice(0, 12).map((h, i) => (
                    <tr key={i}>
                      <td className="px-3 py-2 font-mono text-cyan-300">0x{h.offset.toString(16).toUpperCase()}</td>
                      <td className="px-3 py-2 text-slate-200">{h.name}</td>
                      <td className="px-3 py-2">
                        <button type="button" onClick={async () => {
                          const raw = new Uint8Array(await r.file.arrayBuffer());
                          download(`incrustado_${i}_${h.name.toLowerCase().replace(/\W+/g, '_')}.bin`, new Blob([raw.subarray(h.offset) as BlobPart]));
                        }} className="inline-flex items-center gap-1 text-slate-300 hover:text-cyan-300"><Download className="h-3 w-3" /> Extraer desde aquí</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!res?.trailingBytes && r.embedded.length === 0 && (
            <p className="flex items-center gap-2 text-sm text-emerald-200"><Check className="h-4 w-4" /> No hay datos añadidos ni archivos incrustados que extraer.</p>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            <button type="button" onClick={() => onTab('forense')} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/60"><Binary className="h-3.5 w-3.5" /> Ver visor hexadecimal y cadenas</button>
            <button type="button" onClick={() => onTab('metadatos')} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/60"><Eye className="h-3.5 w-3.5" /> Revisar comentarios y metadatos</button>
            <button type="button" onClick={() => onTab('informe')} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/60">Ir al informe final</button>
          </div>
        </div>
      </Card>
    </div>
  );
}

function explain(technique: string): string {
  if (/LSB/i.test(technique))
    return 'El mensaje se reconstruye leyendo 1 bit de cada canal de cada píxel, empezando por la esquina superior izquierda, y agrupando los bits de 8 en 8 para formar caracteres ASCII. Los visores ignoran ese bit, por eso la foto se ve idéntica.';
  if (/metadatos/i.test(technique))
    return 'El mensaje estaba en un campo de metadatos (autor, comentario, XMP, EXIF…). El visor de imágenes no lo muestra, pero cualquiera que lea la estructura del archivo puede verlo.';
  if (/añadidos|XOR/i.test(technique))
    return 'El mensaje estaba en bytes añadidos después del marcador de fin del archivo. Los programas normales dejan de leer ahí, así que el contenido viaja invisible.';
  if (/base64|hex|ROT13|invertido/i.test(technique))
    return 'El mensaje estaba codificado con una transformación reversible. Se decodificó y apareció la bandera.';
  return 'El mensaje estaba escrito en claro entre los bytes del archivo: las cadenas de texto ASCII/UTF-16 lo delatan aunque la interfaz no lo muestre.';
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
      {children}
    </label>
  );
}
