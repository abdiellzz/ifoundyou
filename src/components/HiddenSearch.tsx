import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import { ChevronDown, Download, FileSearch, Filter, Layers, Search, Sparkles, Wand2, X } from 'lucide-react';
import { compact, exportStreams, searchKeyword, type HiddenScan, type Hit } from '../lib/hidden';
import { download, formatBytes } from '../lib/utils';
import { Card, CopyButton, SectionTitle } from './ui';
import { cn } from '../utils/cn';

const QUICK = ['pulela', 'bandera', 'flag', 'clave', 'password', 'secreto'];
const GROUPS = ['Todos', 'Archivo', 'Contenedor', 'Metadatos', 'Texto invisible', 'Imagen LSB', 'Decodificación', 'Transformación'] as const;

const GROUP_STYLE: Record<string, string> = {
  Archivo: 'border-slate-600/50 bg-slate-500/10 text-slate-300',
  Contenedor: 'border-violet-400/50 bg-violet-400/10 text-violet-300',
  Metadatos: 'border-amber-400/50 bg-amber-400/10 text-amber-300',
  'Texto invisible': 'border-emerald-400/50 bg-emerald-400/10 text-emerald-300',
  'Imagen LSB': 'border-cyan-400/50 bg-cyan-400/10 text-cyan-300',
  Decodificación: 'border-sky-400/50 bg-sky-400/10 text-sky-300',
  Transformación: 'border-fuchsia-400/50 bg-fuchsia-400/10 text-fuchsia-300',
};

export default function HiddenSearch({ scan, keyword, setKeyword, onHitCount }: { scan: HiddenScan | null; keyword: string; setKeyword: (s: string) => void; onHitCount?: (n: number) => void }) {
  const deferred = useDeferredValue(keyword);
  const [openWord, setOpenWord] = useState<string | null>(null);
  const [showAllWords, setShowAllWords] = useState(false);
  const [group, setGroup] = useState<(typeof GROUPS)[number]>('Todos');
  const [filter, setFilter] = useState('');
  const [openStream, setOpenStream] = useState<string | null>(null);
  const [streamLimit, setStreamLimit] = useState(40);

  const hits = useMemo(() => (scan && deferred.trim().length >= 2 ? searchKeyword(scan, deferred) : []), [scan, deferred]);
  const auto = useMemo(() => (scan ? { words: scan.words, flags: scan.flags } : null), [scan]);
  useEffect(() => onHitCount?.(hits.length), [hits.length, onHitCount]);

  const shownStreams = useMemo(() => {
    if (!scan) return [];
    const q = compact(filter);
    return scan.streams.filter(
      (s) =>
        (group === 'Todos' || s.group === group) &&
        (!q || compact(s.label + s.detail + s.text).includes(q)),
    );
  }, [scan, filter, group]);

  return (
    <div className="space-y-6">
      {/* Buscador en vivo */}
      <section className="rounded-2xl border border-cyan-400/40 bg-[#0b0f16] p-5 sm:p-6" style={{ backgroundImage: 'radial-gradient(700px 200px at 0% 0%, rgba(34,211,238,.10), transparent 65%)' }}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-300"><Wand2 className="h-5 w-5" /></div>
            <div>
              <h2 className="text-lg font-bold text-white">Busca cualquier palabra oculta</h2>
              <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-slate-400">
                Funciona con <b className="text-slate-200">cualquier archivo</b> (TXT, PDF, DOCX, XLSX, ZIP, PNG, JPG, EXE, MP3…) y con <b className="text-slate-200">cualquier palabra</b>, no solo banderas. Busca en texto claro, metadatos, archivos internos, planos de bits y cientos de codificaciones. Los acentos, signos y letras separadas se ignoran: <code className="font-mono text-cyan-200">p.u.l.e.l.a</code> también coincide.
              </p>
            </div>
          </div>
          {scan && (
            <button type="button" onClick={() => download('flujos_decodificados.txt', exportStreams(scan), 'text/plain')} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/60">
              <Download className="h-3.5 w-3.5" /> Exportar todos los flujos
            </button>
          )}
        </div>

        <div className="relative mt-4">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-5 w-5 -translate-y-1/2 text-cyan-300" />
          <input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="Escribe la palabra que buscas… p. ej. pulela"
            spellCheck={false}
            className="w-full rounded-xl border border-cyan-400/40 bg-[#070b11] py-3.5 pl-11 pr-12 font-mono text-base text-cyan-100 placeholder:font-sans placeholder:text-slate-600"
          />
          {keyword && (
            <button type="button" onClick={() => setKeyword('')} className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 hover:text-slate-200" aria-label="Borrar"><X className="h-4 w-4" /></button>
          )}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-[11px] uppercase tracking-wider text-slate-500">Prueba:</span>
          {QUICK.map((q) => (
            <button key={q} type="button" onClick={() => setKeyword(q)} className={cn('rounded-full border px-2.5 py-1 font-mono text-[11px]', keyword === q ? 'border-cyan-400/60 bg-cyan-400/15 text-cyan-200' : 'border-slate-700 text-slate-400 hover:text-slate-200')}>
              {q}
            </button>
          ))}
        </div>

        {scan && (
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1 border-t border-slate-800/70 pt-3 text-[11px] text-slate-500">
            <span><b className="font-mono text-slate-200">{scan.stats.streams}</b> flujos decodificados</span>
            <span><b className="font-mono text-slate-200">{scan.stats.combos}</b> combinaciones de bits</span>
            <span><b className="font-mono text-slate-200">{scan.stats.transforms}</b> transformaciones guardadas</span>
            <span><b className="font-mono text-slate-200">{scan.stats.transformsProbed.toLocaleString('es-ES')}+</b> transformaciones probadas al buscar</span>
            <span><b className="font-mono text-slate-200">{formatBytes(scan.stats.bytes)}</b> examinados · {scan.stats.elapsedMs} ms</span>
          </div>
        )}

        {keyword.trim().length >= 2 && (
          <div className="mt-4">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <Sparkles className="h-3.5 w-3.5 text-cyan-300" />
              {deferred !== keyword
                ? 'Buscando en todos los flujos y transformaciones…'
                : hits.length
                  ? `${hits.length} coincidencia(s) con «${keyword}»`
                  : `Sin coincidencias con «${keyword}»`}
            </div>
            {deferred !== keyword ? (
              <div className="h-1 overflow-hidden rounded-full bg-slate-800"><div className="h-full w-1/3 animate-pulse rounded-full bg-cyan-400" /></div>
            ) : hits.length ? (
              <div className="max-h-[340px] space-y-2 overflow-auto pr-1">
                {hits.slice(0, 24).map((h) => <HitRow key={h.id} hit={h} keyword={keyword} />)}
              </div>
            ) : (
              <p className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs leading-relaxed text-slate-400">
                No aparece en {scan?.stats.streams ?? 0} flujos ni tras probar XOR de 1 byte, ROT-1…25, Atbash, inversión, suma de bytes, UTF-16, base64, hexadecimal, compresión ni esteganografía de texto. Prueba con una parte más corta de la palabra, o revisa el explorador de flujos de más abajo.
              </p>
            )}
          </div>
        )}
      </section>

      {/* Palabras detectadas automáticamente */}
      {auto && (auto.words.length > 0 || auto.flags.length > 0) && (
        <Card>
          <SectionTitle
            icon={<Sparkles className="h-4 w-4" />}
            title="Palabras y banderas detectadas sin buscar nada"
            hint="El motor puntúa palabras plausibles en todos los flujos. Las que vienen de planos de bits, texto invisible o transformaciones puntúan más alto que las del texto visible."
            right={<span className="rounded-full bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">{auto.words.length}</span>}
          />
          <div className="p-5">
            {auto.flags.length > 0 && (
              <div className="mb-4 flex flex-wrap gap-2">
                {auto.flags.slice(0, 10).map((f) => (
                  <span key={f.id} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-400/50 bg-emerald-400/10 px-2.5 py-1 font-mono text-xs text-emerald-200">
                    🏴 {f.word} <CopyButton text={f.word} />
                  </span>
                ))}
              </div>
            )}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {(showAllWords ? auto.words : auto.words.slice(0, 24)).map((h) => (
                <div key={h.id} className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/40">
                  <button type="button" onClick={() => setOpenWord(openWord === h.id ? null : h.id)} className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-slate-800/40">
                    <span className={cn('min-w-0 flex-1 truncate font-mono text-[13px]', h.variant === 'palabra conocida' ? 'text-cyan-200' : 'text-slate-200')}>{h.word}</span>
                    <span className={cn('rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase', GROUP_STYLE[h.group])}>{h.group}</span>
                    <ChevronDown className={cn('h-3.5 w-3.5 shrink-0 text-slate-500 transition', openWord === h.id && 'rotate-180')} />
                  </button>
                  {openWord === h.id && (
                    <div className="border-t border-slate-800 p-3">
                      <p className="break-words font-mono text-[11px] leading-relaxed text-slate-300">…{h.context}…</p>
                      <p className="mt-2 text-[11px] text-slate-500">{h.technique} · {h.detail}</p>
                      <div className="mt-2"><CopyButton text={h.word} /></div>
                    </div>
                  )}
                </div>
              ))}
            </div>
            {auto.words.length > 24 && (
              <button type="button" onClick={() => setShowAllWords(!showAllWords)} className="mt-3 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/50">
                {showAllWords ? 'Mostrar menos' : `Mostrar las ${auto.words.length} palabras`}
              </button>
            )}
          </div>
        </Card>
      )}

      {/* Pruebas */}
      {scan && (
        <Card>
          <SectionTitle icon={<FileSearch className="h-4 w-4" />} title="Qué se ha abierto y decodificado" hint="Fuentes examinadas en este archivo concreto." />
          <div className="divide-y divide-slate-800/70">
            {scan.checks.map((c) => (
              <div key={c.id} className="flex items-start gap-3 px-5 py-3">
                <span className={cn('mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold', c.status === 'found' ? 'border-emerald-400/60 bg-emerald-400/15 text-emerald-300' : c.status === 'skipped' ? 'border-slate-600 text-slate-500' : 'border-slate-700 bg-slate-800/50 text-slate-400')}>
                  {c.status === 'found' ? '✓' : c.status === 'skipped' ? '–' : '·'}
                </span>
                <div>
                  <div className="text-sm font-medium text-slate-200">{c.label}</div>
                  <div className="mt-0.5 text-xs leading-relaxed text-slate-400">{c.note}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Explorador de flujos */}
      {scan && (
        <Card>
          <SectionTitle
            icon={<Layers className="h-4 w-4" />}
            title="Explorador de flujos decodificados"
            hint="Cada flujo es una forma distinta de leer el archivo. Filtra por técnica o busca dentro de todos a la vez; puedes copiar o descargar el contenido completo."
            right={
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Filter className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
                  <select value={group} onChange={(e) => { setGroup(e.target.value as (typeof GROUPS)[number]); setStreamLimit(40); }} className="rounded-lg border border-slate-800 bg-slate-900/80 py-1.5 pl-8 pr-2 text-xs text-slate-200">
                    {GROUPS.map((g) => <option key={g} value={g}>{g}</option>)}
                  </select>
                </div>
                <input value={filter} onChange={(e) => { setFilter(e.target.value); setStreamLimit(40); }} placeholder="Filtrar flujos…" className="w-36 rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600" />
              </div>
            }
          />
          <div className="max-h-[480px] overflow-auto p-5">
            {!shownStreams.length ? (
              <p className="text-sm text-slate-500">Ningún flujo coincide con el filtro.</p>
            ) : (
              <div className="space-y-2">
                {shownStreams.slice(0, streamLimit).map((s) => (
                  <div key={s.id} className="overflow-hidden rounded-lg border border-slate-800 bg-slate-950/40">
                    <button type="button" onClick={() => setOpenStream(openStream === s.id ? null : s.id)} className="flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-slate-800/30">
                      <span className={cn('mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase', GROUP_STYLE[s.group])}>{s.group}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13px] font-medium text-slate-100">{s.label}</span>
                        <span className="block truncate font-mono text-[11px] text-slate-500">{s.text.slice(0, 130)}</span>
                      </span>
                      <span className={cn('shrink-0 font-mono text-[10px]', s.printable > 0.8 ? 'text-emerald-400' : 'text-slate-500')}>{(s.printable * 100).toFixed(0)}%</span>
                      <ChevronDown className={cn('mt-1 h-3.5 w-3.5 shrink-0 text-slate-500 transition', openStream === s.id && 'rotate-180')} />
                    </button>
                    {openStream === s.id && (
                      <div className="border-t border-slate-800 p-3">
                        <div className="mb-2 flex flex-wrap items-center gap-2">
                          <span className="text-[11px] text-slate-500">{s.detail}</span>
                          <span className="ml-auto flex gap-2">
                            <CopyButton text={s.text} label="Copiar texto" />
                            {s.bytes && (
                              <button type="button" onClick={() => download(`flujo_${s.id}.bin`, new Blob([s.bytes! as BlobPart]))} className="inline-flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1 text-[11px] text-slate-300 hover:border-cyan-400/50">
                                <Download className="h-3 w-3" /> Bytes
                              </button>
                            )}
                          </span>
                        </div>
                        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-[#070b11] p-3 font-mono text-[11px] leading-relaxed text-slate-300">{s.text || '(sin texto legible)'}</pre>
                      </div>
                    )}
                  </div>
                ))}
                {shownStreams.length > streamLimit && (
                  <button type="button" onClick={() => setStreamLimit(streamLimit + 60)} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/50">
                    Mostrar más ({shownStreams.length - streamLimit} restantes)
                  </button>
                )}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

function HitRow({ hit, keyword }: { hit: Hit; keyword: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="overflow-hidden rounded-lg border border-cyan-400/25 bg-cyan-400/[0.04]">
      <button type="button" onClick={() => setOpen(!open)} className="flex w-full items-start gap-2.5 px-3 py-2.5 text-left hover:bg-cyan-400/[0.07]">
        <span className={cn('mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase', GROUP_STYLE[hit.group])}>{hit.group}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <code className="font-mono text-sm font-semibold text-cyan-200">{keyword}</code>
            <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">{hit.variant}</span>
            <span className="truncate text-[11px] text-slate-400">{hit.technique}</span>
          </div>
          <div className="mt-1 truncate font-mono text-[11px] text-slate-400">…{hit.context}…</div>
        </div>
        <ChevronDown className={cn('mt-1 h-3.5 w-3.5 shrink-0 text-slate-500 transition', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="border-t border-cyan-400/20 p-3">
          <p className="text-[11px] text-slate-400">{hit.detail}</p>
          <pre className="mt-2 max-h-52 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-[#070b11] p-2 font-mono text-[11px] leading-relaxed text-slate-300">{hit.streamText.slice(0, 3000)}</pre>
          <div className="mt-2 flex gap-2"><CopyButton text={hit.streamText.slice(0, 3000)} label="Copiar flujo" /></div>
        </div>
      )}
    </div>
  );
}
