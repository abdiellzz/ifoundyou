import { useCallback, useEffect, useRef, useState } from 'react';
import { ClipboardCheck, Crosshair, Eye, FileWarning, Loader2, Lock, Plus, UploadCloud } from 'lucide-react';
import type { AnalysisResult } from './lib/types';
import { analyzeFile } from './lib/analyze';
import { makeChallenge404, makeDemoFile, makeDisguisedFile, makeHiddenWordDemo } from './lib/demo';
import { formatBytes } from './lib/utils';
import { VERDICT_META } from './lib/report';
import { cn } from './utils/cn';
import ChallengeView from './components/ChallengeView';
import Landing from './components/Landing';
import Sidebar, { type Job } from './components/Sidebar';
import ForensicsView from './components/ForensicsView';
import MetadataView from './components/MetadataView';
import ReportView from './components/ReportView';
import { Logo, VerdictBadge } from './components/ui';

type Tab = 'resolver' | 'forense' | 'metadatos' | 'informe';

export default function App() {
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('resolver');
  const [solvedFlags, setSolvedFlags] = useState<Record<string, string[]>>({});
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const queue = useRef<{ file: File; jobId: string }[]>([]);
  const running = useRef(false);
  const pendingSelect = useRef<string | null>(null);

  const pump = useCallback(async () => {
    if (running.current) return;
    running.current = true;
    while (queue.current.length) {
      const { file, jobId } = queue.current.shift()!;
      try {
        const res = await analyzeFile(file, (message, progress) =>
          setJobs((js) => js.map((j) => (j.id === jobId ? { ...j, message, progress } : j))),
        );
        setResults((rs) => [...rs, res]);
        if (pendingSelect.current === file.name) {
          setSelected(res.id);
          pendingSelect.current = null;
        } else setSelected((cur) => cur ?? res.id);
        setJobs((js) => js.filter((j) => j.id !== jobId));
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'No se pudo analizar el archivo.';
        setJobs((js) => js.map((j) => (j.id === jobId ? { ...j, error: msg, progress: 100 } : j)));
      }
    }
    running.current = false;
  }, []);

  const handleFiles = useCallback(
    (list: FileList | File[], target: Tab = 'resolver') => {
      const files = Array.from(list);
      if (!files.length) return;
      setTab(target);
      const newJobs: Job[] = files.map((f) => ({
        id: `${f.name}-${Math.random().toString(36).slice(2, 9)}`,
        name: f.name,
        size: f.size,
        progress: 0,
        message: 'En cola…',
      }));
      setJobs((js) => [...js, ...newJobs]);
      files.forEach((file, i) => queue.current.push({ file, jobId: newJobs[i].id }));
      void pump();
    },
    [pump],
  );

  useEffect(() => {
    let depth = 0;
    const hasFiles = (e: DragEvent) => !!e.dataTransfer && Array.from(e.dataTransfer.types).includes('Files');
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth++;
      setDragging(true);
    };
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    };
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth = 0;
      setDragging(false);
      if (e.dataTransfer?.files.length) handleFiles(e.dataTransfer.files);
    };
    window.addEventListener('dragenter', enter);
    window.addEventListener('dragover', over);
    window.addEventListener('dragleave', leave);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragenter', enter);
      window.removeEventListener('dragover', over);
      window.removeEventListener('dragleave', leave);
      window.removeEventListener('drop', drop);
    };
  }, [handleFiles]);

  const pick = () => inputRef.current?.click();
  const startWith = (file: File, target: Tab) => {
    pendingSelect.current = file.name;
    handleFiles([file], target);
  };
  const demo = async () => startWith(await makeDemoFile(), 'metadatos');
  const challenge = async () => startWith(await makeChallenge404(), 'resolver');
  const disguised = () => startWith(makeDisguisedFile(), 'forense');
  const hiddenWord = () => startWith(makeHiddenWordDemo(), 'resolver');

  const remove = (id: string) => {
    setResults((rs) => {
      const next = rs.filter((r) => r.id !== id);
      setSelected((cur) => (cur === id ? next[0]?.id ?? null : cur));
      return next;
    });
    setSolvedFlags((m) => {
      const n = { ...m };
      delete n[id];
      return n;
    });
  };
  const current = results.find((r) => r.id === selected) ?? null;
  const empty = results.length === 0 && jobs.length === 0;
  const selectResult = (id: string) => {
    setSelected(id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };
  const goTab = (t: Tab) => {
    setTab(t);
    window.scrollTo({ top: 0 });
  };

  const tabs: { id: Tab; label: string; tool: string; icon: React.ReactNode; color: string }[] = [
    { id: 'resolver', label: 'Buscar lo oculto', tool: 'PALABRAS · BANDERAS · CUALQUIER ARCHIVO', icon: <Crosshair className="h-4 w-4" />, color: '#22d3ee' },
    { id: 'forense', label: '¿Archivo falso?', tool: 'FORENSE · CAMUFLAJE Y POLIZONES', icon: <FileWarning className="h-4 w-4" />, color: '#fb923c' },
    { id: 'metadatos', label: '¿Qué filtra?', tool: 'AUTOR · GPS · EDICIONES', icon: <Eye className="h-4 w-4" />, color: '#a78bfa' },
    { id: 'informe', label: 'Veredicto y pasos', tool: 'INFORME + QUÉ HACER', icon: <ClipboardCheck className="h-4 w-4" />, color: '#34d399' },
  ];

  return (
    <div className="flex min-h-screen flex-col">
      <input
        ref={inputRef}
        type="file"
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files) handleFiles(e.target.files);
          e.target.value = '';
        }}
      />

      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#06080c]/80 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-[1400px] items-center justify-between gap-4 px-4 sm:px-6">
          <button
            type="button"
            onClick={() => {
              setSelected(null);
              setResults([]);
              setJobs([]);
              setSolvedFlags({});
              queue.current = [];
            }}
            className="flex items-center gap-2.5"
            aria-label="FoundYou — inicio"
          >
            <Logo className="h-8 w-8 text-cyan-300 drop-shadow-[0_0_10px_rgba(34,211,238,.6)]" />
            <div className="text-left leading-none">
              <div className="text-lg font-extrabold tracking-tight text-white">Found<span className="text-cyan-300">You</span></div>
              <div className="mt-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-slate-500">Te encontré</div>
            </div>
          </button>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-medium text-emerald-300 sm:inline-flex">
              <Lock className="h-3 w-3" /> 100 % local · nada se sube
            </span>
            {!empty && (
              <button type="button" onClick={pick} className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-400 px-3.5 py-2 text-sm font-bold text-slate-950 transition hover:bg-cyan-300">
                <Plus className="h-4 w-4" /> <span className="hidden sm:inline">Analizar más</span>
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1">
        {empty ? (
          <Landing onPick={pick} onDemo={demo} onChallenge={challenge} onDisguised={disguised} onHiddenWord={hiddenWord} />
        ) : (
          <div className="mx-auto grid max-w-[1400px] gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[290px_minmax(0,1fr)]">
            <Sidebar
              results={results}
              jobs={jobs}
              selected={selected}
              solvedFlags={solvedFlags}
              onSelect={selectResult}
              onRemove={remove}
              onDismissJob={(id) => setJobs((js) => js.filter((j) => j.id !== id))}
              onAdd={pick}
            />

            <div className="min-w-0">
              {!current ? (
                <div className="flex min-h-[50vh] flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 p-10 text-center">
                  {jobs.some((j) => !j.error) ? (
                    <>
                      <Loader2 className="h-10 w-10 animate-spin text-cyan-300" />
                      <p className="mt-4 text-lg font-semibold text-slate-100">Analizando…</p>
                      <p className="mt-1 text-sm text-slate-400">{jobs.find((j) => !j.error)?.message}</p>
                    </>
                  ) : (
                    <>
                      <UploadCloud className="h-10 w-10 text-slate-600" />
                      <p className="mt-4 text-slate-400">Selecciona un archivo de la lista o añade uno nuevo.</p>
                    </>
                  )}
                </div>
              ) : (
                <div key={current.id} className="animate-fade-up">
                  <div className="rounded-2xl border border-slate-800/90 bg-[#0b0f16]/90 p-4 sm:p-5">
                    <div className="flex flex-wrap items-center gap-3">
                      <div className="min-w-0 flex-1">
                        <h1 className="truncate text-xl font-bold tracking-tight text-white" title={current.name}>{current.name}</h1>
                        <p className="mt-0.5 truncate text-xs text-slate-400">
                          {current.typeLabel} · {formatBytes(current.size)} · SHA-256 <span className="font-mono text-slate-500">{current.hashes.sha256.slice(0, 16)}…</span>
                        </p>
                      </div>
                      <VerdictBadge v={current.verdict} />
                    </div>
                  </div>

                  <div className="sticky top-16 z-30 -mx-1 mt-4 bg-[#06080c]/85 px-1 py-2 backdrop-blur-xl">
                    <div role="tablist" className="grid grid-cols-2 gap-1.5 rounded-2xl border border-slate-800/90 bg-[#0b0f16] p-1.5 xl:grid-cols-4">
                      {tabs.map((t) => {
                        const active = tab === t.id;
                        const v = VERDICT_META[current.verdict];
                        const color = t.id === 'informe' ? v.hex : t.color;
                        return (
                          <button
                            key={t.id}
                            role="tab"
                            aria-selected={active}
                            type="button"
                            onClick={() => goTab(t.id)}
                            className={cn(
                              'flex flex-col items-center justify-center gap-0.5 rounded-xl px-2 py-2.5 text-center transition sm:flex-row sm:gap-2.5 sm:px-3 sm:text-left',
                              active ? 'text-white' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200',
                            )}
                            style={active ? { background: `${color}1c`, boxShadow: `inset 0 0 0 1px ${color}77` } : undefined}
                          >
                            <span style={{ color: active ? color : undefined }} className={active ? '' : 'text-slate-500'}>{t.icon}</span>
                            <span className="flex flex-col leading-tight">
                              <span className="text-[12px] font-semibold sm:text-[13px]">{t.label}</span>
                              <span className="mt-0.5 hidden text-[9px] uppercase tracking-wider text-slate-500 xl:block">{t.tool}</span>
                            </span>
                            {t.id === 'resolver' && (solvedFlags[current.id]?.length ?? 0) > 0 && (
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  <div className="mt-4">
                    {tab === 'resolver' && (
                      <ChallengeView
                        r={current}
                        onFlags={(id, flags) => setSolvedFlags((m) => ({ ...m, [id]: flags }))}
                        onTab={(t) => goTab(t)}
                      />
                    )}
                    {tab === 'forense' && <ForensicsView r={current} />}
                    {tab === 'metadatos' && <MetadataView r={current} />}
                    {tab === 'informe' && <ReportView r={current} flags={solvedFlags[current.id]} onTab={(t) => goTab(t)} />}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      <footer className="border-t border-slate-800/70 py-5 text-center text-[11px] text-slate-600">
        FoundYou · Te encontré — análisis estático en tu navegador. Indicios técnicos, no una pericia forense certificada.
      </footer>

      {dragging && (
        <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-[#06080c]/85 backdrop-blur-sm">
          <div className="rounded-3xl border-2 border-dashed border-cyan-300 bg-cyan-400/10 px-16 py-14 text-center shadow-[0_0_80px_rgba(34,211,238,.3)]">
            <UploadCloud className="mx-auto h-14 w-14 text-cyan-300" />
            <p className="mt-4 text-2xl font-bold text-white">Suelta para analizar</p>
          </div>
        </div>
      )}
    </div>
  );
}
