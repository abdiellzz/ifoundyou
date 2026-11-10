import { useRef, useState } from 'react';
import { Activity, Binary, Fingerprint, FlaskConical, Layers, ScanSearch, TextSearch, ShieldCheck } from 'lucide-react';
import type { AnalysisResult } from '../lib/types';
import { formatBytes, formatDate } from '../lib/utils';
import { Card, CopyButton, EmptyOk, FindingCard, SectionTitle, SeverityBadge } from './ui';
import EntropyChart from './EntropyChart';
import HexViewer from './HexViewer';
import ImageLab from './ImageLab';
import StringsExplorer from './StringsExplorer';
import { cn } from '../utils/cn';

const LAB_TYPES = ['JPEG', 'PNG', 'GIF', 'WebP', 'BMP', 'AVIF'];

export default function ForensicsView({ r }: { r: AnalysisResult }) {
  const [hexOffset, setHexOffset] = useState(0);
  const hexRef = useRef<HTMLDivElement>(null);
  const jump = (o: number) => {
    setHexOffset(o);
    setTimeout(() => hexRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 40);
  };
  const forense = r.findings.filter((f) => f.axis === 'forense');
  const isImg = !!r.type && LAB_TYPES.includes(r.type.name);
  const ent = r.entropy.overall;
  const entLabel = ent < 4.5 ? 'Estructurado / texto' : ent < 6.5 ? 'Datos mixtos / código' : ent < 7.4 ? 'Comprimido' : 'Cifrado o aleatorio';
  const marks = [...r.embedded.map((h) => h.offset), ...(r.trailing ? [r.trailing.offset] : [])];

  return (
    <div className="space-y-6">
      {/* Identificación */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Tipo real (magic bytes)" value={r.typeLabel} sub={r.type?.mime ?? 'sin firma conocida'} />
        <Stat
          label="Extensión declarada"
          value={r.ext ? `.${r.ext}` : '(ninguna)'}
          sub={r.extMismatch ? 'NO coincide con el contenido' : 'Coincide con el contenido'}
          tone={r.extMismatch ? 'bad' : 'ok'}
        />
        <Stat label="Tamaño" value={formatBytes(r.size)} sub={`${r.size.toLocaleString('es-ES')} bytes`} />
        <div className="rounded-xl border border-slate-800/90 bg-[#0b0f16]/90 p-4">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Entropía global</div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="font-mono text-xl font-semibold text-slate-50">{ent.toFixed(2)}</span>
            <span className="text-xs text-slate-500">/ 8</span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-800">
            <div className="h-full rounded-full" style={{ width: `${(ent / 8) * 100}%`, background: ent > 7.4 ? '#f87171' : ent > 6.5 ? '#fbbf24' : '#34d399' }} />
          </div>
          <div className="mt-1.5 text-xs text-slate-400">{entLabel}</div>
        </div>
      </div>

      {/* Hallazgos */}
      <Card>
        <SectionTitle
          icon={<ScanSearch className="h-4 w-4" />}
          title="Hallazgos forenses"
          hint="Integridad, estructura y señales de manipulación, camuflaje o contenido peligroso."
          right={<span className="rounded-full bg-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">{forense.length}</span>}
        />
        <div className="space-y-3 p-5">
          {forense.length ? (
            forense.map((f) => <FindingCard key={f.id} f={f} onOffset={jump} />)
          ) : (
            <EmptyOk>
              <b>Estructura limpia.</b> La extensión coincide con el contenido, no hay archivos incrustados ni datos ocultos tras el final del archivo y no se detectaron funciones activas peligrosas.
            </EmptyOk>
          )}
        </div>
      </Card>

      {/* Hashes */}
      <Card>
        <SectionTitle icon={<Fingerprint className="h-4 w-4" />} title="Huellas criptográficas" hint="Identifican de forma única el archivo. Úsalas para verificar integridad, comparar versiones o consultar bases de reputación." />
        <div className="divide-y divide-slate-800/70">
          {(
            [
              ['MD5', r.hashes.md5],
              ['SHA-1', r.hashes.sha1],
              ['SHA-256', r.hashes.sha256],
              ['SHA-512', r.hashes.sha512],
            ] as const
          ).map(([k, v]) => (
            <div key={k} className="flex items-center gap-3 px-5 py-3">
              <span className="w-16 shrink-0 text-xs font-bold uppercase tracking-wider text-slate-500">{k}</span>
              <code className="min-w-0 flex-1 break-all font-mono text-[12px] text-cyan-100/90">{v}</code>
              <CopyButton text={v} />
            </div>
          ))}
        </div>
      </Card>

      {/* Entropía */}
      <Card>
        <SectionTitle icon={<Activity className="h-4 w-4" />} title="Mapa de entropía" hint="Cada barra es un bloque del archivo. Las zonas de entropía muy alta dentro de un formato que no debería tenerla delatan datos cifrados, comprimidos o añadidos. Haz clic en una barra para ver sus bytes." />
        <div className="p-5">
          <EntropyChart r={r} onOffset={jump} />
        </div>
      </Card>

      {/* Incrustados */}
      <Card>
        <SectionTitle icon={<Layers className="h-4 w-4" />} title="Contenido oculto e incrustado" hint="Archivos dentro de otros archivos y bytes sobrantes tras el final lógico del formato (técnica habitual de polyglots y esteganografía por anexo)." />
        <div className="space-y-4 p-5">
          {r.embedded.length === 0 && !r.trailing ? (
            <EmptyOk>No se encontraron firmas de otros archivos dentro de este ni datos tras su final lógico.</EmptyOk>
          ) : (
            <>
              {r.trailing && (
                <div className="rounded-xl border border-pink-400/30 bg-pink-400/5 p-4">
                  <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-pink-200">
                    {formatBytes(r.trailing.size)} tras el final lógico
                    <button type="button" onClick={() => jump(r.trailing!.offset)} className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300">
                      @0x{r.trailing.offset.toString(16).toUpperCase()}
                    </button>
                  </div>
                  <dl className="mt-2 grid gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
                    <div><dt className="text-slate-500">Empieza por</dt><dd className="font-mono text-slate-200">{r.trailing.startsWith}</dd></div>
                    <div><dt className="text-slate-500">Parece ser</dt><dd className="text-slate-200">{r.trailing.detected ?? 'datos sin firma'}</dd></div>
                    <div><dt className="text-slate-500">Entropía</dt><dd className="font-mono text-slate-200">{r.trailing.entropy.toFixed(2)} / 8</dd></div>
                  </dl>
                </div>
              )}
              {r.embedded.length > 0 && (
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-slate-900/70 text-[11px] uppercase tracking-wider text-slate-500">
                      <tr><th className="px-3 py-2">Offset</th><th className="px-3 py-2">Tipo</th><th className="px-3 py-2">Gravedad</th><th className="px-3 py-2">Descripción</th></tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {r.embedded.map((h, i) => (
                        <tr key={i} className="align-top">
                          <td className="px-3 py-2">
                            <button type="button" onClick={() => jump(h.offset)} className="font-mono text-xs text-cyan-300 hover:underline">0x{h.offset.toString(16).toUpperCase()}</button>
                          </td>
                          <td className="px-3 py-2 font-medium text-slate-100">{h.name}</td>
                          <td className="px-3 py-2"><SeverityBadge s={h.severity} /></td>
                          <td className="px-3 py-2 text-slate-400">{h.note}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      </Card>

      {/* Laboratorio de imagen */}
      {isImg && (
        <Card>
          <SectionTitle icon={<FlaskConical className="h-4 w-4" />} title="Laboratorio de imagen" hint="Herramientas visuales para detectar retoques (ELA) y datos escondidos en los bits menos significativos (plano LSB)." />
          <ImageLab file={r.file} stego={r.stego} />
        </Card>
      )}

      {/* Cadenas */}
      <Card>
        <SectionTitle icon={<TextSearch className="h-4 w-4" />} title="Cadenas de texto e indicadores" hint="Texto legible (ASCII y UTF-16) extraído del binario. Se destacan URLs, correos, IPs, rutas con nombres de usuario, credenciales y APIs sospechosas." />
        <StringsExplorer r={r} onOffset={jump} />
      </Card>

      {/* Hex */}
      <div ref={hexRef}>
        <Card>
          <SectionTitle icon={<Binary className="h-4 w-4" />} title="Visor hexadecimal" hint="Navega por los bytes reales del archivo. Los enlaces de offset de toda la herramienta te traen aquí." />
          <HexViewer file={r.file} offset={hexOffset} onOffset={setHexOffset} mark={marks} />
        </Card>
      </div>

      <p className="flex items-center gap-2 px-1 pb-2 text-xs text-slate-500">
        <ShieldCheck className="h-4 w-4 text-emerald-400/70" />
        Análisis realizado en {r.durationMs} ms · última modificación según el sistema: {formatDate(r.lastModified)}
      </p>
    </div>
  );
}

function Stat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'ok' | 'bad' }) {
  return (
    <div className={cn('rounded-xl border bg-[#0b0f16]/90 p-4', tone === 'bad' ? 'border-red-500/50 bg-red-500/5' : 'border-slate-800/90')}>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-1 truncate text-lg font-semibold text-slate-50" title={value}>{value}</div>
      {sub && <div className={cn('mt-0.5 truncate text-xs', tone === 'bad' ? 'font-semibold text-red-300' : tone === 'ok' ? 'text-emerald-400/90' : 'text-slate-400')}>{sub}</div>}
    </div>
  );
}
