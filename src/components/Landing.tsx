import { Crosshair, Eye, FileWarning, FileSearch, Lock, Search, Sparkles, UploadCloud } from 'lucide-react';

interface Props {
  onPick: () => void;
  onDemo: () => void;
  onChallenge: () => void;
  onDisguised: () => void;
  onHiddenWord: () => void;
}

const FORMATS = ['JPEG · PNG · GIF · WebP · TIFF', 'PDF', 'Word · Excel · PowerPoint', 'ZIP · JAR · APK · ODF', 'EXE · DLL · ELF', 'MP3 · FLAC · WAV', 'MP4 · MOV', 'TXT · HTML · SVG · XML'];

export default function Landing({ onPick, onDemo, onChallenge, onDisguised, onHiddenWord }: Props) {
  return (
    <div className="mx-auto w-full max-w-5xl px-4 pb-16 pt-10 sm:px-6 sm:pt-14">
      <div className="animate-fade-up text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs font-medium text-cyan-200">
          <Sparkles className="h-3.5 w-3.5" /> De «sube un archivo» a «resuelve este caso»
        </span>
        <h1 className="mt-6 text-5xl font-extrabold tracking-tight text-white sm:text-7xl">
          Te{' '}
          <span className="bg-gradient-to-r from-cyan-300 via-sky-400 to-indigo-400 bg-clip-text text-transparent">encontré.</span>
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-base leading-relaxed text-slate-400 sm:text-lg">
          No es un visor de archivos: es un <b className="font-semibold text-slate-200">resolutor de casos</b>. Recupera banderas escondidas en imágenes, desenmascara ejecutables camuflados y saca a la luz lo que un documento cuenta de ti.
        </p>
      </div>

      {/* Casos concretos */}
      <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Case
          icon={<Crosshair className="h-5 w-5" />}
          eyebrow="RETO CTF / ESTEGANOGRAFÍA"
          title="Hay un mensaje oculto en una foto"
          detail="Recupera la bandera CIBERISTMO{...} probando 320 combinaciones de planos de bits."
          cta="Resolver el vuelo 404"
          onClick={onChallenge}
        />
        <Case
          icon={<Search className="h-5 w-5" />}
          eyebrow="CUALQUIER ARCHIVO · CUALQUIER PALABRA"
          title="Busco una palabra escondida"
          detail="TXT, PDF, DOCX, ZIP, EXE, PNG… encuentra «pulela» o lo que sea en texto invisible, XOR, ROT, base64 y más."
          cta="Probar con palabra oculta"
          onClick={onHiddenWord}
        />
        <Case
          icon={<FileWarning className="h-5 w-5" />}
          eyebrow="ARCHIVO SOSPECHOSO"
          title="¿Es un PDF o un ejecutable?"
          detail="Compara extensión y contenido real, busca polizones, macros, hashes y datos añadidos al final."
          cta="Probar con un señuelo"
          onClick={onDisguised}
        />
        <Case
          icon={<Eye className="h-5 w-5" />}
          eyebrow="ANTES DE COMPARTIR"
          title="¿Qué filtra este archivo de mí?"
          detail="Autor, empresa, GPS, revisión de cambios, hojas ocultas y software usado."
          cta="Ver archivo de ejemplo"
          onClick={onDemo}
        />
      </div>

      {/* Dropzone */}
      <div
        role="button"
        tabIndex={0}
        onClick={onPick}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onPick()}
        className="group relative mt-5 cursor-pointer overflow-hidden rounded-3xl border-2 border-dashed border-cyan-400/30 bg-[#0a0e15]/80 p-9 text-center transition hover:border-cyan-300/70 hover:bg-cyan-400/[0.04] sm:p-12"
      >
        <div className="pointer-events-none absolute inset-x-0 h-24 animate-scan bg-gradient-to-b from-transparent via-cyan-400/15 to-transparent" />
        <div className="pointer-events-none absolute left-4 top-4 h-5 w-5 border-l-2 border-t-2 border-cyan-300/70" />
        <div className="pointer-events-none absolute right-4 top-4 h-5 w-5 border-r-2 border-t-2 border-cyan-300/70" />
        <div className="pointer-events-none absolute bottom-4 left-4 h-5 w-5 border-b-2 border-l-2 border-cyan-300/70" />
        <div className="pointer-events-none absolute bottom-4 right-4 h-5 w-5 border-b-2 border-r-2 border-cyan-300/70" />
        <div className="relative">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-300 shadow-[0_0_40px_rgba(34,211,238,.25)] transition group-hover:scale-105">
            <UploadCloud className="h-7 w-7" />
          </div>
          <p className="mt-4 text-xl font-semibold text-slate-100">O sube tu propio archivo</p>
          <p className="mt-1 text-sm text-slate-400">Arrastra aquí o haz clic · varios a la vez · hasta 150 MB cada uno</p>
          <button type="button" onClick={(e) => { e.stopPropagation(); onPick(); }} className="mt-5 rounded-xl bg-cyan-400 px-5 py-2.5 text-sm font-bold text-slate-950 shadow-[0_8px_30px_rgba(34,211,238,.3)] transition hover:bg-cyan-300">
            Elegir archivos
          </button>
        </div>
      </div>

      <p className="mt-4 flex items-center justify-center gap-2 text-center text-xs text-slate-500">
        <Lock className="h-3.5 w-3.5 text-emerald-400" />
        Todo el análisis ocurre en tu navegador. Ningún archivo se sube a ningún servidor.
      </p>

      {/* Qué hace exactamente */}
      <div className="mt-12">
        <h2 className="text-center text-xs font-bold uppercase tracking-[0.2em] text-slate-500">Las 4 herramientas, sin nombres genéricos</h2>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Tool n="01" title="Buscar lo oculto" items={['Cualquier archivo y cualquier palabra', '320+ configuraciones LSB y planos de bits', 'ZIP / DOCX / PDF descomprimidos', 'XOR, ROT-1…25, base64, hex, UTF-16', 'Texto invisible, espacios y acrosticos']} />
          <Tool n="02" title="¿Archivo falso?" items={['Extensión vs. magic bytes', 'Ejecutables y ZIP incrustados', 'Hashes y mapa de entropía', 'Visor hexadecimal y cadenas', 'ELA + macros + JavaScript en PDF']} />
          <Tool n="03" title="¿Qué filtra?" items={['EXIF, GPS, XMP e IPTC', 'Autor, empresa, último editor', 'Cambios y comentarios en Office', 'Hojas ocultas y notas del orador', 'Mapa de la ubicación encontrada']} />
          <Tool n="04" title="Veredicto y pasos" items={['Limpio → Peligroso', 'Puntuaciones forense y privacidad', 'Resumen y recomendaciones', 'Informe HTML / PDF / JSON', 'Copia limpia de JPG y PNG']} />
        </div>
      </div>

      <div className="mt-10 text-center">
        <div className="mb-3 flex items-center justify-center gap-2 text-xs font-semibold uppercase tracking-widest text-slate-500">
          <FileSearch className="h-4 w-4" /> Formatos que entiende
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          {FORMATS.map((f) => (
            <span key={f} className="rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1 font-mono text-[11px] text-slate-400">{f}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function Case({ icon, eyebrow, title, detail, cta, onClick }: { icon: React.ReactNode; eyebrow: string; title: string; detail: string; cta: string; onClick: () => void }) {
  return (
    <div className="flex flex-col rounded-2xl border border-slate-800/90 bg-[#0b0f16]/80 p-5 transition hover:border-cyan-400/40">
      <div className="flex items-center gap-2 text-cyan-300">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-400/25 bg-cyan-400/10">{icon}</div>
        <span className="text-[10px] font-bold uppercase tracking-[0.12em]">{eyebrow}</span>
      </div>
      <h3 className="mt-4 text-[15px] font-semibold leading-snug text-slate-100">{title}</h3>
      <p className="mt-2 flex-1 text-xs leading-relaxed text-slate-400">{detail}</p>
      <button type="button" onClick={onClick} className="mt-4 rounded-lg border border-cyan-400/40 bg-cyan-400/10 px-3 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-400/20">
        {cta} →
      </button>
    </div>
  );
}

function Tool({ n, title, items }: { n: string; title: string; items: string[] }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-[#0b0f16]/70 p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        <span className="font-mono text-xs text-slate-700">{n}</span>
      </div>
      <ul className="mt-3 space-y-1.5">
        {items.map((i) => (
          <li key={i} className="flex gap-2 text-[11.5px] leading-snug text-slate-400">
            <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-cyan-400" />
            {i}
          </li>
        ))}
      </ul>
    </div>
  );
}
