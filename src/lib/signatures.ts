import type { Category, TypeInfo } from './types';
import { ascii, matchAt } from './utils';

interface Sig {
  info: TypeInfo;
  magic: (number | null)[];
  offset?: number;
}

const t = (name: string, ext: string[], mime: string, category: Category): TypeInfo => ({
  name,
  ext,
  mime,
  category,
});

const OFFICE_ZIP_EXT = [
  'zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'dotx', 'xltx', 'potx', 'odt', 'ods',
  'odp', 'odg', 'jar', 'war', 'apk', 'aar', 'epub', 'xpi', 'vsix', 'nupkg', 'kmz', 'crx', 'ipa',
  'whl', 'xps', 'sketch', 'key', 'pages', 'numbers', 'mmap',
];

const SIGS: Sig[] = [
  { info: t('JPEG', ['jpg', 'jpeg', 'jpe', 'jfif'], 'image/jpeg', 'image'), magic: [0xff, 0xd8, 0xff] },
  { info: t('PNG', ['png', 'apng'], 'image/png', 'image'), magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { info: t('GIF', ['gif'], 'image/gif', 'image'), magic: [0x47, 0x49, 0x46, 0x38, null, 0x61] },
  { info: t('TIFF', ['tif', 'tiff', 'dng', 'cr2', 'nef', 'arw'], 'image/tiff', 'image'), magic: [0x49, 0x49, 0x2a, 0x00] },
  { info: t('TIFF', ['tif', 'tiff', 'dng', 'cr2', 'nef', 'arw'], 'image/tiff', 'image'), magic: [0x4d, 0x4d, 0x00, 0x2a] },
  { info: t('Photoshop (PSD)', ['psd'], 'image/vnd.adobe.photoshop', 'image'), magic: [0x38, 0x42, 0x50, 0x53] },
  { info: t('Icono (ICO)', ['ico'], 'image/x-icon', 'image'), magic: [0x00, 0x00, 0x01, 0x00, null, 0x00] },
  { info: t('PDF', ['pdf'], 'application/pdf', 'document'), magic: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { info: t('Documento OLE2 (Office clásico / MSI)', ['doc', 'xls', 'ppt', 'msi', 'msg', 'dot', 'xlt', 'pps', 'vsd', 'pub', 'mpp'], 'application/x-ole-storage', 'document'), magic: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] },
  { info: t('RTF', ['rtf'], 'application/rtf', 'document'), magic: [0x7b, 0x5c, 0x72, 0x74, 0x66] },
  { info: t('ZIP / OOXML / ODF', OFFICE_ZIP_EXT, 'application/zip', 'archive'), magic: [0x50, 0x4b, 0x03, 0x04] },
  { info: t('ZIP (vacío)', OFFICE_ZIP_EXT, 'application/zip', 'archive'), magic: [0x50, 0x4b, 0x05, 0x06] },
  { info: t('RAR', ['rar'], 'application/vnd.rar', 'archive'), magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { info: t('7-Zip', ['7z'], 'application/x-7z-compressed', 'archive'), magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { info: t('GZIP', ['gz', 'tgz'], 'application/gzip', 'archive'), magic: [0x1f, 0x8b, 0x08] },
  { info: t('BZIP2', ['bz2', 'tbz2'], 'application/x-bzip2', 'archive'), magic: [0x42, 0x5a, 0x68, null] },
  { info: t('XZ', ['xz', 'txz'], 'application/x-xz', 'archive'), magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { info: t('TAR', ['tar'], 'application/x-tar', 'archive'), magic: [0x75, 0x73, 0x74, 0x61, 0x72], offset: 257 },
  { info: t('Ejecutable Windows (PE/MZ)', ['exe', 'dll', 'sys', 'scr', 'ocx', 'cpl', 'drv', 'efi'], 'application/vnd.microsoft.portable-executable', 'executable'), magic: [0x4d, 0x5a] },
  { info: t('Ejecutable Linux (ELF)', ['elf', 'so', 'bin', 'o', 'out', 'ko'], 'application/x-elf', 'executable'), magic: [0x7f, 0x45, 0x4c, 0x46] },
  { info: t('Mach-O (macOS)', ['dylib', 'bin', 'o', 'macho'], 'application/x-mach-binary', 'executable'), magic: [0xcf, 0xfa, 0xed, 0xfe] },
  { info: t('Mach-O (macOS)', ['dylib', 'bin', 'o', 'macho'], 'application/x-mach-binary', 'executable'), magic: [0xce, 0xfa, 0xed, 0xfe] },
  { info: t('Java class / Mach-O universal', ['class', 'bin'], 'application/java-vm', 'executable'), magic: [0xca, 0xfe, 0xba, 0xbe] },
  { info: t('Dalvik DEX (Android)', ['dex'], 'application/vnd.android.dex', 'executable'), magic: [0x64, 0x65, 0x78, 0x0a, null, null, null, 0x00] },
  { info: t('WebAssembly', ['wasm'], 'application/wasm', 'executable'), magic: [0x00, 0x61, 0x73, 0x6d] },
  { info: t('Acceso directo Windows (LNK)', ['lnk'], 'application/x-ms-shortcut', 'executable'), magic: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },
  { info: t('MP3 (ID3)', ['mp3'], 'audio/mpeg', 'audio'), magic: [0x49, 0x44, 0x33] },
  { info: t('OGG', ['ogg', 'oga', 'ogv', 'opus'], 'audio/ogg', 'audio'), magic: [0x4f, 0x67, 0x67, 0x53] },
  { info: t('FLAC', ['flac'], 'audio/flac', 'audio'), magic: [0x66, 0x4c, 0x61, 0x43] },
  { info: t('Matroska / WebM', ['mkv', 'webm', 'mka'], 'video/x-matroska', 'video'), magic: [0x1a, 0x45, 0xdf, 0xa3] },
  { info: t('FLV', ['flv'], 'video/x-flv', 'video'), magic: [0x46, 0x4c, 0x56, 0x01] },
  { info: t('SQLite', ['sqlite', 'db', 'sqlite3', 'db3'], 'application/vnd.sqlite3', 'data'), magic: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00] },
  { info: t('KeePass (KDBX)', ['kdbx'], 'application/x-keepass2', 'data'), magic: [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5] },
  { info: t('Captura de red (PCAP)', ['pcap', 'cap'], 'application/vnd.tcpdump.pcap', 'data'), magic: [0xd4, 0xc3, 0xb2, 0xa1] },
  { info: t('Captura de red (PCAP)', ['pcap', 'cap'], 'application/vnd.tcpdump.pcap', 'data'), magic: [0xa1, 0xb2, 0xc3, 0xd4] },
  { info: t('PCAPNG', ['pcapng'], 'application/x-pcapng', 'data'), magic: [0x0a, 0x0d, 0x0d, 0x0a] },
  { info: t('Volcado de memoria (MDMP)', ['dmp', 'mdmp'], 'application/x-dmp', 'data'), magic: [0x4d, 0x44, 0x4d, 0x50] },
  { info: t('Registro de Windows (regf)', ['dat', 'hiv'], 'application/x-registry', 'data'), magic: [0x72, 0x65, 0x67, 0x66] },
  { info: t('Volumen cifrado LUKS', ['img', 'luks'], 'application/x-luks', 'data'), magic: [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe] },
  { info: t('Fuente TrueType', ['ttf'], 'font/ttf', 'data'), magic: [0x00, 0x01, 0x00, 0x00, 0x00] },
  { info: t('Fuente OpenType', ['otf'], 'font/otf', 'data'), magic: [0x4f, 0x54, 0x54, 0x4f] },
  { info: t('WOFF', ['woff'], 'font/woff', 'data'), magic: [0x77, 0x4f, 0x46, 0x46] },
  { info: t('WOFF2', ['woff2'], 'font/woff2', 'data'), magic: [0x77, 0x4f, 0x46, 0x32] },
  { info: t('BMP', ['bmp', 'dib'], 'image/bmp', 'image'), magic: [0x42, 0x4d, null, null, null, null, 0x00, 0x00, 0x00, 0x00] },
];

const BINARY_EXTS = new Set<string>();
SIGS.forEach((s) => s.info.ext.forEach((e) => BINARY_EXTS.add(e)));
['webp', 'wav', 'avi', 'mp4', 'mov', 'm4a', 'm4v', '3gp', 'heic', 'heif', 'avif'].forEach((e) => BINARY_EXTS.add(e));

const ALIASES: Record<string, string[]> = {
  jpg: ['jpeg', 'jpe', 'jfif'],
  jpeg: ['jpg', 'jpe', 'jfif'],
  tif: ['tiff'],
  tiff: ['tif'],
  htm: ['html'],
  yml: ['yaml'],
};

export function isExecutableExt(ext: string): boolean {
  return /^(exe|dll|scr|com|bat|cmd|msi|ps1|vbs|vbe|js|jse|wsf|hta|jar|lnk|sh|apk|app|cpl|pif|reg|sys)$/i.test(ext);
}

function textKind(b: Uint8Array): TypeInfo | null {
  const n = Math.min(b.length, 4096);
  if (n === 0) return null;
  let bad = 0;
  let start = 0;
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) start = 3;
  else if ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff)) {
    // UTF-16 con BOM
    return t('Texto UTF-16', ['txt', 'csv', 'log', 'reg', 'ini'], 'text/plain', 'text');
  }
  for (let i = start; i < n; i++) {
    const c = b[i];
    if (c === 0 || (c < 9) || (c > 13 && c < 32 && c !== 27)) bad++;
  }
  if (bad / n > 0.01) return null;
  const head = new TextDecoder('utf-8').decode(b.subarray(0, n)).trimStart().toLowerCase();
  if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg')))
    return t('SVG', ['svg'], 'image/svg+xml', 'text');
  if (head.startsWith('<?xml')) return t('XML', ['xml', 'xsd', 'xsl', 'plist', 'rels', 'config', 'csproj'], 'application/xml', 'text');
  if (head.startsWith('<!doctype html') || head.startsWith('<html') || head.includes('<head') )
    return t('HTML', ['html', 'htm', 'xhtml'], 'text/html', 'text');
  if (head.startsWith('#!')) return t('Script (shebang)', ['sh', 'py', 'pl', 'rb', 'js', 'bash', 'zsh'], 'text/x-script', 'text');
  if (head.startsWith('-----begin')) return t('Texto PEM / PGP', ['pem', 'key', 'crt', 'cer', 'asc', 'pub', 'gpg'], 'application/x-pem-file', 'text');
  if (head.startsWith('{') || head.startsWith('[')) return t('JSON / texto estructurado', ['json', 'txt', 'js', 'map', 'geojson', 'ipynb'], 'application/json', 'text');
  return t('Texto plano', [], 'text/plain', 'text');
}

export function detectType(b: Uint8Array): TypeInfo | null {
  if (b.length === 0) return null;
  // RIFF contenedores
  if (matchAt(b, 0, [0x52, 0x49, 0x46, 0x46]) && b.length >= 12) {
    const f = ascii(b, 8, 4);
    if (f === 'WEBP') return t('WebP', ['webp'], 'image/webp', 'image');
    if (f === 'WAVE') return t('WAV', ['wav'], 'audio/wav', 'audio');
    if (f === 'AVI ') return t('AVI', ['avi'], 'video/x-msvideo', 'video');
    return t('RIFF', [], 'application/x-riff', 'data');
  }
  // ISO BMFF (mp4, mov, heic…)
  if (matchAt(b, 4, [0x66, 0x74, 0x79, 0x70]) && b.length >= 12) {
    const brand = ascii(b, 8, 4);
    if (/^(heic|heix|hevc|hevx|mif1|msf1)/.test(brand)) return t('HEIC / HEIF', ['heic', 'heif'], 'image/heic', 'image');
    if (brand === 'avif' || brand === 'avis') return t('AVIF', ['avif'], 'image/avif', 'image');
    if (brand === 'qt  ') return t('QuickTime MOV', ['mov', 'qt'], 'video/quicktime', 'video');
    if (/^M4A|^M4B/.test(brand)) return t('M4A (audio MPEG-4)', ['m4a', 'm4b', 'mp4'], 'audio/mp4', 'audio');
    if (/^3g/.test(brand)) return t('3GP', ['3gp', '3g2', 'mp4'], 'video/3gpp', 'video');
    return t('MP4 (ISO BMFF)', ['mp4', 'm4v', 'mov', 'm4a', 'f4v'], 'video/mp4', 'video');
  }
  for (const s of SIGS) {
    if (matchAt(b, s.offset ?? 0, s.magic)) return s.info;
  }
  // MP3 sin ID3 (frame sync)
  if (b[0] === 0xff && (b[1] & 0xe0) === 0xe0 && b.length > 4 && ((b[1] >> 1) & 3) !== 0)
    return t('MP3 (frame MPEG)', ['mp3', 'mp2'], 'audio/mpeg', 'audio');
  return textKind(b);
}

export interface MismatchResult {
  mismatch: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  note: string;
}

export function checkExtension(declared: string, type: TypeInfo | null, names?: string[]): MismatchResult {
  const none: MismatchResult = { mismatch: false, severity: 'low', note: '' };
  if (!type) return none;
  const exts = names ?? type.ext;
  const d = declared.toLowerCase();
  if (!d) return none;
  if (exts.includes(d) || (ALIASES[d] ?? []).some((a) => exts.includes(a))) return none;
  if (type.category === 'text') {
    if (!BINARY_EXTS.has(d)) return none; // .txt .log .py .md etc.
    if (isExecutableExt(d) && d !== 'jar' && d !== 'lnk') return none; // scripts son texto legítimo
  }
  if (type.category === 'data' && !BINARY_EXTS.has(d)) return none;
  if (type.category === 'executable' && !isExecutableExt(d)) {
    return {
      mismatch: true,
      severity: 'critical',
      note: `El contenido es un ${type.name} pero la extensión declarada es ".${d}". Es una técnica clásica de camuflaje de malware.`,
    };
  }
  if (isExecutableExt(d) && type.category !== 'executable') {
    return {
      mismatch: true,
      severity: 'medium',
      note: `La extensión ".${d}" sugiere un ejecutable/script, pero el contenido real es ${type.name}.`,
    };
  }
  return {
    mismatch: true,
    severity: 'medium',
    note: `La extensión ".${d}" no corresponde con el contenido real (${type.name}). El archivo pudo ser renombrado, manipulado o convertido sin cuidado.`,
  };
}
