export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Axis = 'forense' | 'privacidad';
export type Category =
  | 'image'
  | 'document'
  | 'archive'
  | 'executable'
  | 'audio'
  | 'video'
  | 'text'
  | 'data'
  | 'unknown';

export interface Finding {
  id: string;
  axis: Axis;
  severity: Severity;
  title: string;
  detail: string;
  offset?: number;
  recommendation?: string;
}

export interface MetaEntry {
  key: string;
  value: string;
  sensitive?: boolean;
}

export interface MetaGroup {
  id: string;
  title: string;
  entries: MetaEntry[];
  note?: string;
}

export interface Extraction {
  groups: MetaGroup[];
  findings: Finding[];
  gps?: { lat: number; lon: number } | null;
  label?: string;
  exts?: string[];
  category?: Category;
  leaks?: InterestingString[];
}

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
}

export interface TypeInfo {
  name: string;
  ext: string[];
  mime: string;
  category: Category;
}

export interface EmbeddedHit {
  offset: number;
  name: string;
  severity: Severity;
  note: string;
}

export interface TrailingInfo {
  offset: number;
  size: number;
  entropy: number;
  startsWith: string;
  detected: string | null;
  note: string;
}

export interface InterestingString {
  type: string;
  value: string;
  offset: number;
}

export interface StringSample {
  offset: number;
  text: string;
  wide: boolean;
}

export interface StringsResult {
  total: number;
  samples: StringSample[];
  interesting: InterestingString[];
}

export interface StegoResult {
  width: number;
  height: number;
  pixels: number;
  lsbRatio: [number, number, number];
  pEmbed: number;
  applicable: boolean;
}

export interface TimelineEvent {
  time: number;
  label: string;
  source: string;
}

export type Verdict = 'limpio' | 'precaucion' | 'sospechoso' | 'peligroso';

export interface AnalysisResult {
  id: string;
  file: File;
  name: string;
  size: number;
  ext: string;
  browserMime: string;
  lastModified: number;
  hashes: Hashes;
  type: TypeInfo | null;
  typeLabel: string;
  extMismatch: boolean;
  entropy: { overall: number; blocks: number[]; blockSize: number };
  embedded: EmbeddedHit[];
  trailing: TrailingInfo | null;
  strings: StringsResult;
  metadata: MetaGroup[];
  gps: { lat: number; lon: number } | null;
  stego: StegoResult | null;
  findings: Finding[];
  scores: { forense: number; privacidad: number; total: number };
  verdict: Verdict;
  timeline: TimelineEvent[];
  analyzedAt: number;
  durationMs: number;
  cleanable: 'jpeg' | 'png' | null;
}
