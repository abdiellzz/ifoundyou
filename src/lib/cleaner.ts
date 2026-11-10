import * as exifr from 'exifr';
import { walkJpeg, walkPng } from './structure';

const concat = (parts: Uint8Array[]) => {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

/** Reescribe un JPEG sin EXIF, XMP, IPTC, comentarios ni datos añadidos tras el EOI. Conserva ICC y la orientación. */
export async function cleanJpeg(b: Uint8Array): Promise<Uint8Array | null> {
  const { segments, end } = walkJpeg(b);
  const sos = segments.find((s) => s.marker === 0xda);
  if (!sos) return null;
  const parts: Uint8Array[] = [Uint8Array.of(0xff, 0xd8)];
  let orientation: number | undefined;
  try {
    orientation = await exifr.orientation(b);
  } catch {
    orientation = undefined;
  }
  if (orientation && orientation > 1 && orientation <= 8) {
    parts.push(
      Uint8Array.of(
        0xff, 0xe1, 0x00, 0x22, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00,
        0x4d, 0x4d, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x01, 0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, orientation, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
      ),
    );
  }
  for (const s of segments) {
    if (s.offset >= sos.offset) break;
    const m = s.marker;
    const isApp = m >= 0xe0 && m <= 0xef;
    const keep =
      (!isApp && m !== 0xfe) ||
      m === 0xe0 ||
      m === 0xee ||
      (m === 0xe2 && s.ident.startsWith('ICC_PROFILE'));
    if (keep) parts.push(b.subarray(s.offset, s.offset + s.length));
  }
  parts.push(b.subarray(sos.offset, end ?? b.length));
  return concat(parts);
}

const PNG_KEEP = new Set([
  'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'iCCP', 'sBIT', 'bKGD', 'pHYs',
  'acTL', 'fcTL', 'fdAT', 'hIST', 'cICP', 'mDCv', 'cLLi',
]);

/** Reescribe un PNG dejando solo los chunks necesarios para renderizar la imagen. */
export function cleanPng(b: Uint8Array): Uint8Array | null {
  const { chunks } = walkPng(b);
  if (!chunks.length) return null;
  const parts: Uint8Array[] = [b.subarray(0, 8)];
  for (const c of chunks) {
    if (PNG_KEEP.has(c.type)) parts.push(b.subarray(c.offset, c.offset + 12 + c.length));
    if (c.type === 'IEND') break;
  }
  return concat(parts);
}
