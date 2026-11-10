import type { MetaEntry } from './types';
import { decodeUtf8, indexOfBytes, isSensitiveKey, stringify, strBytes } from './utils';

export function toEntries(
  obj: Record<string, unknown>,
  opts: { forceSensitive?: boolean; skip?: RegExp } = {},
): MetaEntry[] {
  const out: MetaEntry[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (opts.skip && opts.skip.test(k)) continue;
    const value = stringify(v);
    if (!value) continue;
    out.push({ key: k, value, sensitive: opts.forceSensitive || isSensitiveKey(k) });
  }
  return out;
}

function walk(el: Element, out: MetaEntry[], depth = 0) {
  if (depth > 40 || out.length > 400) return;
  const kids = Array.from(el.children);
  const name = el.localName;
  if (name === 'Description') {
    for (const a of Array.from(el.attributes)) {
      if (a.name.startsWith('xmlns') || a.localName === 'about') continue;
      const v = a.value.trim();
      if (v) out.push({ key: a.name, value: stringify(v, 300), sensitive: isSensitiveKey(a.localName) });
    }
  }
  if (kids.length === 0) {
    const t = (el.textContent ?? '').trim();
    if (t && name !== 'li') out.push({ key: el.tagName, value: stringify(t, 300), sensitive: isSensitiveKey(name) });
    return;
  }
  // Contenedores RDF (Bag / Seq / Alt)
  const list = kids.length === 1 && ['Bag', 'Seq', 'Alt'].includes(kids[0].localName) ? kids[0] : null;
  if (list) {
    const items = Array.from(list.children)
      .map((li) => (li.textContent ?? '').trim())
      .filter(Boolean);
    if (items.length && Array.from(list.children).every((li) => li.children.length === 0)) {
      out.push({ key: el.tagName, value: stringify(items.join(' · '), 300), sensitive: isSensitiveKey(name) });
      return;
    }
  }
  for (const k of kids) walk(k, out, depth + 1);
}

export function flattenXml(xml: string): MetaEntry[] {
  try {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) return [];
    const out: MetaEntry[] = [];
    if (doc.documentElement) walk(doc.documentElement, out);
    return out;
  } catch {
    return [];
  }
}

const XMP_START = strBytes('<x:xmpmeta');
const XMP_END = strBytes('</x:xmpmeta>');

export function findXmpBlocks(b: Uint8Array, max = 3): string[] {
  const res: string[] = [];
  let from = 0;
  while (res.length < max) {
    const s = indexOfBytes(b, XMP_START, from);
    if (s < 0) break;
    const e = indexOfBytes(b, XMP_END, s, Math.min(b.length, s + 3_000_000));
    if (e < 0) break;
    res.push(decodeUtf8(b, s, e + XMP_END.length));
    from = e + XMP_END.length;
  }
  return res;
}

export function parseXmp(xml: string): MetaEntry[] {
  const raw = flattenXml(xml);
  const skip = /^(x:xmpmeta|rdf:RDF|xmlns)/i;
  return raw.filter((e) => !skip.test(e.key));
}

export async function inflateZlib(data: Uint8Array): Promise<Uint8Array | null> {
  try {
    if (typeof DecompressionStream === 'undefined') return null;
    const ds = new DecompressionStream('deflate');
    const stream = new Blob([data as BlobPart]).stream().pipeThrough(ds);
    const buf = await new Response(stream).arrayBuffer();
    return new Uint8Array(buf);
  } catch {
    return null;
  }
}
