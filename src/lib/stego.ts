import type { StegoResult } from './types';

function erf(x: number): number {
  const s = x < 0 ? -1 : 1;
  const a = Math.abs(x);
  const t = 1 / (1 + 0.3275911 * a);
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-a * a);
  return s * y;
}
const phi = (z: number) => 0.5 * (1 + erf(z / Math.SQRT2));

/** Probabilidad de incrustación LSB (Westfeld–Pfitzmann, aproximación Wilson–Hilferty). */
function pairsTest(hist: Uint32Array): number | null {
  let chi = 0;
  let k = 0;
  for (let i = 0; i < 128; i++) {
    const a = hist[2 * i];
    const b = hist[2 * i + 1];
    const exp = (a + b) / 2;
    if (exp > 4) {
      chi += ((a - exp) * (a - exp)) / exp;
      k++;
    }
  }
  if (k < 8) return null;
  const df = k - 1;
  const z = (Math.cbrt(chi / df) - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
  return phi(-z);
}

export async function analyzeStego(file: File): Promise<StegoResult | null> {
  let bmp: ImageBitmap;
  try {
    bmp = await createImageBitmap(file, { premultiplyAlpha: 'none', colorSpaceConversion: 'none' });
  } catch {
    return null;
  }
  const { width, height } = bmp;
  const pixels = width * height;
  if (pixels < 2500 || pixels > 12_000_000) {
    bmp.close();
    return null;
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) {
    bmp.close();
    return null;
  }
  ctx.drawImage(bmp, 0, 0);
  bmp.close();
  const data = ctx.getImageData(0, 0, width, height).data;

  const hist = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
  const ones = [0, 0, 0];
  let counted = 0;
  const checkpoints = [0.1, 0.25, 0.5, 1].map((f) => Math.floor(pixels * f));
  let cp = 0;
  let best = 0;
  for (let p = 0; p < pixels; p++) {
    const o = p * 4;
    if (data[o + 3] === 255) {
      counted++;
      for (let c = 0; c < 3; c++) {
        const v = data[o + c];
        hist[c][v]++;
        ones[c] += v & 1;
      }
    }
    if (p + 1 === checkpoints[cp]) {
      if (counted > 2000) {
        for (let c = 0; c < 3; c++) {
          const r = pairsTest(hist[c]);
          if (r !== null && r > best) best = r;
        }
      }
      cp++;
    }
  }
  if (counted === 0) return null;
  return {
    width,
    height,
    pixels,
    lsbRatio: [ones[0] / counted, ones[1] / counted, ones[2] / counted],
    pEmbed: best,
    applicable: counted > 2000,
  };
}
