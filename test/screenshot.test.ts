import { describe, expect, it } from 'vitest';
import {
  encodeScreenshot,
  screenshotByteBudget,
  screenshotDocumentSize,
  screenshotRenderScale,
} from '../src/probe/screenshot';

describe('screenshot quality limits', () => {
  it('uses up to 2x density for ordinary HiDPI documents', () => {
    expect(screenshotRenderScale(1_280, 720, 1)).toBe(1);
    expect(screenshotRenderScale(1_280, 720, 2)).toBe(2);
    expect(screenshotRenderScale(390, 844, 3)).toBe(2);
  });

  it('bounds unusually large full-page canvases without flattening them to viewport height', () => {
    const scale = screenshotRenderScale(1_440, 8_000, 2);
    expect(scale).toBeGreaterThan(0.9);
    expect(1_440 * scale).toBeLessThanOrEqual(4_096);
    expect(8_000 * scale).toBeLessThanOrEqual(16_384);
    expect(1_440 * 8_000 * scale * scale).toBeLessThanOrEqual(10_000_000);
  });

  it('uses the maximum body and root dimensions for the full page', () => {
    const fakeDocument = {
      documentElement: { clientWidth: 1_280, scrollWidth: 1_300, offsetWidth: 1_290, clientHeight: 720, scrollHeight: 4_000, offsetHeight: 3_990 },
      body: { clientWidth: 1_270, scrollWidth: 1_400, offsetWidth: 1_380, clientHeight: 700, scrollHeight: 4_200, offsetHeight: 4_100 },
    } as unknown as Document;
    expect(screenshotDocumentSize(fakeDocument)).toEqual({ width: 1_400, height: 4_200 });
  });

  it('budgets the JPEG against both image and whole-request limits', () => {
    expect(screenshotByteBudget(100_000)).toBe(19_806_560);
    expect(screenshotByteBudget(1_100_000)).toBe(18_806_560);
    expect(screenshotByteBudget(1_950_000)).toBe(17_956_560);
    expect(screenshotByteBudget(100_000, 200_000)).toBe(73_616);
    expect(screenshotByteBudget(Number.NaN)).toBe(0);
  });

  it('treats browser encoding failures as a missing screenshot', async () => {
    const brokenCanvas = {
      width: 1_280,
      height: 720,
      toBlob: () => { throw new DOMException('Encoding failed'); },
    } as unknown as HTMLCanvasElement;

    await expect(encodeScreenshot(brokenCanvas, 1_300_000)).resolves.toBeNull();
  });
});
