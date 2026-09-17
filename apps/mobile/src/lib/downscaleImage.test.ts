import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { downscaleImage, MAX_LONG_SIDE } from "./downscaleImage";

function mockBitmap(width: number, height: number) {
  return { width, height, close: vi.fn() };
}

describe("downscaleImage", () => {
  let originalCreateImageBitmap: typeof globalThis.createImageBitmap | undefined;
  let originalCreateElement: typeof document.createElement;

  beforeEach(() => {
    originalCreateImageBitmap = globalThis.createImageBitmap;
    originalCreateElement = document.createElement.bind(document);
  });

  afterEach(() => {
    if (originalCreateImageBitmap) {
      globalThis.createImageBitmap = originalCreateImageBitmap;
    } else {
      // @ts-expect-error jsdom does not define this by default
      delete globalThis.createImageBitmap;
    }
    document.createElement = originalCreateElement;
    vi.restoreAllMocks();
  });

  it("returns the original bytes unchanged when already within the long-side cap", async () => {
    const bitmap = mockBitmap(1000, 2000);
    globalThis.createImageBitmap = vi.fn().mockResolvedValue(bitmap);
    const originalBytes = new Uint8Array([1, 2, 3]).buffer;
    const file = {
      type: "image/png",
      arrayBuffer: vi.fn().mockResolvedValue(originalBytes),
    } as unknown as File;

    const result = await downscaleImage(file);

    expect(result.mime).toBe("image/png");
    expect(result.bytes).toBe(originalBytes);
    expect(bitmap.close).toHaveBeenCalled();
  });

  it("scales the long side down to the cap, preserving aspect ratio, and re-encodes as JPEG", async () => {
    // 6000x4000 -> long side 6000 must become MAX_LONG_SIDE, short side scaled proportionally.
    const bitmap = mockBitmap(6000, 4000);
    globalThis.createImageBitmap = vi.fn().mockResolvedValue(bitmap);
    const file = {
      type: "image/jpeg",
      arrayBuffer: vi.fn(),
    } as unknown as File;

    let capturedWidth = 0;
    let capturedHeight = 0;
    const drawImage = vi.fn();
    const resizedBlobBytes = new Uint8Array([9, 9]).buffer;
    const canvas = {
      set width(w: number) {
        capturedWidth = w;
      },
      get width() {
        return capturedWidth;
      },
      set height(h: number) {
        capturedHeight = h;
      },
      get height() {
        return capturedHeight;
      },
      getContext: vi.fn(() => ({ drawImage })),
      toBlob: (cb: (b: Blob | null) => void, mime: string) => {
        cb({ type: mime, arrayBuffer: () => Promise.resolve(resizedBlobBytes) } as unknown as Blob);
      },
    };
    document.createElement = vi.fn().mockReturnValue(canvas) as unknown as typeof document.createElement;

    const result = await downscaleImage(file);

    expect(capturedWidth).toBe(MAX_LONG_SIDE);
    expect(capturedHeight).toBe(2000); // 4000 * (3000/6000)
    expect(drawImage).toHaveBeenCalledWith(bitmap, 0, 0, MAX_LONG_SIDE, 2000);
    expect(result.mime).toBe("image/jpeg");
    expect(result.bytes).toBe(resizedBlobBytes);
    expect(bitmap.close).toHaveBeenCalled();
  });
});
