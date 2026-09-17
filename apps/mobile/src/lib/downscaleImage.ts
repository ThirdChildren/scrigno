// Client-side image resizing only — no crypto happens here (`CLAUDE.md`: "no crypto in JS").
// Used by the camera-capture flow (`docs/ROADMAP.md` M5): "a 12 MP scan of a card is waste" —
// this must run *before* the bytes ever reach `doc_add_bytes`/encryption, never after.

/** Long-side cap in pixels (`docs/ROADMAP.md` M5). */
export const MAX_LONG_SIDE = 3000;
const JPEG_QUALITY = 0.85;

/**
 * Downscales `file` so its longest side is at most `maxLongSide` (default [`MAX_LONG_SIDE`]),
 * re-encoding to JPEG only when a resize actually happens. A file already within bounds is
 * returned byte-for-byte unchanged (no quality loss, no re-encode) — its own MIME type is kept.
 */
export async function downscaleImage(
  file: File,
  maxLongSide: number = MAX_LONG_SIDE,
): Promise<{ bytes: ArrayBuffer; mime: string }> {
  const bitmap = await createImageBitmap(file);
  try {
    const longSide = Math.max(bitmap.width, bitmap.height);
    if (longSide <= maxLongSide) {
      return { bytes: await file.arrayBuffer(), mime: file.type || "image/jpeg" };
    }

    const scale = maxLongSide / longSide;
    const targetWidth = Math.max(1, Math.round(bitmap.width * scale));
    const targetHeight = Math.max(1, Math.round(bitmap.height * scale));

    const canvas = document.createElement("canvas");
    canvas.width = targetWidth;
    canvas.height = targetHeight;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("2d canvas context unavailable");
    ctx.drawImage(bitmap, 0, 0, targetWidth, targetHeight);

    const mime = "image/jpeg";
    const blob = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (b) => (b ? resolve(b) : reject(new Error("canvas.toBlob failed"))),
        mime,
        JPEG_QUALITY,
      );
    });
    return { bytes: await blob.arrayBuffer(), mime };
  } finally {
    bitmap.close();
  }
}
