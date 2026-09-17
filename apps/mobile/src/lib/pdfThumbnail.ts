// Client-side, lazy thumbnail rendering for PDF documents (`docs/ROADMAP.md` M4: a
// server/Rust-generated, persisted PDF thumbnail is still out of scope — this renders page 1
// on-device instead of showing a generic file icon for every PDF in the grid).
//
// Heavier than the cached-JPEG path used for images: it decrypt-fetches the *whole* document via
// `doc_open` (the same IPC call `useObjectUrl` uses for the full viewer) just to rasterize page 1.
// Callers must cache the result per document (see `DocThumbnail`'s `useQuery`) so this only runs
// once per document per session, not on every grid re-render.
import * as pdfjsLib from "pdfjs-dist";
// Bundled locally (no CDN, CSP-safe), same as `PdfViewer.tsx`.
import pdfWorkerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { docOpen } from "./ipc";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorkerUrl;

/** Target width in CSS pixels for the rendered thumbnail — small, since the grid only ever
 * displays it at `aspect-square` tile size. */
const THUMB_TARGET_WIDTH = 256;

/**
 * Renders page 1 of PDF document `id` to a JPEG data URL, or `null` if it can't be rendered
 * (corrupt/unsupported PDF, decryption failure, …) — callers fall back to the placeholder icon
 * on `null` rather than a broken image.
 */
export async function renderPdfThumbnail(id: string, mime: string): Promise<string | null> {
  try {
    const blob = await docOpen(id, mime);
    const data = await blob.arrayBuffer();
    // `destroy()` lives on the loading task, not the resolved `PDFDocumentProxy` (mirrors
    // `PdfViewer.tsx`'s cleanup).
    const loadingTask = pdfjsLib.getDocument({ data });
    try {
      const doc = await loadingTask.promise;
      const page = await doc.getPage(1);
      const unscaled = page.getViewport({ scale: 1 });
      const scale = unscaled.width > 0 ? THUMB_TARGET_WIDTH / unscaled.width : 1;
      const viewport = page.getViewport({ scale });
      const canvas = document.createElement("canvas");
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      const context = canvas.getContext("2d");
      if (!context) return null;
      await page.render({ canvasContext: context, viewport, canvas }).promise;
      return canvas.toDataURL("image/jpeg", 0.8);
    } finally {
      await loadingTask.destroy();
    }
  } catch {
    return null;
  }
}
