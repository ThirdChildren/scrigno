import { useEffect, useRef, useState } from "react";
import * as pdfjsLib from "pdfjs-dist";
// Bundled locally (no CDN, CSP-safe): Vite's `?url` import copies the worker file into the build
// and gives us a same-origin URL for it (`docs/ROADMAP.md` M4: "PDF via pdf.js bundled locally").
import pdfWorkerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { it } from "../i18n/it";

pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorkerUrl;

/**
 * Minimal, paginated PDF viewer over a local object URL. Loads the document once per `url`
 * change, then renders only the current page to a canvas — a scrollable multi-page view is
 * explicitly out of scope for this milestone (`docs/ROADMAP.md` M4: "keep the viewer simple").
 */
export function PdfViewer({ url }: { url: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const docRef = useRef<pdfjsLib.PDFDocumentProxy | null>(null);
  const loadingTaskRef = useRef<pdfjsLib.PDFDocumentLoadingTask | null>(null);
  const [currentUrl, setCurrentUrl] = useState(url);
  const [page, setPage] = useState(1);
  const [numPages, setNumPages] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // "Adjusting state when a prop changes" (react.dev), done during render rather than in an
  // effect: resets the viewer's page/error state as soon as `url` changes.
  if (url !== currentUrl) {
    setCurrentUrl(url);
    setError(null);
    setNumPages(0);
    setPage(1);
  }

  useEffect(() => {
    let cancelled = false;

    const loadingTask = pdfjsLib.getDocument({ url });
    loadingTaskRef.current = loadingTask;
    loadingTask.promise
      .then((doc) => {
        if (cancelled) return;
        docRef.current = doc;
        setNumPages(doc.numPages);
      })
      .catch(() => {
        if (!cancelled) setError(it.document.unsupportedPreview);
      });

    return () => {
      cancelled = true;
      docRef.current = null;
      void loadingTaskRef.current?.destroy();
      loadingTaskRef.current = null;
    };
  }, [url]);

  useEffect(() => {
    const doc = docRef.current;
    const canvas = canvasRef.current;
    if (!doc || !canvas || numPages === 0) return;
    let cancelled = false;

    void doc.getPage(page).then(async (pageProxy) => {
      if (cancelled) return;
      const viewport = pageProxy.getViewport({ scale: 1.2 });
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      const context = canvas.getContext("2d");
      if (!context) return;
      await pageProxy.render({ canvasContext: context, viewport, canvas }).promise;
    });

    return () => {
      cancelled = true;
    };
  }, [page, numPages]);

  if (error) return <p className="text-neutral-400">{error}</p>;

  return (
    <div className="flex flex-col items-center gap-3">
      <canvas ref={canvasRef} className="max-w-full rounded-md bg-white" />
      {numPages > 1 && (
        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            aria-label={it.document.pdfPrev}
            className="min-h-11 min-w-11 rounded-md border border-neutral-700 disabled:opacity-40"
          >
            ‹
          </button>
          <span className="text-sm text-neutral-300">{it.document.pdfPage(page, numPages)}</span>
          <button
            type="button"
            disabled={page >= numPages}
            onClick={() => setPage((p) => p + 1)}
            aria-label={it.document.pdfNext}
            className="min-h-11 min-w-11 rounded-md border border-neutral-700 disabled:opacity-40"
          >
            ›
          </button>
        </div>
      )}
    </div>
  );
}
