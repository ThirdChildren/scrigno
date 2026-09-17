import { useQuery } from "@tanstack/react-query";
import { docThumb } from "../lib/ipc";
import { useObjectUrl } from "../lib/useObjectUrl";
import { renderPdfThumbnail } from "../lib/pdfThumbnail";
import { it } from "../i18n/it";

const PDF_MIME = "application/pdf";

/**
 * Thumbnail image for one document, or a placeholder icon if it has none.
 *
 * Server-generated thumbnails (`doc_thumb`) only exist for `image/*` documents today
 * (`docs/ROADMAP.md` M4 leaves a persisted PDF thumbnail for M5). For a PDF document with no
 * server thumbnail, this renders page 1 client-side via `pdfjs-dist` instead of the generic file
 * icon — lazily (only once the server-thumb lookup has come back empty) and cached per
 * `id`+`contentHash` for the session via `useQuery`'s own in-memory cache, so it is computed at
 * most once per document per session rather than on every grid re-render. Never persisted to
 * disk-backed storage (CLAUDE.md: no plaintext document content in `localStorage`/IndexedDB).
 */
export function DocThumbnail({
  id,
  title,
  mime,
  contentHash,
}: {
  id: string;
  title: string;
  mime: string;
  contentHash: string;
}) {
  const { url: serverUrl, loading: serverLoading } = useObjectUrl(id, () => docThumb(id));

  const isPdf = mime === PDF_MIME;
  const pdfThumbQuery = useQuery({
    queryKey: ["pdfThumb", id, contentHash],
    queryFn: () => renderPdfThumbnail(id, mime),
    // Wait for the (cheap, local) server-thumb lookup to resolve first, so a PDF that does gain
    // a server thumbnail in the future never pays for the (expensive, decrypt-the-whole-file)
    // client-side render as well.
    enabled: isPdf && !serverLoading && !serverUrl,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });

  const url = serverUrl ?? (isPdf ? (pdfThumbQuery.data ?? null) : null);

  if (!url) {
    return (
      <div
        role="img"
        aria-label={it.vault.noThumb}
        className="flex aspect-square w-full items-center justify-center rounded-md bg-neutral-800 text-neutral-500"
      >
        <svg viewBox="0 0 24 24" className="h-8 w-8" fill="none" stroke="currentColor" aria-hidden="true">
          <path
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M7 3h7l5 5v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"
          />
          <path strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" d="M14 3v5h5" />
        </svg>
      </div>
    );
  }

  return (
    <img
      src={url}
      alt={`${it.vault.thumbAlt}: ${title}`}
      className="aspect-square w-full rounded-md object-cover"
    />
  );
}
