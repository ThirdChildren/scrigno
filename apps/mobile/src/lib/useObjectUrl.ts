import { useEffect, useState } from "react";

/**
 * Runs `fetchBlob` whenever `key` changes, exposing the result as an object URL. Revokes the
 * previous URL whenever the fetch re-runs (`key` changes) or the component unmounts.
 *
 * `key` (rather than a raw dependency list) identifies *what* is being fetched (e.g. a document
 * id, or `id:mime`) — pass `null` to skip fetching (e.g. while the id or mime type is not known
 * yet). Resetting `url`/`loading`/`error` happens during render when `key` changes (react.dev:
 * "adjusting state when a prop changes"), not inside the effect body, so the actual fetch/URL
 * creation stays the effect's only side effect.
 *
 * CLAUDE.md: decrypted bytes "live only in memory / object URLs that are revoked on close" — this
 * hook is the one place that rule is implemented, so every binary IPC response (`doc_open`,
 * `doc_thumb`) goes through it rather than each screen managing its own `URL.revokeObjectURL`.
 */
export function useObjectUrl(
  key: string | null,
  fetchBlob: () => Promise<Blob | null>,
): { url: string | null; loading: boolean; error: unknown } {
  const [currentKey, setCurrentKey] = useState(key);
  const [url, setUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(key !== null);
  const [error, setError] = useState<unknown>(null);

  if (key !== currentKey) {
    setCurrentKey(key);
    setUrl(null);
    setError(null);
    setLoading(key !== null);
  }

  useEffect(() => {
    if (key === null) return;
    let cancelled = false;
    let objectUrl: string | null = null;

    fetchBlob()
      .then((blob) => {
        if (cancelled) return;
        if (blob) {
          objectUrl = URL.createObjectURL(blob);
          setUrl(objectUrl);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
    // `fetchBlob` is intentionally excluded: callers pass a fresh closure every render, and `key`
    // is the actual identity that should trigger a re-fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return { url, loading, error };
}
