import { docThumb } from "../lib/ipc";
import { useObjectUrl } from "../lib/useObjectUrl";
import { it } from "../i18n/it";

/** Thumbnail image for one document, or a placeholder icon if it has none. */
export function DocThumbnail({ id, title }: { id: string; title: string }) {
  const { url } = useObjectUrl(id, () => docThumb(id));

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
