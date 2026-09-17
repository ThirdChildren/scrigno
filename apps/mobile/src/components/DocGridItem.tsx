import { DocThumbnail } from "./DocThumbnail";
import { it } from "../i18n/it";
import type { DocSummary } from "../lib/ipc";

export function DocGridItem({ doc, onOpen }: { doc: DocSummary; onOpen: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onOpen(doc.id)}
      className="flex flex-col gap-1 rounded-md p-1 text-left"
    >
      <div className="relative">
        <DocThumbnail id={doc.id} title={doc.title} />
        {doc.dirty && (
          <span className="absolute right-1 top-1 rounded bg-amber-600 px-1.5 py-0.5 text-[10px] text-white">
            {it.vault.dirtyBadge}
          </span>
        )}
      </div>
      <span className="truncate text-sm text-neutral-100">{doc.title}</span>
    </button>
  );
}
