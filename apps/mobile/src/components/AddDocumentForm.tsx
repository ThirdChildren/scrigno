import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import { docAddBytes, docAddFromPath, type DocSummary } from "../lib/ipc";

function parseTags(raw: string): string[] {
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

/**
 * Where the document's bytes come from: a filesystem path from the desktop dialog plugin
 * (`doc_add_from_path`), or already-in-memory bytes from the Android camera-capture flow
 * (`doc_add_bytes`, `docs/ARCHITECTURE.md §6`) — already downscaled by the caller
 * (`lib/downscaleImage.ts`) before this component ever sees them.
 */
export type AddDocumentSource =
  | { kind: "path"; path: string }
  | { kind: "bytes"; bytes: ArrayBuffer; mime: string; originalName: string };

/** Modal metadata form shown after a file is picked (dialog) or captured (camera). */
export function AddDocumentForm({
  source,
  onClose,
  onAdded,
}: {
  source: AddDocumentSource;
  onClose: () => void;
  onAdded: (doc: DocSummary) => void;
}) {
  const [title, setTitle] = useState("");
  const [tags, setTags] = useState("");
  const [note, setNote] = useState("");

  const mutation = useMutation({
    mutationFn: () =>
      source.kind === "path"
        ? docAddFromPath({ path: source.path, title, tags: parseTags(tags), note })
        : docAddBytes({
            bytes: source.bytes,
            mime: source.mime,
            originalName: source.originalName,
            title,
            tags: parseTags(tags),
            note,
          }),
    onSuccess: onAdded,
  });

  return (
    <div
      role="dialog"
      aria-labelledby="add-document-heading"
      className="fixed inset-0 z-10 flex flex-col justify-end bg-black/60 p-4"
    >
      <form
        className="flex flex-col gap-4 rounded-t-xl bg-neutral-900 p-6 pb-[env(safe-area-inset-bottom)]"
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
      >
        <h2 id="add-document-heading" className="text-lg font-semibold text-neutral-100">
          {it.vault.addTitle}
        </h2>

        <label className="flex flex-col gap-1 text-sm text-neutral-300">
          {it.common.title}
          <input
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="min-h-11 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-neutral-100"
          />
        </label>

        <label className="flex flex-col gap-1 text-sm text-neutral-300">
          {it.common.tags} <span className="text-xs text-neutral-500">({it.common.tagsHint})</span>
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            className="min-h-11 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-neutral-100"
          />
        </label>

        <label className="flex flex-col gap-1 text-sm text-neutral-300">
          {it.common.note}
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="min-h-20 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-neutral-100"
          />
        </label>

        {mutation.isError && (
          <p role="alert" className="text-sm text-red-400">
            {errorMessage(mutation.error)}
          </p>
        )}

        <div className="flex gap-3">
          <button
            type="button"
            onClick={onClose}
            className="min-h-11 flex-1 rounded-md border border-neutral-700 px-4 py-3 text-neutral-100"
          >
            {it.common.cancel}
          </button>
          <button
            type="submit"
            disabled={title.trim() === "" || mutation.isPending}
            className="min-h-11 flex-1 rounded-md bg-emerald-600 px-4 py-3 font-medium text-white disabled:opacity-40"
          >
            {it.common.save}
          </button>
        </div>
      </form>
    </div>
  );
}
