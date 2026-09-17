import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import {
  docDelete,
  docGetMeta,
  docOpen,
  docSetKeepOffline,
  docUpdateMeta,
  docsList,
} from "../lib/ipc";
import { useObjectUrl } from "../lib/useObjectUrl";
import { PdfViewer } from "../components/PdfViewer";

function parseTags(raw: string): string[] {
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

/** Document screen: viewer, metadata edit, delete, keep-offline toggle (`docs/ROADMAP.md` M4). */
export function Document({ id, onBack }: { id: string; onBack: () => void }) {
  const queryClient = useQueryClient();
  const headingRef = useRef<HTMLHeadingElement>(null);

  const metaQuery = useQuery({ queryKey: ["docMeta", id], queryFn: () => docGetMeta(id) });
  const docsListQuery = useQuery({ queryKey: ["docsList"], queryFn: docsList });
  const summary = docsListQuery.data?.find((d) => d.id === id);

  const [title, setTitle] = useState("");
  const [tags, setTags] = useState("");
  const [note, setNote] = useState("");
  // "Adjusting state when a prop changes" (react.dev), done during render rather than in an
  // effect: seeds the editable fields once per fetch of `metaQuery.data`.
  const [loadedMeta, setLoadedMeta] = useState(metaQuery.data);
  if (metaQuery.data && metaQuery.data !== loadedMeta) {
    setLoadedMeta(metaQuery.data);
    setTitle(metaQuery.data.title);
    setTags(metaQuery.data.tags.join(", "));
    setNote(metaQuery.data.note);
  }

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const mime = metaQuery.data?.mime;
  const { url: fileUrl } = useObjectUrl(mime ? `${id}:${mime}` : null, () =>
    mime ? docOpen(id, mime) : Promise.resolve(null),
  );

  const updateMutation = useMutation({
    mutationFn: () => docUpdateMeta({ id, title, tags: parseTags(tags), note }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["docMeta", id] });
      void queryClient.invalidateQueries({ queryKey: ["docsList"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => docDelete(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["docsList"] });
      onBack();
    },
  });

  const keepOfflineMutation = useMutation({
    mutationFn: (keepOffline: boolean) => docSetKeepOffline({ id, keepOffline }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["docsList"] }),
  });

  const handleDelete = () => {
    if (window.confirm(it.document.deleteConfirm)) deleteMutation.mutate();
  };

  return (
    <main className="flex min-h-screen flex-col gap-4 bg-neutral-950 p-4 pb-[env(safe-area-inset-bottom)] text-neutral-100">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onBack}
          className="min-h-11 min-w-11 rounded-md border border-neutral-700 px-3"
        >
          {it.common.back}
        </button>
        <h1 ref={headingRef} tabIndex={-1} className="text-lg font-semibold">
          {it.document.editTitle}
        </h1>
      </div>

      <div className="flex items-center justify-center rounded-md bg-neutral-900 p-2">
        {!fileUrl && <p className="p-6 text-neutral-500">{it.common.loading}</p>}
        {fileUrl && metaQuery.data?.mime.startsWith("image/") && (
          <img src={fileUrl} alt={title} className="max-h-[50vh] max-w-full object-contain" />
        )}
        {fileUrl && metaQuery.data?.mime === "application/pdf" && <PdfViewer url={fileUrl} />}
        {fileUrl &&
          metaQuery.data &&
          !metaQuery.data.mime.startsWith("image/") &&
          metaQuery.data.mime !== "application/pdf" && (
            <p className="p-6 text-neutral-500">{it.document.unsupportedPreview}</p>
          )}
      </div>

      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          updateMutation.mutate();
        }}
      >
        <label className="flex flex-col gap-1 text-sm text-neutral-300">
          {it.common.title}
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-100"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-neutral-300">
          {it.common.tags} <span className="text-xs text-neutral-500">({it.common.tagsHint})</span>
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-100"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-neutral-300">
          {it.common.note}
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="min-h-20 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-100"
          />
        </label>

        {updateMutation.isError && (
          <p role="alert" className="text-sm text-red-400">
            {errorMessage(updateMutation.error)}
          </p>
        )}

        <button
          type="submit"
          disabled={title.trim() === "" || updateMutation.isPending}
          className="min-h-11 rounded-md bg-emerald-600 px-4 py-3 font-medium text-white disabled:opacity-40"
        >
          {it.common.save}
        </button>
      </form>

      <label className="flex min-h-11 items-center gap-3 text-sm text-neutral-300">
        <input
          type="checkbox"
          checked={summary?.keep_offline ?? false}
          onChange={(e) => keepOfflineMutation.mutate(e.target.checked)}
          className="h-5 w-5"
        />
        {it.document.keepOffline}
      </label>

      <button
        type="button"
        disabled
        title={it.common.comingSoon}
        className="min-h-11 rounded-md border border-neutral-800 px-4 py-3 text-neutral-600"
      >
        {it.document.share}
      </button>

      {deleteMutation.isError && (
        <p role="alert" className="text-sm text-red-400">
          {errorMessage(deleteMutation.error)}
        </p>
      )}
      <button
        type="button"
        onClick={handleDelete}
        disabled={deleteMutation.isPending}
        className="min-h-11 rounded-md border border-red-800 px-4 py-3 font-medium text-red-400 disabled:opacity-40"
      >
        {it.common.delete}
      </button>
    </main>
  );
}
