import { useMemo, useRef, useState, type ChangeEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import { docsList, syncNow, vaultLock, type DocSummary } from "../lib/ipc";
import { downscaleImage } from "../lib/downscaleImage";
import { DocGridItem } from "../components/DocGridItem";
import { AddDocumentForm, type AddDocumentSource } from "../components/AddDocumentForm";
import { SyncBanner } from "../components/SyncBanner";

const FILE_FILTERS = [{ name: "Documenti", extensions: ["pdf", "jpg", "jpeg", "png"] }];
// Stable reference so `docsQuery.data ?? EMPTY_DOCS` doesn't defeat the `useMemo`s below with a
// fresh `[]` on every render while the query is still loading.
const EMPTY_DOCS: DocSummary[] = [];

function matchesQuery(doc: DocSummary, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === "") return true;
  return doc.title.toLowerCase().includes(q) || doc.tags.some((t) => t.toLowerCase().includes(q));
}

/** Vault screen: searchable/tag-filterable document grid (`docs/ROADMAP.md` M4). */
export function Vault({
  onOpenDocument,
  onOpenSettings,
}: {
  onOpenDocument: (id: string) => void;
  onOpenSettings: () => void;
}) {
  const queryClient = useQueryClient();
  const docsQuery = useQuery({ queryKey: ["docsList"], queryFn: docsList });
  const [search, setSearch] = useState("");
  const [selectedTags, setSelectedTags] = useState<Set<string>>(new Set());
  const [pendingSource, setPendingSource] = useState<AddDocumentSource | null>(null);
  const [captureError, setCaptureError] = useState<unknown>(null);
  const cameraInputRef = useRef<HTMLInputElement>(null);

  const docs = docsQuery.data ?? EMPTY_DOCS;
  const allTags = useMemo(() => Array.from(new Set(docs.flatMap((d) => d.tags))).sort(), [docs]);
  const filtered = useMemo(
    () =>
      docs.filter(
        (d) =>
          matchesQuery(d, search) &&
          (selectedTags.size === 0 || d.tags.some((t) => selectedTags.has(t))),
      ),
    [docs, search, selectedTags],
  );

  const syncMutation = useMutation({
    mutationFn: syncNow,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["docsList"] }),
  });
  const lockMutation = useMutation({
    mutationFn: vaultLock,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] }),
  });

  const toggleTag = (tag: string) => {
    setSelectedTags((prev) => {
      const next = new Set(prev);
      if (next.has(tag)) next.delete(tag);
      else next.add(tag);
      return next;
    });
  };

  const handleAdd = async () => {
    const path = await openFileDialog({ multiple: false, directory: false, filters: FILE_FILTERS });
    if (typeof path === "string") setPendingSource({ kind: "path", path });
  };

  // Android camera capture (`docs/ROADMAP.md` M5): `<input type="file" capture>` — ignored by
  // desktop browsers, which just fall back to a normal file picker, so this button works (if
  // redundantly with "Aggiungi documento") on every platform. Downscaling happens here, in the
  // browser/webview, *before* any bytes cross IPC — `doc_add_bytes` (and everything downstream of
  // it, including encryption) only ever sees the already-downscaled result.
  const handleCameraChange = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setCaptureError(null);
    try {
      const { bytes, mime } = await downscaleImage(file);
      setPendingSource({ kind: "bytes", bytes, mime, originalName: file.name });
    } catch (err) {
      setCaptureError(err);
    }
  };

  return (
    <main className="flex min-h-screen flex-col gap-4 bg-neutral-950 p-4 pb-[env(safe-area-inset-bottom)] text-neutral-100">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">{it.vault.heading}</h1>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onOpenSettings}
            aria-label={it.vault.settings}
            className="min-h-11 min-w-11 rounded-md border border-neutral-700 px-3"
          >
            ⚙
          </button>
          <button
            type="button"
            onClick={() => lockMutation.mutate()}
            className="min-h-11 rounded-md border border-neutral-700 px-3 text-sm"
          >
            {it.vault.lock}
          </button>
        </div>
      </header>

      <label htmlFor="vault-search" className="sr-only">
        {it.vault.searchPlaceholder}
      </label>
      <input
        id="vault-search"
        type="search"
        placeholder={it.vault.searchPlaceholder}
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-100"
      />

      {allTags.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {allTags.map((tag) => (
            <button
              key={tag}
              type="button"
              aria-pressed={selectedTags.has(tag)}
              onClick={() => toggleTag(tag)}
              className={`min-h-8 rounded-full px-3 py-1 text-xs ${
                selectedTags.has(tag)
                  ? "bg-emerald-600 text-white"
                  : "bg-neutral-800 text-neutral-300"
              }`}
            >
              {tag}
            </button>
          ))}
        </div>
      )}

      <SyncBanner report={syncMutation.data ?? null} syncing={syncMutation.isPending} />
      {syncMutation.isError && (
        <p role="alert" className="text-sm text-red-400">
          {errorMessage(syncMutation.error)}
        </p>
      )}

      <button
        type="button"
        onClick={() => syncMutation.mutate()}
        disabled={syncMutation.isPending}
        className="min-h-11 rounded-md border border-neutral-700 px-3 text-sm disabled:opacity-40"
      >
        {it.vault.sync}
      </button>

      {docs.length === 0 && !docsQuery.isLoading && (
        <p className="text-center text-neutral-500">{it.vault.empty}</p>
      )}
      {docs.length > 0 && filtered.length === 0 && (
        <p className="text-center text-neutral-500">{it.vault.noResults}</p>
      )}

      <div className="grid flex-1 grid-cols-3 gap-3 overflow-y-auto sm:grid-cols-4">
        {filtered.map((doc) => (
          <DocGridItem key={doc.id} doc={doc} onOpen={onOpenDocument} />
        ))}
      </div>

      {captureError !== null && (
        <p role="alert" className="text-sm text-red-400">
          {errorMessage(captureError)}
        </p>
      )}

      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => void handleAdd()}
          className="min-h-11 flex-1 rounded-md bg-emerald-600 px-4 py-3 font-medium text-white"
        >
          {it.vault.addFromFile}
        </button>
        <button
          type="button"
          onClick={() => cameraInputRef.current?.click()}
          className="min-h-11 flex-1 rounded-md border border-emerald-700 px-4 py-3 font-medium text-emerald-400"
        >
          {it.vault.addFromCamera}
        </button>
      </div>
      <label htmlFor="vault-camera-input" className="sr-only">
        {it.vault.addFromCamera}
      </label>
      <input
        id="vault-camera-input"
        ref={cameraInputRef}
        type="file"
        accept="image/*"
        capture="environment"
        onChange={(e) => void handleCameraChange(e)}
        className="hidden"
      />

      {pendingSource && (
        <AddDocumentForm
          source={pendingSource}
          onClose={() => setPendingSource(null)}
          onAdded={() => {
            setPendingSource(null);
            void queryClient.invalidateQueries({ queryKey: ["docsList"] });
          }}
        />
      )}
    </main>
  );
}
