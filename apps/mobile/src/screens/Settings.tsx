import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import { settingsGet, settingsSet, vaultAddRecoveryCode, vaultLock } from "../lib/ipc";
import { RecoveryCodeReveal } from "../components/RecoveryCodeReveal";
import { CheckIcon } from "../components/CheckIcon";
import { useSavedFlash } from "../lib/useSavedFlash";
import pkg from "../../package.json";

/** Settings screen (`docs/ROADMAP.md` M4). "Cambia passphrase" is a documented stub this
 * milestone — no client capability exists yet for it (see this milestone's report). */
export function Settings({ onBack }: { onBack: () => void }) {
  const queryClient = useQueryClient();
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: settingsGet });
  const [autoLockMinutes, setAutoLockMinutes] = useState(5);
  const [cacheLimitMb, setCacheLimitMb] = useState(512);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);

  // "Adjusting state when a prop changes" (react.dev), done during render rather than in an
  // effect: tracks the last-loaded/last-saved settings for dirty-tracking below. Updated
  // whenever `settingsQuery.data` gets a new reference — a fresh fetch, or the value written
  // back by `saveMutation.onSuccess`.
  const [loadedSettings, setLoadedSettings] = useState(settingsQuery.data);
  if (settingsQuery.data && settingsQuery.data !== loadedSettings) {
    setLoadedSettings(settingsQuery.data);
  }

  // Seeds the editable fields exactly once per mount. Must NOT reuse the "differs from
  // loadedSettings" check above as its trigger: on a revisit of Settings already fetched earlier
  // this session, TanStack Query serves the cached result synchronously on the very first
  // render, so `settingsQuery.data` and the `useState(settingsQuery.data)` initializer above
  // capture the identical reference on render #1 — "differs" is false from the start, and the
  // fields would never get seeded. See the identical fix and rationale in `Document.tsx` (this
  // uses a `useState` flag rather than a ref for the same reason noted there: refs can't be
  // read/written during render under this project's lint rules).
  const [seeded, setSeeded] = useState(false);
  if (settingsQuery.data && !seeded) {
    setSeeded(true);
    setAutoLockMinutes(settingsQuery.data.auto_lock_minutes);
    setCacheLimitMb(Number(settingsQuery.data.cache_limit_mb));
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      settingsSet({
        auto_lock_minutes: autoLockMinutes,
        cache_limit_mb: BigInt(cacheLimitMb),
        server_url: settingsQuery.data?.server_url ?? "",
      }),
    onSuccess: (data) => queryClient.setQueryData(["settings"], data),
  });

  // Same dirty-tracking as `Document.tsx`: these inputs save on blur with no explicit Save
  // button, so the only feedback the user gets is this "salvato" message, shown once a save
  // succeeds and hidden again as soon as a field diverges from what was last saved.
  const savedAutoLockMinutes = loadedSettings?.auto_lock_minutes ?? autoLockMinutes;
  const savedCacheLimitMb = loadedSettings ? Number(loadedSettings.cache_limit_mb) : cacheLimitMb;
  const isDirty = autoLockMinutes !== savedAutoLockMinutes || cacheLimitMb !== savedCacheLimitMb;
  const showSaved = useSavedFlash(saveMutation.isSuccess, isDirty);

  const recoveryMutation = useMutation({
    mutationFn: vaultAddRecoveryCode,
    onSuccess: setRecoveryCode,
  });

  const lockMutation = useMutation({
    mutationFn: vaultLock,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] }),
  });

  if (recoveryCode) {
    return <RecoveryCodeReveal code={recoveryCode} onContinue={() => setRecoveryCode(null)} />;
  }

  return (
    <main className="flex min-h-screen flex-col gap-5 bg-neutral-950 p-4 pb-[env(safe-area-inset-bottom)] text-neutral-100">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onBack}
          className="min-h-11 min-w-11 rounded-md border border-neutral-700 px-3"
        >
          {it.common.back}
        </button>
        <h1 className="text-lg font-semibold">{it.settings.heading}</h1>
      </div>

      {settingsQuery.data && (
        <p className="text-sm text-neutral-500">
          {it.settings.serverUrl}: {settingsQuery.data.server_url}
        </p>
      )}

      <label className="flex flex-col gap-1 text-sm text-neutral-300">
        {it.settings.autoLockMinutes}
        <input
          type="number"
          min={1}
          max={30}
          value={autoLockMinutes}
          onChange={(e) => setAutoLockMinutes(Number(e.target.value))}
          onBlur={() => saveMutation.mutate()}
          className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2"
        />
      </label>

      <label className="flex flex-col gap-1 text-sm text-neutral-300">
        {it.settings.cacheLimitMb}
        <input
          type="number"
          min={1}
          value={cacheLimitMb}
          onChange={(e) => setCacheLimitMb(Number(e.target.value))}
          onBlur={() => saveMutation.mutate()}
          className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2"
        />
      </label>

      {saveMutation.isError && (
        <p role="alert" className="text-sm text-red-400">
          {errorMessage(saveMutation.error)}
        </p>
      )}
      {showSaved && (
        <p
          aria-live="polite"
          className="inline-flex w-fit items-center gap-1.5 rounded-full border border-emerald-800 bg-emerald-950 px-2.5 py-1 text-xs text-emerald-400"
        >
          <CheckIcon className="h-3.5 w-3.5" />
          {it.common.saved}
        </p>
      )}

      <button
        type="button"
        onClick={() => recoveryMutation.mutate()}
        disabled={recoveryMutation.isPending}
        className="min-h-11 rounded-md border border-neutral-700 px-4 py-3 disabled:opacity-40"
      >
        {it.settings.addRecoveryCode}
      </button>
      {recoveryMutation.isError && (
        <p role="alert" className="text-sm text-red-400">
          {errorMessage(recoveryMutation.error)}
        </p>
      )}

      <button
        type="button"
        disabled
        title={it.common.comingSoon}
        className="min-h-11 rounded-md border border-neutral-800 px-4 py-3 text-neutral-600"
      >
        {it.settings.changePassphrase}
      </button>

      <button
        type="button"
        onClick={() => lockMutation.mutate()}
        className="min-h-11 rounded-md bg-red-700 px-4 py-3 font-medium text-white"
      >
        {it.settings.lockNow}
      </button>

      <section className="mt-auto text-xs text-neutral-500">
        <h2 className="font-semibold text-neutral-400">{it.settings.about}</h2>
        <p>{it.appName}</p>
        <p>{it.settings.aboutVersion(pkg.version)}</p>
      </section>
    </main>
  );
}
