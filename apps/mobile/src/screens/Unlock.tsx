import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import { isAppError, settingsGet, vaultUnlock, vaultUnlockQuick } from "../lib/ipc";

/**
 * Unlock screen (`docs/ROADMAP.md` M4/M5). The passphrase field is always shown; the quick-unlock
 * (biometric) affordance is an addition on top, not a replacement.
 *
 * `settings_get` is callable while the vault is locked: `commands.rs::settings_get` only reaches
 * into `UnlockedVault` state for `cache_limit_mb` (falling back to a display default otherwise),
 * and `auto_lock_minutes`/`server_url`/`quick_unlock_enabled` never require an unlock. So this
 * screen reads the real, persisted enrollment status (`Settings.quick_unlock_enabled`,
 * `docs/CRYPTO.md §5.2`) up front and only renders the button when it's actually enrolled,
 * instead of showing it unconditionally and discovering the answer from a failed unlock attempt.
 * A `quick_unlock_unavailable` rejection at click time (e.g. enrollment revoked between the query
 * firing and the click) still hides the button for the rest of this screen's lifetime, as a
 * defensive fallback rather than the primary signal.
 */
export function Unlock() {
  const queryClient = useQueryClient();
  const [passphrase, setPassphrase] = useState("");
  const [quickUnlockUnavailable, setQuickUnlockUnavailable] = useState(false);

  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: settingsGet });
  const quickUnlockAvailable =
    (settingsQuery.data?.quick_unlock_enabled ?? false) && !quickUnlockUnavailable;

  const mutation = useMutation({
    mutationFn: () => vaultUnlock({ passphrase }),
    onSuccess: () => {
      setPassphrase("");
      void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] });
    },
  });

  const quickMutation = useMutation({
    mutationFn: () => vaultUnlockQuick(it.unlock.quickUnlockReason),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] }),
    onError: (err: unknown) => {
      if (isAppError(err) && err.code === "quick_unlock_unavailable") {
        setQuickUnlockUnavailable(true);
      }
    },
  });

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-5 bg-neutral-950 p-6 text-neutral-100">
      <h1 className="text-2xl font-semibold">{it.unlock.heading}</h1>

      {quickUnlockAvailable && (
        <div className="flex flex-col gap-3">
          <button
            type="button"
            onClick={() => quickMutation.mutate()}
            disabled={quickMutation.isPending}
            className="min-h-11 rounded-md border border-emerald-700 px-4 py-3 font-medium text-emerald-400 disabled:opacity-40"
          >
            {quickMutation.isPending ? it.unlock.quickUnlockSubmitting : it.unlock.quickUnlock}
          </button>
          {quickMutation.isError && (
            <p role="alert" className="text-sm text-red-400">
              {errorMessage(quickMutation.error)}
            </p>
          )}
          <p className="text-center text-xs text-neutral-500">{it.unlock.or}</p>
        </div>
      )}

      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          mutation.reset();
          mutation.mutate();
        }}
      >
        <div className="flex flex-col gap-1">
          <label htmlFor="unlock-passphrase" className="text-sm text-neutral-300">
            {it.unlock.passphrase}
          </label>
          <input
            id="unlock-passphrase"
            type="password"
            autoFocus
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-100"
          />
        </div>

        {mutation.isError && (
          <p role="alert" className="text-sm text-red-400">
            {errorMessage(mutation.error)}
          </p>
        )}

        <button
          type="submit"
          disabled={passphrase.length === 0 || mutation.isPending}
          className="min-h-11 rounded-md bg-emerald-600 px-4 py-3 font-medium text-white disabled:opacity-40"
        >
          {mutation.isPending ? it.unlock.submitting : it.unlock.submit}
        </button>
      </form>
    </main>
  );
}
