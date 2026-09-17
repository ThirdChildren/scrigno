import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import { vaultUnlock } from "../lib/ipc";

/**
 * Unlock screen (`docs/ROADMAP.md` M4). Desktop has no quick-unlock affordance this milestone
 * (`vault_unlock_quick` always rejects with `quick_unlock_unavailable` on desktop,
 * `docs/ARCHITECTURE.md §6`) — feature detection for M4's only target platform resolves to
 * "unavailable", so the passphrase field is shown directly, per the brief.
 */
export function Unlock() {
  const queryClient = useQueryClient();
  const [passphrase, setPassphrase] = useState("");

  const mutation = useMutation({
    mutationFn: () => vaultUnlock({ passphrase }),
    onSuccess: () => {
      setPassphrase("");
      void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] });
    },
  });

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-5 bg-neutral-950 p-6 text-neutral-100">
      <h1 className="text-2xl font-semibold">{it.unlock.heading}</h1>
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
