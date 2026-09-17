import { useState } from "react";
import { it } from "../i18n/it";

/**
 * One-time recovery-code reveal. The plaintext code lives only in this component's `props` (owned
 * by the caller's local state) — it is never persisted, never re-fetchable
 * (`vault_add_recovery_code`'s own doc comment: "shown once"), and the caller must discard it from
 * state as soon as `onContinue` fires (see `Setup.tsx`/`Settings.tsx`).
 */
export function RecoveryCodeReveal({
  code,
  onContinue,
}: {
  code: string;
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    void navigator.clipboard.writeText(code).then(() => setCopied(true));
  };

  return (
    <div
      role="dialog"
      aria-labelledby="recovery-code-heading"
      className="flex min-h-screen flex-col gap-6 bg-neutral-950 p-6 text-neutral-100"
    >
      <h1 id="recovery-code-heading" className="text-2xl font-semibold">
        {it.recoveryCode.heading}
      </h1>
      <p className="text-neutral-400">{it.recoveryCode.body}</p>
      <p
        role="alert"
        className="rounded-md border border-amber-600 bg-amber-950/40 p-3 text-sm text-amber-300"
      >
        {it.recoveryCode.warning}
      </p>
      <code className="break-all rounded-md bg-neutral-900 p-4 text-center text-lg tracking-wider">
        {code}
      </code>
      <button
        type="button"
        onClick={handleCopy}
        className="min-h-11 rounded-md border border-neutral-700 px-4 py-3 text-neutral-100"
      >
        {copied ? it.recoveryCode.copied : it.recoveryCode.copy}
      </button>
      <div className="mt-auto pb-[env(safe-area-inset-bottom)]">
        <button
          type="button"
          onClick={onContinue}
          className="min-h-11 w-full rounded-md bg-emerald-600 px-4 py-3 font-medium text-white"
        >
          {it.recoveryCode.continueButton}
        </button>
      </div>
    </div>
  );
}
