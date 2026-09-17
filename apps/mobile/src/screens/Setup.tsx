import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { it } from "../i18n/it";
import { errorMessage } from "../i18n/errors";
import { vaultCreate, vaultJoin, vaultAddRecoveryCode } from "../lib/ipc";
import { passphraseStrength, MIN_PASSPHRASE_LENGTH } from "../lib/passphrase";
import { RecoveryCodeReveal } from "../components/RecoveryCodeReveal";

// Dev default suggested by the setup UI (docs/ARCHITECTURE.md §7); editable.
const DEFAULT_SERVER_URL = "http://127.0.0.1:8787";

type Mode = "create" | "join";

const strengthLabel = {
  weak: it.setup.strengthWeak,
  fair: it.setup.strengthFair,
  strong: it.setup.strengthStrong,
} as const;

/** Setup screen: create a new vault or join an existing one (`docs/ROADMAP.md` M4). */
export function Setup() {
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<Mode>("create");
  const [serverUrl, setServerUrl] = useState(DEFAULT_SERVER_URL);
  const [token, setToken] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      if (mode === "create") {
        await vaultCreate({ serverUrl, token, passphrase });
        const code = await vaultAddRecoveryCode();
        setRecoveryCode(code);
      } else {
        await vaultJoin({ serverUrl, token, passphrase });
        await queryClient.invalidateQueries({ queryKey: ["vaultStatus"] });
      }
    },
  });

  if (recoveryCode) {
    return (
      <RecoveryCodeReveal
        code={recoveryCode}
        onContinue={() => {
          setRecoveryCode(null);
          void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] });
        }}
      />
    );
  }

  const tooShort = passphrase.length > 0 && passphrase.length < MIN_PASSPHRASE_LENGTH;
  const mismatch = confirm.length > 0 && confirm !== passphrase;
  const canSubmit =
    serverUrl.trim() !== "" &&
    token.trim() !== "" &&
    passphrase.length >= MIN_PASSPHRASE_LENGTH &&
    passphrase === confirm &&
    !mutation.isPending;

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col gap-5 bg-neutral-950 p-6 text-neutral-100">
      <h1 className="text-2xl font-semibold">{it.setup.heading}</h1>

      <div className="flex gap-2" role="tablist">
        {(["create", "join"] as const).map((m) => (
          <button
            key={m}
            type="button"
            role="tab"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className={`min-h-11 flex-1 rounded-md px-3 py-2 text-sm ${
              mode === m ? "bg-emerald-600 text-white" : "bg-neutral-900 text-neutral-300"
            }`}
          >
            {m === "create" ? it.setup.modeCreate : it.setup.modeJoin}
          </button>
        ))}
      </div>

      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          mutation.reset();
          mutation.mutate();
        }}
      >
        <Field id="server-url" label={it.setup.serverUrl} value={serverUrl} onChange={setServerUrl} />
        <p className="text-xs text-neutral-500">{it.setup.serverUrlHintAndroidEmulator}</p>
        <p className="text-xs text-neutral-500">{it.setup.serverUrlHintAndroidPhone}</p>
        <Field id="token" label={it.setup.token} value={token} onChange={setToken} type="password" />
        <Field
          id="passphrase"
          label={it.setup.passphrase}
          value={passphrase}
          onChange={setPassphrase}
          type="password"
        />
        {passphrase.length > 0 && (
          <p className="text-sm text-neutral-400">
            {tooShort ? it.setup.passphraseTooShort : strengthLabel[passphraseStrength(passphrase)]}
          </p>
        )}
        <Field
          id="passphrase-confirm"
          label={it.setup.passphraseConfirm}
          value={confirm}
          onChange={setConfirm}
          type="password"
        />
        {mismatch && <p className="text-sm text-red-400">{it.setup.passphraseMismatch}</p>}
        <p className="text-xs text-neutral-500">{it.setup.passphraseHint}</p>

        {mutation.isError && (
          <p role="alert" className="text-sm text-red-400">
            {errorMessage(mutation.error)}
          </p>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="min-h-11 rounded-md bg-emerald-600 px-4 py-3 font-medium text-white disabled:opacity-40"
        >
          {mutation.isPending
            ? it.setup.submitting
            : mode === "create"
              ? it.setup.submitCreate
              : it.setup.submitJoin}
        </button>
      </form>
    </main>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
  type = "text",
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm text-neutral-300">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="min-h-11 rounded-md border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-100"
      />
    </div>
  );
}
