import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import { it } from "./i18n/it";
import { errorMessage } from "./i18n/errors";
import { vaultStatus } from "./lib/ipc";
import { Setup } from "./screens/Setup";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import { Document } from "./screens/Document";
import { Settings } from "./screens/Settings";

type View = { type: "vault" } | { type: "document"; id: string } | { type: "settings" };

/**
 * Everything shown once the vault is unlocked. A tiny hand-rolled router: the app is small
 * enough that a full router library would be overkill (`docs/ROADMAP.md` M4).
 */
function AuthenticatedApp() {
  const [view, setView] = useState<View>({ type: "vault" });

  if (view.type === "document") {
    return <Document id={view.id} onBack={() => setView({ type: "vault" })} />;
  }
  if (view.type === "settings") {
    return <Settings onBack={() => setView({ type: "vault" })} />;
  }
  return (
    <Vault
      onOpenDocument={(id) => setView({ type: "document", id })}
      onOpenSettings={() => setView({ type: "settings" })}
    />
  );
}

/** Top-level routing keyed on `vault_status` (`docs/ARCHITECTURE.md §6`). */
function App() {
  const queryClient = useQueryClient();
  const statusQuery = useQuery({
    queryKey: ["vaultStatus"],
    queryFn: vaultStatus,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void listen("vault-locked", () => {
      // Auto-lock fired server-side: drop every cache that assumed the vault was unlocked
      // (CLAUDE.md: "clearing in-memory document state and object URLs" — unmounting Vault/
      // Document below revokes their own object URLs via `useObjectUrl`'s cleanup) and force an
      // immediate refetch so routing falls back to Unlock rather than waiting on a poll.
      queryClient.removeQueries({ queryKey: ["docsList"] });
      queryClient.removeQueries({ queryKey: ["docMeta"] });
      void queryClient.invalidateQueries({ queryKey: ["vaultStatus"] });
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [queryClient]);

  if (statusQuery.isError) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-neutral-950 text-neutral-100">
        <h1 className="text-2xl font-semibold">{it.appName}</h1>
        <p role="alert" className="text-red-400">
          {errorMessage(statusQuery.error)}
        </p>
      </main>
    );
  }

  if (statusQuery.isLoading || !statusQuery.data) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-neutral-950 text-neutral-100">
        <h1 className="text-4xl font-semibold">{it.appName}</h1>
        <p className="text-neutral-400">{it.common.loading}</p>
      </main>
    );
  }

  switch (statusQuery.data) {
    case "uninitialised":
      return <Setup />;
    case "locked":
      return <Unlock />;
    case "unlocked":
      return <AuthenticatedApp />;
  }
}

export default App;
