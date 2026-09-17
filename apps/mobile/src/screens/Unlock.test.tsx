import { describe, expect, it as vitestIt, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { Unlock } from "./Unlock";
import { it } from "../i18n/it";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockInvoke = vi.mocked(invoke);

function settingsResponse(quickUnlockEnabled: boolean) {
  return {
    auto_lock_minutes: 5,
    cache_limit_mb: 512n,
    server_url: "http://127.0.0.1:8787",
    quick_unlock_enabled: quickUnlockEnabled,
  };
}

/** Mounts a dummy `vaultStatus` observer alongside `Unlock` so that the query client's
 * `invalidateQueries` call on unlock success has an active subscriber to trigger a real refetch,
 * the same way `App.tsx`'s routing query would. */
function StatusProbe() {
  const query = useQuery({ queryKey: ["vaultStatus"], queryFn: () => invoke("vault_status") });
  return <div data-testid="status">{String(query.data ?? "")}</div>;
}

function renderUnlock() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <StatusProbe />
      <Unlock />
    </QueryClientProvider>,
  );
}

describe("Unlock", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  vitestIt("renders a passphrase field and a submit button", () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(false));
      return Promise.resolve("locked");
    });
    renderUnlock();
    expect(screen.getByLabelText(it.unlock.passphrase)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: it.unlock.submit })).toBeInTheDocument();
  });

  vitestIt("submits the entered passphrase via vault_unlock", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock") return Promise.resolve(undefined);
      if (cmd === "vault_status") return Promise.resolve("unlocked");
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(false));
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });
    const user = userEvent.setup();
    renderUnlock();

    await user.type(screen.getByLabelText(it.unlock.passphrase), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: it.unlock.submit }));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith("vault_unlock", {
        passphrase: "correct horse battery staple",
      });
    });
  });

  vitestIt("shows the Italian wrong-passphrase message on failure", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock") {
        return Promise.reject({ code: "wrong_passphrase", message: "wrong passphrase" });
      }
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(false));
      return Promise.resolve("locked");
    });
    const user = userEvent.setup();
    renderUnlock();

    await user.type(screen.getByLabelText(it.unlock.passphrase), "not the right one");
    await user.click(screen.getByRole("button", { name: it.unlock.submit }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Passphrase errata");
  });

  vitestIt("does not show the biometric button when quick unlock isn't enrolled", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(false));
      return Promise.resolve("locked");
    });
    renderUnlock();

    await screen.findByLabelText(it.unlock.passphrase);
    expect(screen.queryByRole("button", { name: it.unlock.quickUnlock })).not.toBeInTheDocument();
  });

  vitestIt("shows a biometric quick-unlock button when enrolled and calls vault_unlock_quick with an Italian reason", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock_quick") return Promise.resolve(undefined);
      if (cmd === "vault_status") return Promise.resolve("unlocked");
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(true));
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });
    const user = userEvent.setup();
    renderUnlock();

    await user.click(await screen.findByRole("button", { name: it.unlock.quickUnlock }));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith("vault_unlock_quick", {
        reason: it.unlock.quickUnlockReason,
      });
    });
  });

  vitestIt("hides the quick-unlock button once it reports quick_unlock_unavailable, even though enrolled", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock_quick") {
        return Promise.reject({ code: "quick_unlock_unavailable", message: "unavailable" });
      }
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(true));
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });
    const user = userEvent.setup();
    renderUnlock();

    await user.click(await screen.findByRole("button", { name: it.unlock.quickUnlock }));

    await waitFor(() => {
      expect(screen.queryByRole("button", { name: it.unlock.quickUnlock })).not.toBeInTheDocument();
    });
  });

  vitestIt("triggers a vault_status refetch after a successful unlock", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock") return Promise.resolve(undefined);
      if (cmd === "vault_status") return Promise.resolve("unlocked");
      if (cmd === "settings_get") return Promise.resolve(settingsResponse(false));
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });
    const user = userEvent.setup();
    renderUnlock();

    await user.type(screen.getByLabelText(it.unlock.passphrase), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: it.unlock.submit }));

    await waitFor(() => {
      expect(screen.getByTestId("status")).toHaveTextContent("unlocked");
    });
  });
});
