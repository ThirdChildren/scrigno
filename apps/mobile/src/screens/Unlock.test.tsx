import { describe, expect, it as vitestIt, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { Unlock } from "./Unlock";
import { it } from "../i18n/it";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockInvoke = vi.mocked(invoke);

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
    renderUnlock();
    expect(screen.getByLabelText(it.unlock.passphrase)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: it.unlock.submit })).toBeInTheDocument();
  });

  vitestIt("submits the entered passphrase via vault_unlock", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock") return Promise.resolve(undefined);
      if (cmd === "vault_status") return Promise.resolve("unlocked");
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
      return Promise.resolve("locked");
    });
    const user = userEvent.setup();
    renderUnlock();

    await user.type(screen.getByLabelText(it.unlock.passphrase), "not the right one");
    await user.click(screen.getByRole("button", { name: it.unlock.submit }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Passphrase errata");
  });

  vitestIt("triggers a vault_status refetch after a successful unlock", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_unlock") return Promise.resolve(undefined);
      if (cmd === "vault_status") return Promise.resolve("unlocked");
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
