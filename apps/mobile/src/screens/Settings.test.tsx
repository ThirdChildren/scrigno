import { describe, expect, it as vitestIt, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { Settings } from "./Settings";
import { it } from "../i18n/it";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockInvoke = vi.mocked(invoke);

function renderSettings() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <Settings onBack={() => {}} />
    </QueryClientProvider>,
  );
}

function defaultInvokeImpl(cmd: string) {
  if (cmd === "settings_get") {
    return Promise.resolve({
      auto_lock_minutes: 5,
      cache_limit_mb: 512n,
      server_url: "http://127.0.0.1:8787",
      quick_unlock_enabled: false,
    });
  }
  if (cmd === "vault_lock") return Promise.resolve(undefined);
  if (cmd === "vault_forget_quick_unlock") return Promise.resolve(undefined);
  if (cmd === "vault_status") return Promise.resolve("locked");
  return Promise.reject(new Error(`unexpected command ${cmd}`));
}

describe("Settings", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  // Crypto-reviewer's flagged, security-relevant gap: a plain `vault_lock` alone leaves quick
  // unlock enrolled on Android. "Blocca completamente" must call both commands, every time,
  // regardless of whether quick unlock was ever enabled in this session.
  vitestIt("Blocca completamente calls both vault_lock and vault_forget_quick_unlock", async () => {
    mockInvoke.mockImplementation(defaultInvokeImpl);
    const user = userEvent.setup();
    renderSettings();

    await screen.findByText(/127\.0\.0\.1:8787/);
    await user.click(screen.getByRole("button", { name: it.settings.lockNow }));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith("vault_lock");
      expect(mockInvoke).toHaveBeenCalledWith("vault_forget_quick_unlock");
    });
  });

  vitestIt("initializes the quick-unlock toggle as enabled when already enrolled", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "settings_get") {
        return Promise.resolve({
          auto_lock_minutes: 5,
          cache_limit_mb: 512n,
          server_url: "http://127.0.0.1:8787",
          quick_unlock_enabled: true,
        });
      }
      return defaultInvokeImpl(cmd);
    });
    renderSettings();

    expect(
      await screen.findByRole("button", { name: it.settings.quickUnlockEnabled }),
    ).toBeInTheDocument();
  });

  vitestIt("shows the quick-unlock security disclosure", async () => {
    mockInvoke.mockImplementation(defaultInvokeImpl);
    renderSettings();

    expect(await screen.findByText(it.settings.quickUnlockDisclosure)).toBeInTheDocument();
  });

  vitestIt("enrolling quick unlock asks for the passphrase and calls vault_enable_quick_unlock", async () => {
    mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
      if (cmd === "vault_enable_quick_unlock") {
        expect((args as { passphrase: string }).passphrase).toBe("correct horse battery staple");
        return Promise.resolve(undefined);
      }
      return defaultInvokeImpl(cmd);
    });
    const user = userEvent.setup();
    renderSettings();

    await screen.findByText(/127\.0\.0\.1:8787/);
    await user.click(screen.getByRole("button", { name: it.settings.quickUnlockEnable }));
    await user.type(
      screen.getByLabelText(it.settings.quickUnlockConfirmPassphrase),
      "correct horse battery staple",
    );
    await user.click(screen.getByRole("button", { name: it.settings.quickUnlockActivate }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: it.settings.quickUnlockEnabled })).toBeInTheDocument();
    });
  });

  vitestIt("toggling quick unlock off calls vault_forget_quick_unlock", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "vault_enable_quick_unlock") return Promise.resolve(undefined);
      if (cmd === "vault_forget_quick_unlock") return Promise.resolve(undefined);
      return defaultInvokeImpl(cmd);
    });
    const user = userEvent.setup();
    renderSettings();

    await screen.findByText(/127\.0\.0\.1:8787/);
    await user.click(screen.getByRole("button", { name: it.settings.quickUnlockEnable }));
    await user.type(screen.getByLabelText(it.settings.quickUnlockConfirmPassphrase), "a long passphrase");
    await user.click(screen.getByRole("button", { name: it.settings.quickUnlockActivate }));
    await screen.findByRole("button", { name: it.settings.quickUnlockEnabled });

    mockInvoke.mockClear();
    await user.click(screen.getByRole("button", { name: it.settings.quickUnlockEnabled }));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith("vault_forget_quick_unlock");
    });
    expect(await screen.findByRole("button", { name: it.settings.quickUnlockEnable })).toBeInTheDocument();
  });
});
