import { describe, expect, it as vitestIt, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import App from "./App";
import { it } from "./i18n/it";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn().mockResolvedValue(() => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const mockInvoke = vi.mocked(invoke);

function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  );
}

describe("App", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  vitestIt("routes to Setup when the vault is uninitialised", async () => {
    mockInvoke.mockResolvedValue("uninitialised");
    renderApp();

    expect(await screen.findByText(it.setup.heading)).toBeInTheDocument();
  });

  vitestIt("routes to Unlock when the vault is locked", async () => {
    mockInvoke.mockResolvedValue("locked");
    renderApp();

    expect(await screen.findByText(it.unlock.heading)).toBeInTheDocument();
  });
});
