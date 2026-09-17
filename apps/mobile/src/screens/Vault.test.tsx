import { describe, expect, it as vitestIt, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { Vault } from "./Vault";
import { it } from "../i18n/it";
import type { DocSummary } from "../lib/ipc";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../lib/downscaleImage", () => ({
  downscaleImage: vi.fn().mockResolvedValue({ bytes: new ArrayBuffer(4), mime: "image/jpeg" }),
}));

const mockInvoke = vi.mocked(invoke);

function makeDoc(overrides: Partial<DocSummary>): DocSummary {
  return {
    id: "id-1",
    title: "Carta d'identità",
    tags: ["identità"],
    note: "",
    mime: "application/pdf",
    size: 1000n,
    content_hash: "abc",
    original_name: "scan.pdf",
    created_at: "2026-01-01T00:00:00Z",
    version: 1n,
    dirty: false,
    keep_offline: false,
    blob_size: 1000n,
    cached: true,
    ...overrides,
  };
}

function renderVault(docs: DocSummary[]) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "docs_list") return Promise.resolve(docs);
    if (cmd === "doc_thumb") return Promise.resolve(new ArrayBuffer(0));
    return Promise.reject(new Error(`unexpected command ${cmd}`));
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <Vault onOpenDocument={() => {}} onOpenSettings={() => {}} />
    </QueryClientProvider>,
  );
}

describe("Vault", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  vitestIt("renders one grid item per document", async () => {
    const docs = [
      makeDoc({ id: "1", title: "Passaporto" }),
      makeDoc({ id: "2", title: "Bolletta" }),
    ];
    renderVault(docs);

    expect(await screen.findByText("Passaporto")).toBeInTheDocument();
    expect(screen.getByText("Bolletta")).toBeInTheDocument();
  });

  vitestIt("filters the already-fetched list client-side without another docs_list call", async () => {
    const docs = [
      makeDoc({ id: "1", title: "Passaporto" }),
      makeDoc({ id: "2", title: "Bolletta" }),
    ];
    renderVault(docs);
    await screen.findByText("Passaporto");

    const callsBeforeSearch = mockInvoke.mock.calls.filter(([cmd]) => cmd === "docs_list").length;

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(it.vault.searchPlaceholder), "bolletta");

    expect(screen.queryByText("Passaporto")).not.toBeInTheDocument();
    expect(screen.getByText("Bolletta")).toBeInTheDocument();

    const callsAfterSearch = mockInvoke.mock.calls.filter(([cmd]) => cmd === "docs_list").length;
    expect(callsAfterSearch).toBe(callsBeforeSearch);
  });

  vitestIt("filters by title or tag substring", async () => {
    const docs = [
      makeDoc({ id: "1", title: "Passaporto", tags: ["viaggi"] }),
      makeDoc({ id: "2", title: "Bolletta", tags: ["casa"] }),
    ];
    renderVault(docs);
    await screen.findByText("Passaporto");

    const user = userEvent.setup();
    await user.type(screen.getByLabelText(it.vault.searchPlaceholder), "viaggi");

    expect(screen.getByText("Passaporto")).toBeInTheDocument();
    expect(screen.queryByText("Bolletta")).not.toBeInTheDocument();
  });

  // M5: camera capture must downscale before any bytes cross IPC (`docs/ROADMAP.md`), and go
  // through `doc_add_bytes` rather than `doc_add_from_path`.
  vitestIt("downscales a captured photo and opens the add form with the resulting bytes", async () => {
    renderVault([]);
    await screen.findByText(it.vault.empty);

    const user = userEvent.setup();
    const file = new File([new Uint8Array([1, 2, 3])], "foto.jpg", { type: "image/jpeg" });
    const input = document.getElementById("vault-camera-input") as HTMLInputElement;
    await user.upload(input, file);

    expect(await screen.findByText(it.vault.addTitle)).toBeInTheDocument();

    const { downscaleImage } = await import("../lib/downscaleImage");
    expect(downscaleImage).toHaveBeenCalledWith(file);
  });
});
