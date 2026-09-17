import { describe, expect, it as vitestIt, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { Document } from "./Document";
import { it } from "../i18n/it";
import type { DocMeta } from "../lib/ipc";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockInvoke = vi.mocked(invoke);

function makeMeta(overrides: Partial<DocMeta> = {}): DocMeta {
  return {
    v: 1,
    title: "Passaporto",
    tags: ["viaggi", "identità"],
    note: "Scaduto nel 2030",
    mime: "image/png",
    size: 12345,
    content_hash: "abc123",
    original_name: "passaporto.png",
    created_at: "2026-01-01T00:00:00Z",
    thumb: null,
    ...overrides,
  };
}

function renderDocument(id = "doc-1") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <Document id={id} onBack={() => {}} />
    </QueryClientProvider>,
  );
}

describe("Document", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    // jsdom has no object URL implementation; `useObjectUrl` (image preview / thumbnails) needs
    // one to exist even though these tests don't assert on the preview itself.
    Object.assign(URL, {
      createObjectURL: vi.fn(() => "blob:mock"),
      revokeObjectURL: vi.fn(),
    });
  });

  // Exercises the real `Document.tsx` component (mocked IPC only) to check the reported bug:
  // opening a document should prefill title/tags/note with its current saved values, not leave
  // them blank. This passes against the real component/prefill logic — see the investigation
  // notes in the handback report for what that does and doesn't rule out about the field-blanking
  // bug seen in the running app.
  vitestIt("prefills title/tags/note from doc_get_meta", async () => {
    const meta = makeMeta();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "doc_get_meta") return Promise.resolve(meta);
      if (cmd === "docs_list") return Promise.resolve([]);
      if (cmd === "doc_open") return Promise.resolve(new ArrayBuffer(8));
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });

    renderDocument();

    expect(await screen.findByDisplayValue(meta.title)).toBeInTheDocument();
    expect(screen.getByDisplayValue("viaggi, identità")).toBeInTheDocument();
    expect(screen.getByDisplayValue(meta.note)).toBeInTheDocument();
  });

  vitestIt("surfaces an error and leaves fields empty when doc_get_meta fails", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "doc_get_meta") {
        return Promise.reject({ code: "not_found", message: "not found" });
      }
      if (cmd === "docs_list") return Promise.resolve([]);
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });

    renderDocument();

    expect(await screen.findByRole("alert")).toHaveTextContent("Documento non trovato.");
    expect(screen.getByLabelText(it.common.title)).toHaveValue("");
  });

  vitestIt("keeps Save disabled with nothing to save, enables it on edit, confirms after saving", async () => {
    let meta = makeMeta();
    mockInvoke.mockImplementation((cmd: string, args?: unknown) => {
      if (cmd === "doc_get_meta") return Promise.resolve(meta);
      if (cmd === "docs_list") return Promise.resolve([]);
      if (cmd === "doc_open") return Promise.resolve(new ArrayBuffer(8));
      if (cmd === "doc_update_meta") {
        const a = args as { title: string; tags: string[]; note: string };
        meta = { ...meta, title: a.title, tags: a.tags, note: a.note };
        return Promise.resolve({
          id: "doc-1",
          title: meta.title,
          tags: meta.tags,
          note: meta.note,
          mime: meta.mime,
          size: BigInt(meta.size),
          content_hash: meta.content_hash,
          original_name: meta.original_name,
          created_at: meta.created_at,
          version: 2n,
          dirty: false,
          keep_offline: false,
          blob_size: 0n,
          cached: true,
        });
      }
      return Promise.reject(new Error(`unexpected command ${cmd}`));
    });

    const user = userEvent.setup();
    renderDocument();

    const titleInput = await screen.findByDisplayValue(meta.title);
    const saveButton = screen.getByRole("button", { name: it.common.save });
    expect(saveButton).toBeDisabled();

    await user.clear(titleInput);
    await user.type(titleInput, "Nuovo titolo");
    expect(saveButton).toBeEnabled();

    await user.click(saveButton);

    await waitFor(() => {
      expect(saveButton).toBeDisabled();
    });
    expect(await screen.findByRole("alert")).toHaveTextContent(it.common.saved);
  });
});
