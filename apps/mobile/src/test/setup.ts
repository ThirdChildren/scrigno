import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

// `vitest.config`'s `test.globals` is not enabled (tests import `describe`/`it`/`expect`
// explicitly), so `@testing-library/react`'s own auto-cleanup — which relies on detecting a
// global `afterEach` — never registers itself. Do it explicitly so every test file starts from
// an empty DOM.
afterEach(() => {
  cleanup();
});
