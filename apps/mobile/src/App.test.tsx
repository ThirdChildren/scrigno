import { describe, expect, it as vitestIt } from "vitest";
import { render, screen } from "@testing-library/react";
import App from "./App";
import { it } from "./i18n/it";

describe("App", () => {
  vitestIt("shows the app name and the hard-coded vault status", () => {
    render(<App />);

    expect(screen.getByText(it.appName)).toBeInTheDocument();
    expect(screen.getByText(it.vaultStatus.uninitialised)).toBeInTheDocument();
  });
});
