import { it } from "../i18n/it";
import type { SyncReport } from "../lib/ipc";

/**
 * Shows the last `sync_now` result (`docs/ARCHITECTURE.md §5`) and a rollback warning if any
 * `SyncWarning::ServerRollback` was observed. `aria-live` so screen readers announce updates.
 */
export function SyncBanner({ report, syncing }: { report: SyncReport | null; syncing: boolean }) {
  if (!syncing && !report) return null;

  const hasRollback = report?.warnings.some((w) => w.kind === "ServerRollback") ?? false;

  return (
    <div aria-live="polite" className="flex flex-col gap-1 rounded-md bg-neutral-900 px-3 py-2 text-sm">
      {syncing && <span className="text-neutral-300">{it.vault.syncing}</span>}
      {!syncing && report && (
        <span className="text-neutral-300">
          {it.syncBanner.pulled(report.pulled)} · {it.syncBanner.pushed(report.pushed)} ·{" "}
          {it.syncBanner.conflicts(report.conflicts)}
        </span>
      )}
      {hasRollback && (
        <span role="alert" className="text-amber-400">
          {it.syncBanner.rollback}
        </span>
      )}
    </div>
  );
}
