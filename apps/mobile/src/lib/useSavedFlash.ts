import { useEffect, useState } from "react";

const FLASH_MS = 2000;

/**
 * Drives a brief "saved" confirmation instead of a persistent banner: flips `true` the instant
 * `isSuccess` transitions to `true` (i.e. right after a save resolves), then clears itself after
 * a couple of seconds. Also clears immediately once `isDirty` is `true` again, so editing a field
 * hides a stale confirmation instead of leaving it lingering past the point it's still accurate.
 */
export function useSavedFlash(isSuccess: boolean, isDirty: boolean): boolean {
  const [lastSuccess, setLastSuccess] = useState(isSuccess);
  const [flash, setFlash] = useState(false);

  // Adjusting state during render (react.dev "You Might Not Need an Effect"), same pattern as
  // the loadedMeta/loadedSettings prefill in `Document.tsx`/`Settings.tsx`: flips on the same
  // render `isSuccess` turns true, no extra render round-trip just to notice the transition.
  if (isSuccess !== lastSuccess) {
    setLastSuccess(isSuccess);
    if (isSuccess) setFlash(true);
  }

  // The auto-clear timer is a genuine effect (a subscription to the passage of time), so it's
  // the one part of this hook that belongs in `useEffect` — and the `setFlash(false)` inside it
  // runs from the `setTimeout` callback, not synchronously in the effect body.
  useEffect(() => {
    if (!flash) return;
    const timer = setTimeout(() => setFlash(false), FLASH_MS);
    return () => clearTimeout(timer);
  }, [flash]);

  return flash && !isDirty;
}
