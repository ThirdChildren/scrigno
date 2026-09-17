/** Small checkmark glyph used for the inline "saved" confirmation. Purely decorative — the
 * confirmation text next to it carries the meaning, so this is always `aria-hidden`. */
export function CheckIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" aria-hidden="true">
      <path strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}
