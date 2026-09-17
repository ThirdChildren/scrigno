// Client-side passphrase strength hint only (`docs/CRYPTO.md §3`: "show an entropy hint, no
// composition rules"). This never blocks submission beyond the 12-char floor the core/server also
// enforce — it is purely a UI nudge.
export type PassphraseStrength = "weak" | "fair" | "strong";

const MIN_LENGTH = 12;

/** A rough, non-authoritative strength estimate from length and character-class variety. */
export function passphraseStrength(passphrase: string): PassphraseStrength {
  if (passphrase.length < MIN_LENGTH) return "weak";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) =>
    re.test(passphrase),
  ).length;
  if (passphrase.length >= 16 && classes >= 3) return "strong";
  if (passphrase.length >= 12 && classes >= 2) return "fair";
  return "weak";
}

export { MIN_LENGTH as MIN_PASSPHRASE_LENGTH };
