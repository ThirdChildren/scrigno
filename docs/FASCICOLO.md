# Fascicolo — document kinds, validity rules, reminders

Implemented in `crates/scrigno-index::kinds` (pure functions, unit-tested against this table)
and shown in the app's kind picker. Rules are **defaults that propose a date**; the user can
always override `expires_at` because the printed date wins. Rules that depend on the holder's
age ask for an **age band**, never for a birth date (nothing personal is stored beyond the
document itself).

Legend: `+N y` = issued_at + N years; band = age of the holder at issue.

## Kinds

| id | Label (it) | Default validity | Reminders (days before) | Notes |
|---|---|---|---|---|
| `cie` | Carta d'identità | adult `+10 y`; band 3–18 `+5 y`; band 0–3 `+3 y` | 60, 30, 7 | Since 2008 expiry falls on the first birthday after the nominal term: round the proposed date **forward to the next birthday** only if the user enters a birth month/day (optional field, not stored) — otherwise keep the nominal date. Renewal needs an appointment: long lead time. |
| `passaporto` | Passaporto | adult `+10 y`; 3–18 `+5 y`; 0–3 `+3 y` | 60, 30, 7 | Same age bands as CIE. |
| `patente` | Patente di guida | band < 50 `+10 y`; 50–70 `+5 y`; 70–80 `+3 y`; > 80 `+2 y` | 60, 30, 7 | Category B and A. Professional categories differ: user edits. |
| `tessera_sanitaria` | Tessera sanitaria / CF | `+6 y` | 30, 7 | For non-EU citizens aligned with the permesso di soggiorno: user edits. |
| `permesso_soggiorno` | Permesso di soggiorno | none (mandatory manual date) | 90, 60, 30 | Duration varies (1–2 y, or unlimited for long-term residents). |
| `revisione` | Revisione veicolo | first `+4 y` from first registration, then `+2 y` | 30, 7 | The kind stores `issued_at` = last revisione (or registration date with a "prima revisione" toggle). |
| `bollo` | Bollo auto/moto | `+12 m` | 30, 7 | Regional deadlines vary by a few days: user edits if needed. |
| `assicurazione` | Assicurazione RC | `+12 m` (toggle `+6 m`) | 30, 7 | |
| `isee` | ISEE / DSU | 31 December of the issue year | 30 | |
| `certificato_medico` | Certificato medico sportivo | `+12 m` | 30, 7 | Agonistico and non agonistico both 1 year by default. |
| `garanzia` | Garanzia / scontrino | `+2 y` from purchase | 30 | Legal warranty for consumer goods. Attach the receipt. |
| `abbonamento` | Abbonamento / tessera | none (manual) | 7 | Gym, transport, memberships. |
| `contratto` | Contratto | none (manual) | 60, 30 | Rent, utilities, phone. Reminder = end or renewal date. |
| `carta_pagamento` | Carta di pagamento | none (manual) | 30 | Printed expiry. Store only the card image if you must; the app is not a wallet. |
| `referto` | Referto / documento medico | none | — | No expiry. |
| `fiscale` | Documento fiscale (CU, 730, F24…) | none | — | No expiry; keep for 5–10 years — a "keep until" hint is fine, no reminder. |
| `veicolo` | Libretto / documenti veicolo | none | — | |
| `casa` | Casa / atti / bollette | none | — | |
| `altro` | Altro | none | — | Default when unset. |

Age bands offered by the picker for `cie`, `passaporto`, `patente`: `0–3`, `3–18`, `18–50`,
`50–70`, `70–80`, `> 80` (the picker shows only the bands that matter for the chosen kind).

## Rules for `compute_expiry`

```
fn compute_expiry(kind: Kind, issued_at: Date, opts: &ExpiryOpts) -> Option<Date>
// opts: age_band: Option<AgeBand>, first_revisione: bool, six_months: bool
```
- Returns `None` for kinds with no default; the UI then requires a manual date for kinds whose
  reminder list is non-empty and simply leaves it blank otherwise.
- Adding years/months uses calendar arithmetic (`+1 y` from 29 Feb → 28 Feb).
- `isee`: `31 Dec` of `issued_at.year()`.
- Never guess an age band: if the kind needs one and none is given, use the adult band and flag
  `assumed_adult = true` in the result so the UI can show "calcolato per un maggiorenne".

## Reminder policy

- Per document: `remind_days` overrides the kind default; `null` = kind default.
- Global settings: master toggle, quiet hours (default 22:00–08:00: reminders scheduled at
  09:00 local), and "also remind on the expiry day" (default on).
- Reminder text is generic before unlock: "Un documento del tuo Scrigno scade tra 30 giorni".
  After unlock the "In scadenza" section shows kind + title.
- Expired documents stay in the vault with an "Scaduto" badge; the kind picker offers
  "Rinnovato → nuovo documento" which creates a fresh document linked by a `replaces` tag
  (`replaces:<old_id>`) and hides the old one from "In scadenza".

## Test fixtures

`crates/scrigno-index/tests/kinds.rs` must cover every row of the table, both age-band
branches for CIE/passaporto/patente, the 29 Feb case, `isee` on 1 Jan and 31 Dec, and the
`assumed_adult` flag.
