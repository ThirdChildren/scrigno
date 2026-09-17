// Maps `AppError.code` (apps/mobile/src-tauri/src/error.rs) to an Italian, actionable message.
// Never show `AppError.message` to the user: it is the English, internal-log string by design
// (see `error.rs`'s module docs) — this file's fallback covers any code we have not mapped yet.
import type { AppError } from "../bindings/AppError";

const messages: Record<string, string> = {
  network_error: "Impossibile contattare il server. Controlla la connessione e riprova.",
  unauthorized: "Token di accesso non valido. Controlla le credenziali e riprova.",
  vault_locked: "Il vault è bloccato. Sbloccalo per continuare.",
  wrong_passphrase: "Passphrase errata. Riprova.",
  sync_contention: "Troppi conflitti durante la sincronizzazione. Riprova tra qualche minuto.",
  server_rollback:
    "Il server ha restituito dati più vecchi del previsto. Controlla la sincronizzazione.",
  storage_error: "Errore di lettura o scrittura locale. Riprova.",
  crypto_error: "Errore di decifratura. Il file potrebbe essere danneggiato.",
  vault_exists: "Esiste già un vault su questo server. Prova a unirti invece di crearne uno.",
  vault_not_initialised: "Nessun vault trovato su questo server. Creane uno prima di unirti.",
  not_found: "Documento non trovato.",
  invalid_input: "Dati non validi. Controlla i campi e riprova.",
  server_contract_error: "Risposta del server inattesa. Riprova più tardi.",
  quick_unlock_unavailable: "Lo sblocco rapido non è disponibile su questo dispositivo.",
  quick_unlock_reauth_required:
    "Lo sblocco rapido è scaduto. Inserisci la passphrase per continuare.",
  biometric_failed: "Verifica dell'impronta o del volto non riuscita. Riprova.",
  already_unlocked: "Il vault è già sbloccato.",
  no_saved_credentials:
    "Nessuna credenziale salvata su questo dispositivo. Configura di nuovo il vault.",
  config_error: "Impossibile salvare la configurazione locale. Riprova.",
  io_error: "Impossibile leggere il file selezionato.",
  invalid_request: "Richiesta non valida.",
  not_implemented: "Questa funzione non è ancora disponibile.",
  internal_error: "Errore interno. Riavvia l'app e riprova.",
};

const fallback = "Si è verificato un errore imprevisto. Riprova.";

/** Resolves any value that might be an `AppError` (or came out of a catch block) to Italian. */
export function errorMessage(err: unknown): string {
  if (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof (err as AppError).code === "string"
  ) {
    return messages[(err as AppError).code] ?? fallback;
  }
  return fallback;
}
