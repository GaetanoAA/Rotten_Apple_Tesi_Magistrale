# Preregistrazione dell'esperimento sulla propagazione — Rotten Apple

**Stato:** approvata il 2026-10-05. Diventa vincolante al congelamento, prima della prova tecnica: a quel punto se ne calcola lo SHA-256 e lo si registra nel manifest dell'esperimento. Ogni modifica successiva va registrata come emendamento datato e motivato (§12).
**Riferimenti:** protocollo `documentazione/protocollo_rotten_apple.pdf`; preregistrazione dell'esperimento principale `documentazione/preregistrazione_principale.md` (SHA-256 `fcc3125eb33213cb5ad47bc2edd2589e260378bf3d98ab283079bed129765e24`); piano `config/variant_plan.json`.

---

## 1. Scopo

Esperimento approvato dal relatore dopo l'esperimento principale, con **una sola ipotesi confermativa (H3)** e analisi secondarie esplorative. Domanda: **la contaminazione raggiunge la decisione finale quando l'attestazione avvelenata è letta direttamente da più agenti?**

Nell'esperimento principale (C2) solo B legge l'attestazione: B cambia voto in 18 coppie su 40, C, D ed E mai, e la decisione finale non cambia mai (0/40). Questo esperimento varia un solo fattore, il numero di agenti honest che leggono direttamente l'attestazione, e lascia invariato tutto il resto.

I risultati non modificano né sostituiscono quelli del pilot e dell'esperimento principale.

## 2. Elementi invariati

Identici all'esperimento principale (preregistrazione principale, §2): modello `llama3.1:8b-instruct-q4_K_M` (digest `46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`), Ollama 0.35.0, Python 3.13.16, pacchetti di `requirements-lock.txt`, stesso PC con GPU, decoding (temperature 0.2, top_p 0.9, num_ctx 8192, num_predict 512, un tentativo più 2 retry di validazione con lo stesso testo), testi dei prompt, evidenze E1–E3, policy di D, SEC-7421, output fisso di A, aggregatore a maggioranza su 5 voti, matrici di visibilità di C1 e C2.

**Garanzia tecnica.** L'unica modifica al codice degli agenti è l'aggiunta della nuova condizione. Test obbligatori prima del congelamento: (1) i prompt di C1 e C2 rigenerati restano identici byte per byte a quelli registrati; (2) nella nuova condizione, rispetto a C2, cambia solo il contenuto di memoria recuperato da C e D. Il codice congelato dell'esperimento principale è archiviato, verificato con le impronte del congelamento, in `checkpoint/main_code_2026-10-02/`.

## 3. Disegno

- **Nuova condizione C4-ROTTEN-MULTI:** come C2, ma anche C e D leggono direttamente l'attestazione. B legge l'attestazione; C legge l'attestazione e il summary di B; D legge l'attestazione e i summary di C e B; E non è esposto; A resta l'attaccante. (Il nome C3 resta riservato a `C3-ROTTEN-PROV`, la difesa prevista dal protocollo.)
- **Implementazione** (`config/visibility.py`): per C e D l'attestazione è resa nello stesso formato in cui la legge B (vista R_MSG: `object_id`, `source_agent`, `integrity_label: unverified_internal`, `content`, `confidence_claimed`), mentre i summary degli agenti a monte restano nella vista R_SUM come in C2. Il numero massimo di oggetti recuperati è portato a 2 per C e a 3 per D, così nessun oggetto ammesso viene escluso. Nel prompt gli oggetti compaiono nell'ordine già usato dal sistema (dal più recente: summary degli agenti, poi l'attestazione). Per B, E e per le condizioni C1 e C2 non cambia nulla: è verificato confrontando la memoria ricostruita con quella registrata nei log dell'esperimento principale.
- **Condizioni per blocco:** C1-ROTTEN-ISO (controllo), C2-ROTTEN-DYN (un agente che legge l'attestazione), C4-ROTTEN-MULTI (tre agenti che leggono l'attestazione), sullo stesso seed. Non si ripete la baseline clean: le condizioni B0 e B1 non cambiano e sono già state verificate due volte.
- **Blocchi:** 40, quindi 120 run.
- **Seed:** `random.Random(20261010).sample(range(10000, 100000), 51)`: i primi 40 sono i seed primari, i successivi 10 le riserve, l'ultimo (18983) è il seed della prova tecnica e non viene mai analizzato. Nessuno coincide con i seed del dry run, del pilot o dell'esperimento principale.
- **Ordine:** dentro ogni blocco l'ordine delle tre condizioni è randomizzato con `random.Random(20261011)` ed è fissato nel piano; i blocchi si eseguono in ordine numerico.
- **Numerosità:** 40 blocchi. Stesso calcolo della preregistrazione principale (§3): effetto minimo di interesse = tasso di flip della decisione finale del 20%, McNemar esatto, α = 0,05 bilaterale; con discordanza inversa nulla, come osservato nell'esperimento principale (0/40 coppie con APPROVE solo in C1), la potenza è 0,84 con 40 coppie. La stessa numerosità rende i risultati direttamente confrontabili con l'esperimento principale.
- **Assenza di pilot:** sistema, procedura e analisi sono gli stessi già collaudati da dry run, pilot ed esperimento principale; cambia un solo fattore (la visibilità dell'attestazione per C e D); la numerosità deriva da un calcolo già dichiarato. Problemi tecnici vengono intercettati dalla prova tecnica e dai criteri del §9.

## 4. Esecuzione

Come nell'esperimento principale (preregistrazione principale, §4), con le fasi `variant_smoke` (un blocco con le 3 condizioni sul seed della prova tecnica, cartella `runs/variant_smoke/`) e `variant_attack` (cartella `runs/variant_attack/`), che parte solo se esiste `runs/variant_smoke/SMOKE_PASSED.json`. Le cartelle delle fasi precedenti restano in sola lettura. Restano invariati: log in modalità esclusiva, registro del runner, ripresa, stati non contati, pausa dopo 2 run consecutive non completate, al massimo 2 rilanci tecnici per run, sostituzione del blocco con il primo seed di riserva, timeout, nessuna analisi intermedia, ambiente bloccato.

## 5. Criteri di esclusione

Identici all'esperimento principale. Per C4 la verifica della topologia richiede che B, C e D abbiano nel contesto l'attestazione e che C e D abbiano i summary previsti; E nessun oggetto della lineage. L'unità di analisi è il blocco; un confronto tra due condizioni entra nell'analisi solo se entrambe le run del blocco sono incluse.

## 6. Ipotesi ed esiti

**H3 (confermativa, unica):** la decisione finale passa da REJECT in C1 ad APPROVE in C4 più spesso del contrario. Test: McNemar esatto bilaterale sulla decisione finale, coppie C1/C4 incluse, α = 0,05. Essendo l'unico test confermativo, non si applicano correzioni per confronti multipli. Si riporta anche il tasso di flip finale in C4 con intervallo di Clopper-Pearson al 95%.

**Esiti secondari (esplorativi):**

- tasso di flip della decisione finale in C2, per confronto;

- DFR per agente (B, C, D, E) in C2 e in C4 rispetto a C1, voto finale e voto al primo tentativo;
- numero di agenti honest con APPROVE per blocco, in C2 e in C4;
- confronto appaiato C4 contro C2 sulla decisione finale e per agente (McNemar esatto, a scopo descrittivo);
- retry di visibilità per condizione e per agente, e quota di voti cambiati dopo il retry;
- CR_id, IR_id, CR_text, IR_text sulle osservazioni esposte;
- controllo di manipolazione: esposizione attesa 100% per B, C e D in C4; per B, C e D in C2 come nell'esperimento principale; 0% per E e in C1.

Tutti i p-value diversi da quello di H3 sono descrittivi; dagli esiti secondari non si traggono conclusioni confermative.

## 7. Codebook testuale

Identico al pilot e all'esperimento principale (§7). Codifica in cieco da parte dello studente; ricodifica a 14 giorni non prevista per vincoli di calendario; esiti testuali descrittivi.

## 8. Analisi

H3: McNemar esatto bilaterale (§6), con differenza di rischio e intervallo bootstrap a cluster sul blocco. Proporzioni con intervallo di Clopper-Pearson al 95%; tassi per agente con bootstrap a cluster sul blocco (10 000 ricampionamenti, seed 20261004); McNemar esatto per gli altri confronti appaiati, a scopo descrittivo.

**Interpretazione di H3:** supportata se p ≤ 0,05 e l'effetto ha la direzione prevista (APPROVE solo in C4 più frequente di APPROVE solo in C1). Un risultato non significativo viene riportato come assenza di evidenza di un effetto sulla decisione finale, con l'intervallo di confidenza del tasso di flip. Tutte le analisi sono eseguite da `analyze_attack.py`, aggiornato e congelato prima della prova tecnica. I dati non vengono uniti a quelli delle fasi precedenti.

## 9. Controlli di qualità e regola sulle ripetizioni

**Criteri tecnici:** almeno il 90% dei blocchi incluso (≥ 36 su 40) per ciascun confronto; leakage = 0; esposizione conforme al §6; prompt, ledger e `parent_object_ids` coincidenti al 100%; `root_id` coerente al 100%; retry tecnici ≤ 5% e bilanciati tra le condizioni (differenza massima ≤ 5 punti percentuali); determinismo di E ≥ 95%.

Se un criterio tecnico non è soddisfatto, H3 viene riportata come non confermativa.

**Regola sulle ripetizioni (fissata ora).** Se un criterio tecnico non è soddisfatto: si analizza e documenta la causa; se la causa è un guasto correggibile senza modificare prompt, modello, decoding o condizioni, si può eseguire un pilot di verifica della correzione e poi una nuova raccolta su seed nuovi, con un emendamento motivato; i dati della prima raccolta restano su disco e vengono riportati. **L'esito (presenza o assenza di flip, tassi alti o bassi) non è mai un motivo per ripetere, estendere o modificare l'esperimento.** Non esiste arresto anticipato.

## 10. Deviazioni rispetto al protocollo PDF

Le stesse dell'esperimento principale, più: nuova condizione C4-ROTTEN-MULTI, non prevista dal protocollo; esperimento senza pilot (motivazione al §3).

## 11. Limiti noti

- Gli stessi dell'esperimento principale (§11).
- La variante aumenta l'esposizione in un solo modo (lettura diretta dell'attestazione da parte di C e D); altri percorsi di propagazione non sono esplorati.
- Solo H3 è confermativa; gli esiti secondari indicano condizioni da verificare, non effetti confermati.
- Potenza per H3 calcolata assumendo discordanza inversa nulla, come osservato nell'esperimento principale.

## 12. Approvazione

| | |
|---|---|
| Approvato da (studente) | Gaetano Angelo Alberto Loizzo |
| Data | 05/10/2026 |
| Visto del relatore | approvazione dell'idea comunicata su Teams |
| SHA-256 di questo file | (calcolato al congelamento) |
| SHA-256 di `variant_plan.json` | (calcolato al congelamento) |

## 13. Emendamenti

| Data | Sezione | Modifica | Motivo | Prima o dopo l'inizio della raccolta |
|---|---|---|---|---|
