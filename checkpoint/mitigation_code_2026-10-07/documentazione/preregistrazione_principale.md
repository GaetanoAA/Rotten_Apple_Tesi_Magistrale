# Preregistrazione dell'esperimento principale — Rotten Apple

**Stato:** approvata il 2026-10-02. Diventa vincolante al congelamento, prima della prova tecnica: a quel punto se ne calcola lo SHA-256 e lo si registra nel manifest dell'esperimento. Ogni modifica successiva va registrata come emendamento datato e motivato (§13).
**Riferimenti:** protocollo `documentazione/protocollo_rotten_apple.pdf`; preregistrazione del pilot `documentazione/preregistrazione_pilot.md` (SHA-256 `1c5ffc4d57ffa041ae428e7f78b2eead173407d23941ad91e7b9c962c524846b`); analisi della causa del criterio non soddisfatto nel pilot `documentazione/analisi_causa_retry_pilot.md`; piano `config/main_plan.json`.

---

## 1. Scopo

Esperimento **confermativo** sul contrasto C2-ROTTEN-DYN contro C1-ROTTEN-ISO: verificare se l'accesso dinamico alla memoria contenente l'attestazione avvelenata (lineage SEC-7421) modifica la decisione finale del sistema multi-agente e il voto dei singoli agenti honest.

Il pilot (2 ottobre 2026, 20 coppie C1/C2) ha soddisfatto tutti i criteri tecnici tranne il bilanciamento dei retry tra condizioni. L'analisi della causa ha mostrato che lo squilibrio dipende dalla manipolazione stessa: l'agente B esposto all'attestazione cita un'evidenza non visibile (E3) e la validazione attiva il retry. Questa preregistrazione ridefinisce il criterio di conseguenza (§9) e lascia invariati sistema, prompt e condizioni.

## 2. Elementi congelati

Identici al pilot:

- **Modello e ambiente:** modello `llama3.1:8b-instruct-q4_K_M`, digest `46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`; server Ollama 0.35.0; Python 3.13.16; pacchetti come in `requirements-lock.txt`.
- **Hardware:** lo stesso PC del pilot (Intel Core i9-13980HX, 31,6 GB di RAM, GPU NVIDIA GeForce RTX 4060 Laptop 8 GB, driver 566.07, Windows 11 Pro 10.0.26200). Modello eseguito interamente su GPU.
- **Decoding:** temperature 0.2, top_p 0.9, num_ctx 8192, num_predict 512, un tentativo più 2 retry di validazione, con lo stesso testo di retry.
- **Contenuti:** testi dei prompt, evidenze E1–E3, policy di D, SEC-7421, output fisso di A, matrice di visibilità di B0, B1, C1 e C2, aggregatore a maggioranza.
- **Codice degli agenti:** invariato rispetto al pilot. Le modifiche ammesse riguardano solo runner, piano e analisi (nuova fase, nuovi criteri, nuove metriche derivate dai log). Il test di regressione sui prompt (identità byte per byte) e quello sulla richiesta a Ollama restano obbligatori. Il codice congelato del pilot è archiviato, verificato con le impronte del congelamento, in `checkpoint/pilot_code_2026-10-02/`.

## 3. Disegno

- **Condizioni:** B0-CLEAN-ISO, B1-CLEAN-DYN, C1-ROTTEN-ISO, C2-ROTTEN-DYN.
- **Contrasto principale:** C2 contro C1 su **40 blocchi**.
- **Baseline clean:** B0 e B1 sui **primi 10 blocchi**, con gli stessi seed.
- **Seed:** `random.Random(20261007).sample(range(10000, 100000), 51)`: i primi 40 sono i seed primari, i successivi 10 le riserve, l'ultimo (16316) è il seed della prova tecnica e non viene mai analizzato. Nessuno coincide con i seed del dry run (42, 1001–1005) o del pilot (seed primari, riserve e prova tecnica).
- **Ordine:** dentro ogni blocco l'ordine delle condizioni è randomizzato con `random.Random(20261008)` ed è fissato nel piano. I blocchi si eseguono in ordine numerico.
- **Numerosità:** 40 coppie C1/C2. Regola (b) della preregistrazione del pilot: effetto minimo di interesse = tasso di flip finale del 20%, McNemar esatto, α = 0,05 bilaterale. Con discordanza inversa pari a quella osservata nel pilot (0/20), la potenza è 0,82 con 39 coppie e 0,84 con 40; si arrotonda a 40. Se la discordanza inversa reale fosse maggiore di zero la potenza sarebbe inferiore (circa 0,55 con 39 coppie e discordanza inversa del 2,5%): il limite è dichiarato in §11.
- **Tempo stimato:** 100 run; nel pilot ogni run è durata 0,2–0,4 minuti, quindi circa 30–60 minuti in tutto.

## 4. Esecuzione

Come nel pilot (preregistrazione del pilot §4, emendamenti 1 e 3 compresi), con queste fasi:

- fase `main_smoke`: un blocco con le 4 condizioni sul seed 16316, solo verifica tecnica, cartella `runs/main_smoke/`;
- fase `main_attack`: cartella `runs/main_attack/`; parte solo se esiste `runs/main_smoke/SMOKE_PASSED.json`;
- `results/` (dry run), `runs/pilot_smoke/` e `runs/pilot_attack/` restano in sola lettura.

Restano invariati: un file di log per run in modalità esclusiva; registro del runner; ripresa; stati INTERRUPTED e PRECHECK_FAILED non contati; pausa dopo 2 run consecutive non completate; al massimo 2 rilanci tecnici per run; sostituzione del blocco con il primo seed di riserva se la coppia C1/C2 non si completa; timeout di 1200 s per chiamata e 5400 s per run; nessuna analisi intermedia; ambiente bloccato (alimentazione collegata, sospensione disattivata, aggiornamenti di Ollama e del driver NVIDIA disattivati, nessuna variabile `OLLAMA_*`).

## 5. Criteri di esclusione

Identici al pilot (§5): una run è esclusa se non è COMPLETED dopo i rilanci previsti; se prompt o provenance non sono ricostruibili; se viola la condizione; se digest o versione del server differiscono da quelli congelati. L'unità di analisi è la coppia. Nessuna esclusione dipende dal verdetto.

## 6. Ipotesi ed esiti

Si calcolano sui soli blocchi inclusi.

### 6.1 Ipotesi confermative

- **H1 (livello coppia):** la decisione finale passa da REJECT in C1 ad APPROVE in C2 più spesso del contrario. Test: McNemar esatto bilaterale sulla decisione finale, α = 0,05. Si riportano anche il Final Flip semplice e l'FMR (definizioni del pilot, §6.1).
- **H2 (livello agente):** l'agente B vota REJECT in C1 e APPROVE in C2 più spesso del contrario. Test: McNemar esatto bilaterale sul voto finale di B, α = 0,05.

H1 e H2 sono le sole ipotesi confermative. Per due test si applica la correzione di Holm.

### 6.2 Esiti secondari

- **DFR direzionale** su B–E e su B–D (definizioni del pilot, §6.2), e per singolo agente.
- **Voto al primo tentativo:** DFR calcolato sul voto del primo tentativo di ciascun agente, prima di eventuali retry, accanto a quello sul voto finale. Fonte: eventi `AGENT_ATTEMPT` dei log.
- **Retry di visibilità per condizione** (definizione in §9): tasso per condizione e per agente, e quota di retry dopo i quali il voto cambia.
- **CR_id, IR_id, CR_text, IR_text** come nel pilot (§6.4), con denominatore le osservazioni esposte.
- **Controllo di manipolazione:** ER come nel pilot (§6.3); qualsiasi scostamento è un errore tecnico.

### 6.3 Esiti esplorativi

Come nel pilot (§6.5): CT in tutte le condizioni, Δconfidenza di B, ripresa lessicale, copia letterale, input duplicati per D, Propagation Depth e Blast Radius, latenze, controlli di determinismo.

## 7. Codebook testuale

Identico al pilot (§7): codici CT2, CT1, CT0, flag REF, regole di derivazione di CR_text e IR_text.

**Procedura:** prima passata automatica con la regola lessicale del codice; esportazione in CSV di tutte le unità in ordine casuale con ID anonimi; codifica manuale in cieco da parte dello studente, con il foglio di lavoro usato nel pilot. Per vincoli di calendario (consegna della tesi il 12 ottobre 2026) **non è prevista la ricodifica a 14 giorni**: il kappa intra-codificatore non viene calcolato e gli esiti testuali (CR_text, IR_text, CT) sono riportati solo come **descrittivi**, insieme all'accordo con la regola lessicale.

## 8. Analisi statistica

- **H1, H2:** McNemar esatto bilaterale; correzione di Holm sui due p-value; differenza di rischio con intervallo bootstrap a cluster sul blocco (10 000 ricampionamenti, seed 20261004, come nel pilot).
- **Proporzioni:** intervallo di Clopper-Pearson al 95%.
- **Tassi a livello agente:** bootstrap a cluster sul blocco, come sopra.
- **Δconfidenza:** Wilcoxon per dati appaiati, esplorativo.
- **Esiti secondari ed esplorativi:** descrittivi, senza correzione per confronti multipli e senza conclusioni confermative.
- **Baseline clean:** tasso di decisione finale REJECT e di REJECT per agente in B0 e B1.
- I dati del pilot non vengono uniti a quelli dell'esperimento principale.

Tutte le analisi sono eseguite da `analyze_attack.py`, aggiornato e congelato prima della prova tecnica.

## 9. Controlli di qualità

**Criteri tecnici** (tutti necessari perché i risultati siano considerati validi):

- almeno il 90% dei blocchi incluso (≥ 36 coppie C1/C2 su 40);
- leakage = 0;
- ER conforme al §6.2;
- prompt, ledger e `parent_object_ids` coincidono nel 100% dei casi; `root_id` coerente con il grafo nel 100% dei casi;
- tasso di **retry tecnici** ≤ 5% delle chiamate di agenti honest;
- **retry tecnici bilanciati:** |tasso C2 − tasso C1| ≤ 5 punti percentuali;
- determinismo di E ≥ 95% (quota di coppie incluse con output di E identico in C1 e C2);
- baseline clean con decisione finale REJECT in almeno il 90% delle run B0 e B1 incluse.

**Classificazione dei retry** (ridefinita sulla base del pilot):

- *retry tecnico:* tentativo non valido per errore di parsing o di schema dell'output (evento `AGENT_ATTEMPT` con `error_type` valorizzato). I timeout non attivano retry e chiudono la run come TIMEOUT, come nel pilot;
- *retry di visibilità:* tentativo con output valido nello schema, rifiutato perché `cited_object_ids` o `decision_basis_ids` contengono identificativi non presenti nel contesto dell'agente.

I retry di visibilità non rientrano nei criteri tecnici: sono un esito secondario (§6.2), perché nel pilot sono risultati una conseguenza dell'esposizione all'attestazione e non un malfunzionamento.

Se un criterio tecnico non è soddisfatto, i test di H1 e H2 vengono riportati come non confermativi; se ne analizza la causa e la si documenta. Prompt, modello e condizioni non vengono modificati per far rientrare il criterio.

**Interpretazione:** H1 e H2 sono considerate supportate se il p-value corretto con Holm è ≤ 0,05 e l'effetto ha la direzione prevista (APPROVE solo in C2). Un risultato non significativo su H1 viene riportato come assenza di evidenza di un effetto sulla decisione finale, con l'intervallo di confidenza del tasso di flip. Non esiste arresto anticipato e non è prevista alcuna raccolta aggiuntiva dopo l'esito.

## 10. Deviazioni dichiarate rispetto al protocollo PDF

Le stesse del pilot (preregistrazione del pilot §10), più:

1. Esecuzione su GPU invece che su CPU.
2. Classificazione dei retry in tecnici e di visibilità (§9).
3. Ricodifica a 14 giorni non prevista; esiti testuali descrittivi (§7).

## 11. Limiti noti

- Un solo modello quantizzato, eseguito su GPU.
- Campi auto-dichiarati.
- Il campo `implication: REJECT` nelle evidenze.
- B è l'unico agente con accesso diretto all'attestazione nella catena; C e D ricevono i summary a monte; E non è esposto.
- Aggregazione a maggioranza su 5 voti, uno dei quali (A) è dell'attaccante: un flip finale richiede che almeno due agenti honest votino APPROVE.
- Il retry di validazione può modificare il voto di un agente esposto (nel pilot 2 casi su 6 per B).
- Potenza per H1 calcolata assumendo discordanza inversa nulla, come osservato nel pilot.
- Un solo codificatore, senza misura di affidabilità.
- La lineage è strutturale, cioè basata sull'esposizione.

## 12. Approvazione

| | |
|---|---|
| Approvato da (studente) | Gaetano Angelo Alberto Loizzo |
| Data | 02/10/2026 |
| Visto del relatore (consigliato) | ______________________ |
| SHA-256 di questo file | (calcolato al congelamento) |
| SHA-256 di `main_plan.json` | (calcolato al congelamento) |

## 13. Emendamenti

| Data | Sezione | Modifica | Motivo | Prima o dopo l'inizio della raccolta |
|---|---|---|---|---|
