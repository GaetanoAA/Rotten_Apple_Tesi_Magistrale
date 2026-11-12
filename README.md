# Rotten Apple: dynamic context poisoning nei sistemi multi-agente LLM

Tesi di laurea magistrale in Sicurezza Informatica (LM-66) · Università degli Studi di Milano · A.A. 2025-2026<br>
Relatore: Prof. Ernesto Damiani · Correlatrice: Dott.ssa Lara Mauri · Autore: Gaetano Angelo Alberto Loizzo

**Tesi completa:** [`tesi/Tesi_Loizzo.pdf`](tesi/Tesi_Loizzo.pdf) · **Presentazione alla seduta di laurea:** [`tesi/Presentazione_Tesi_Loizzo.pdf`](tesi/Presentazione_Tesi_Loizzo.pdf) · **Protocollo:** [`documentazione/protocollo_rotten_apple.pdf`](documentazione/protocollo_rotten_apple.pdf)

[English version below](#english)

## L'esperimento

Un sistema di cinque agenti LLM, eseguiti in ordine fisso (A → B → C → D → E), deve decidere se installare una dipendenza software sintetica che in realtà è compromessa. La decisione finale la prende un aggregatore deterministico a maggioranza.

Uno dei cinque agenti, A, è controllato dall'attaccante. Non tocca gli altri agenti né il voto: scrive nella memoria condivisa una falsa attestazione di sicurezza (SEC-7421) e lascia che siano le regole di retrieval del sistema a recapitarla agli agenti onesti. La domanda è quando l'effetto resta confinato ai singoli agenti e quando arriva alla decisione collettiva.

Il lavoro segue un protocollo preregistrato, con coppie controfattuali di esecuzioni (stesso seed, con e senza esposizione all'attestazione) e un modello locale (`llama3.1:8b-instruct-q4_K_M` su Ollama). Ogni prompt si può ricostruire dai log.

## Risultati principali

1. **Il primo agente che legge l'attestazione cede, ma la decisione finale non cambia.** Nell'esperimento principale il voto di B passa ad APPROVE in 18 coppie su 40 (H2 supportata, p di Holm = 1,5·10⁻⁵), mentre la decisione finale non cambia mai (H1 non supportata).
2. **Nella configurazione di partenza la contaminazione non si propaga agli altri agenti.** C e D non votano mai APPROVE, nemmeno quando leggono direttamente l'attestazione o quando questa si presenta come verificata (H3 non supportata).
3. **Senza il campo `implication` nelle evidenze emerge una falsa maggioranza.** Nel follow-up la decisione finale diventa APPROVE in 6 blocchi su 40, con tre voti favorevoli derivati da un'unica radice informativa. L'effetto si ripresenta nelle raccolte successive, su seed nuovi.
4. **Le due difese root-aware testate amplificano l'attacco.** In quella configurazione la decisione finale diventa APPROVE in 40 blocchi su 40 con la difesa, contro 2 e 4 su 40 senza.

| Fase | Cartella | Run | Esito |
| --- | --- | --- | --- |
| Pilot | `pilot_attack` | 60 | Un criterio tecnico non soddisfatto: niente passaggio diretto all'esperimento principale, che ha una sua preregistrazione |
| Esperimento principale | `main_attack` | 100 | H1 non supportata (0/40), H2 supportata (18/40) |
| Propagazione | `variant_attack` | 120 | H3 non supportata: decisione finale invariata (0/40) anche quando B, C e D leggono l'attestazione |
| Appendice | `appendix_attack` | 120 | Esplorativa: attestazione presentata come verificata, decisione finale invariata (0/40) |
| Follow-up | `followup_attack` | 80 | Esplorativo, senza `implication`: falsa maggioranza in 6/40 blocchi |
| Prima mitigazione (P_root con provenance visibile) | `mitigation2_attack` | 120 | Decisione finale APPROVE in 40/40 blocchi con la difesa, 2/40 senza |
| Seconda mitigazione (collasso dei soli derivati concordi) | `mitigation3_attack` | 121 | Decisione finale APPROVE in 40/40 blocchi con la difesa, 4/40 senza (una run esclusa e rilanciata) |

In totale 721 run (720 analizzate). A queste si aggiungono 11 run di una prima raccolta della mitigazione interrotta per guasto tecnico (`runs/mitigation_attack`) e i 28 log del dry run (`results/`).

## Riprodurre le analisi

Con Python 3.13 e la sola libreria standard, i report si rigenerano dai log:

```bash
python analyze_attack.py analyze --phase pilot_attack --coding coding/pilot_attack/coding_round1_compilato.csv --coding-key coding/pilot_attack/coding_key_DO_NOT_OPEN.csv
python analyze_attack.py analyze --phase main_attack --coding coding/main_attack/coding_round1_compilato.csv --coding-key coding/main_attack/coding_key_DO_NOT_OPEN.csv
python analyze_attack.py analyze --phase variant_attack --coding coding/variant_attack/coding_round1_compilato.csv --coding-key coding/variant_attack/coding_key_DO_NOT_OPEN.csv
python analyze_attack.py analyze --phase appendix_attack
python analyze_attack.py analyze --phase followup_attack
python analyze_attack.py analyze --phase mitigation2_attack
python analyze_attack.py analyze --phase mitigation3_attack
```

I nuovi report vengono salvati in `analysis_outputs/<fase>/` accanto a quelli originali, senza sovrascriverli. Il codice nella radice è quello congelato per l'ultima fase. Per riprodurre byte per byte il riepilogo della prima mitigazione si usa lo script congelato per quella fase, in `checkpoint/mitigation2_code_2026-10-07/`: lo script più recente aggiunge una sola riga descrittiva.

Per rieseguire una raccolta servono Ollama 0.35.0, il modello `llama3.1:8b-instruct-q4_K_M` con il digest indicato nella tesi e i pacchetti di [`requirements-lock.txt`](requirements-lock.txt). Piani, seed e prompt sono identici, ma su hardware diverso il testo generato può cambiare. I 119 test automatici si eseguono con `python -m pytest`.

## Integrità dei materiali

Ogni fase è stata congelata prima della raccolta: `config/<fase>_freeze.json` contiene le impronte SHA-256 della preregistrazione, del piano dei seed e di ogni file di codice, e `checkpoint/<fase>_code_<data>/` conserva il codice congelato. Le impronte di congelamenti e preregistrazioni sono riportate anche in [`LEGGIMI.md`](LEGGIMI.md) e nell'appendice A della tesi.

I file sono pubblicati identici all'archivio consegnato al relatore. Il file `.gitattributes` impedisce a Git di convertire i fine riga, così le impronte restano verificabili dopo il download.

## Struttura del repository

| Percorso | Contenuto |
| --- | --- |
| `tesi/` | Tesi in PDF e presentazione alla seduta di laurea |
| `documentazione/` | Protocollo, preregistrazioni di tutte le fasi, analisi delle cause e deviazioni |
| `config/` | Piani (seed, ordine delle condizioni) e congelamenti di tutte le fasi |
| `agents/`, `core/`, `pilot/`, `run_pilot.py`, `run_single.py` | Sistema multi-agente (LangGraph) e runner degli esperimenti |
| `analyze_attack.py` | Analisi statistica, solo libreria standard |
| `runs/` | Log grezzi: un file JSONL per run, con prompt, risposte grezze e tempi |
| `analysis_outputs/` | Report JSON e riepiloghi delle analisi |
| `coding/` | Codifica manuale delle risposte per pilot, esperimento principale e propagazione |
| `checkpoint/` | Codice congelato di ogni fase e checkpoint del dry run |
| `results/` | Log del dry run |
| `tests/`, `tools/` | Test automatici e strumenti di congelamento e controllo |
| `LEGGIMI.md` | Nota dell'archivio consegnato al relatore |

## Come citare

```bibtex
@mastersthesis{loizzo2026rottenapple,
  author = {Loizzo, Gaetano Angelo Alberto},
  title  = {Dynamic context poisoning nei sistemi multi-agente LLM: analisi della propagazione e strategie di mitigazione},
  school = {Universit{\`a} degli Studi di Milano},
  type   = {Tesi di laurea magistrale},
  year   = {2026}
}
```

<a id="english"></a>
## English

**Rotten Apple** is the experimental part of my master's thesis in Computer Security (University of Milan, 2026). It studies dynamic context poisoning in a five-agent LLM system that decides, by deterministic majority vote, whether to install a compromised synthetic software dependency. One agent is controlled by the attacker and writes a fake security attestation into the shared memory; the attestation reaches the honest agents only through the system's retrieval rules.

The study follows a preregistered protocol with counterfactual pairs of runs and a local model (`llama3.1:8b-instruct-q4_K_M` on Ollama): 721 runs across seven collections. Main findings:

- the first agent that reads the attestation is systematically swayed, but the final decision does not change;
- in the baseline configuration the other agents never vote APPROVE, even when they read the attestation directly;
- removing a single explicit cue (the `implication` field) from the evidence produces a reproducible false majority;
- in that configuration, the two root-aware defenses tested made things worse: the final decision became APPROVE in 40 out of 40 blocks.

The full thesis and the slides are in [`tesi/`](tesi) (in Italian). All raw logs, analysis code and preregistrations are included, and the reports can be regenerated with Python 3.13 and the standard library only (commands above).
