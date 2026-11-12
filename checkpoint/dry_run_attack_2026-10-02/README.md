# Checkpoint `dry_run_attack_2026-10-02`

Congelamento del dry run C1/C2 **prima** di qualsiasi modifica per il pilot.

## Contenuto

| File | Ruolo |
|---|---|
| `MANIFEST.json` | SHA-256 e dimensione di 58 file del progetto, indice dei 28 log, valori attesi di analisi e audit, limiti noti al momento del congelamento |
| `verify_and_checkpoint.py` | Verifica, registra l'ambiente, esegue pytest, crea lo ZIP, mette i log in sola lettura |
| `audit_dry_run.py` | Audit indipendente (non importa codice del progetto) |
| `audit_report_expected.json` | Output atteso dell'audit |
| `analysis_frozen.{json,csv}`, `analysis_frozen_table.txt` | Output dello script di analisi congelato |

File generati dall'esecuzione: `environment/`, `pytest_output.txt`, `analysis_local_output.json`,
`audit_local_output.json`, `verification_report.json`, `MANIFEST.json.sha256`, `ZIP_SHA256.txt`.

## Regole dopo il checkpoint

- Non modificare, spostare o rinominare nulla in `results/`.
- Non eseguire più `experiment.py` (fase e seed sono scritti nel codice: contaminerebbe il dry run).
- `analyze_dry_run_attack.py` e `tests/test_dry_run_attack_logs.py` restano lo strumento storico del dry run.
- I log B0/B1 non hanno `phase`: la loro classificazione è in `MANIFEST.json -> run_index`.
