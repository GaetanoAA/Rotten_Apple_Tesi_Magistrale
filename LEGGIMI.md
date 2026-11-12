# Rotten Apple — materiali sperimentali (versione completa, 7 ottobre 2026)

Documento di sintesi dei risultati: inviato a parte. Questo archivio sostituisce tutte le versioni precedenti.

## Contenuto
- documentazione/: preregistrazioni di pilot, esperimento principale, propagazione, appendice, follow-up e delle due mitigazioni (la prima con l'emendamento 1); analisi della causa del criterio non soddisfatto nel pilot e dell'interruzione della prima raccolta della mitigazione; deviazioni; protocollo.
- config/: piani (seed, ordine delle condizioni) e congelamenti (impronte SHA-256 di tutti i file congelati) di tutte le fasi.
- analysis_outputs/: report JSON e riepiloghi delle analisi; i report piu' recenti di pilot, esperimento principale e propagazione includono la codifica manuale.
- coding/: per pilot, esperimento principale e propagazione, il foglio esportato, la codifica manuale compilata e la chiave. Appendice, follow-up e mitigazioni non prevedono codifica testuale.
- runs/: log grezzi di tutte le run, un file JSONL per run, con prompt, risposte grezze e tempi. runs/mitigation_attack contiene la prima raccolta della mitigazione, interrotta per guasto tecnico (11 run); runs/mitigation2_* e runs/mitigation3_* le due mitigazioni complete.
- results/: log del dry run.
- checkpoint/: checkpoint del dry run e codice congelato di ciascuna fase, verificato con le impronte del proprio congelamento.
- codice nella radice: i file registrati nel congelamento della seconda mitigazione (mitigation3).

## Impronte
- config/pilot_freeze.json: fc0a22d6fd1cff3b75066d63403995c18bf7e661bc1756f3b282a1c56042041a
- documentazione/preregistrazione_pilot.md: 1c5ffc4d57ffa041ae428e7f78b2eead173407d23941ad91e7b9c962c524846b
- config/main_freeze.json: 0121ef285e5e0015d1b068fffaa3841aeaa988131b4cf1b3c389fbcfdc270196
- documentazione/preregistrazione_principale.md: fcc3125eb33213cb5ad47bc2edd2589e260378bf3d98ab283079bed129765e24
- config/variant_freeze.json: 1276255538ccf76ae133698197cee581d17c53fa08e9c72e1a7d2b975f7ba0fa
- documentazione/preregistrazione_variante.md: 0b4f0dc32f1029d6aaf3b34b6a9719b1a8f2763f94182fffd89542a0a65c659d
- config/appendix_freeze.json: cb4d21e539e60fd7256026dbd574b9dccc9abc239cc1a3a37464b3a04d95bf2a
- documentazione/preregistrazione_appendice.md: 3d498338c931ae13d8795e6045a3abb623b777adc08149f25fb048f3265e8027
- config/followup_freeze.json: e01585e2ebcd45ba2dd0713e3751dffd144ad9f99c1c191e7e8f87eeed244ebe
- documentazione/preregistrazione_followup.md: 98df42f707ab5be7750950bfd276b6033ac892ef7687b219c4e5276acdc83b7d
- config/mitigation_freeze.json: 3e9b15d63d302e7326bef2b811c2eb325c4ce0aaa96718666bf3fc818be85da2
- config/mitigation2_freeze.json: db2d16d611595d35d653188214cbf2bf5f33c18c745b8062945cafff99967e05
- documentazione/preregistrazione_mitigazione.md: a5eb97fc869afa053e2b32b96dfcdbb321b145d740b10592bd6b446112e2ab50
- config/mitigation3_freeze.json: 26c4617d5b8595bb15d3886de0101c247d764884dd90916160c17836f0c9baa6
- documentazione/preregistrazione_mitigazione_v2.md: f87f90fc8c7befce5f29ccb74024a7f4cf20acca42b9e7cea45248f693de5145

## Riprodurre le analisi
    python analyze_attack.py analyze --phase pilot_attack --coding coding/pilot_attack/coding_round1_compilato.csv --coding-key coding/pilot_attack/coding_key_DO_NOT_OPEN.csv
    python analyze_attack.py analyze --phase main_attack --coding coding/main_attack/coding_round1_compilato.csv --coding-key coding/main_attack/coding_key_DO_NOT_OPEN.csv
    python analyze_attack.py analyze --phase variant_attack --coding coding/variant_attack/coding_round1_compilato.csv --coding-key coding/variant_attack/coding_key_DO_NOT_OPEN.csv
    python analyze_attack.py analyze --phase appendix_attack
    python analyze_attack.py analyze --phase followup_attack
    python analyze_attack.py analyze --phase mitigation2_attack
    python analyze_attack.py analyze --phase mitigation3_attack
(Python 3.13, solo libreria standard per l'analisi.)
