# Jigsaw XDR+ OmniParser — Jigsaw-plus direction

Jigsaw is excellent at fast EVTX hunting with Sigma/custom rules, keyword/regex search, and JSON/XML/CSV output. Jigsaw keeps that offline-first idea, then adds analyst-facing visibility:

- live dashboard showing the exact hunting path and current artefact;
- parsed-event display even when no rule fires;
- attack-chain synthesis across execution, persistence, credential access, lateral movement, evasion, and cleanup;
- multi-format parsing: EVTX/EVT, XML, JSON/JSONL, CSV, TXT/LOG exports;
- live OS workflow that exports logs first, then hunts the artefacts offline;
- GUI plus CLI outputs: report, hits JSON, events JSON, CSV.

The goal is not just “one executable.” It is a defender workflow that understands how attacks unfold and shows what telemetry was hunted.
