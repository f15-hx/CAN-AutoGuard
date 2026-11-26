# CAN Guard

Simulation-based automotive CAN bus security system (BusMaster + C++ backend + web dashboard).

## Team
| Member | Role |
|---|---|
| M1 | Simulation lead (DBC, ECU nodes, forwarder, SignalValidator, Live traffic page) |
| M2 | Attack engineer (AttackerNode, AttackController, Logger, evaluate.py, Attack lab page) |
| M3 | Detection lead (CanFrame, IDetector, sources, RingBuffer, DbcParser, Whitelist, DetectionEngine, main) |
| M4 | Analytics and UI lead (RateMonitor, ReplayDetector, AlertManager, Server, dashboard) |

## Build
```
cmake -S . -B build
cmake --build build
```

## Rules
- One branch per task (`feature/<name>`), merge through pull requests, someone else reviews.
- Edit only the files you own. Every file starts with an `Owner:` comment.
- Frozen contract files: CanFrame.h, IDetector.h, DetectionResult.h, Alert.h, docs/api_contract.md, docs/alert_schema.json, docs/wire_format.md.
