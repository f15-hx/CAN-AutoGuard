# attack_scenarios.md

Owner: M2 | Attacks and expected symptoms | Status:  DRAFT. IDs and numbers are placeholders until M1 finalizes `vehicle.dbc`.

Threat model: An attacker has gained access to the CAN bus (for example through a compromised infotainment unit or an OBD-II dongle). CAN has no sender authentication system therefore, any node can send any ID.

## Common test setup
- Bus: BusMaster virtual (Simulation driver). Normal traffic from the ECU nodes runs for at least 10 s before each attack.
- Each run writes one line to `busmaster/logs/attack_events.csv`: `scenario,targetId,startUs,endUs`.
- Each attack is recorded to `busmaster/logs/attack_<name>.log` in the wire format `timestampUs,id,dlc,hexbytes`.

---

## 1. Spoofing
| Item | Description |
|---|---|
| Goal | Make a receiver believe a false value (e.g. vehicle speed) |
| Target ID | 0x244 (Speed) |
| Method | Send frames with the real ID and a false value, interleaved with the real sender's frames |
| Parameters | targetId, fakeValue (default 255 km/h), rate (frames/s), duration (s) |
| Expected symptom | Dashboard ECU shows the wrong speed; frame rate on 0x244 doubles; value jumps |
| Should be caught by | SignalValidator (range, rate of change), RateMonitor (period violation) |
| Success criterion | Alert raised within 100 ms of the first fake frame |

## 2. Replay
| Item | Description |
|---|---|
| Goal | Repeat a legitimate command or status from the past |
| Target ID | 0x1A0 (Brake) |
| Method | Record 2 s of valid frames, then resend them unchanged later (same payloads, same counters) |
| Parameters | targetId, recordWindow (s), delay (s) |
| Expected symptom | Duplicate payloads and rolling counters that jump backwards |
| Should be caught by | ReplayDetector (payload hash, counter), RateMonitor (period) |
| Success criterion | Alert raised within 200 ms of the first replayed frame |

## 3. Denial of service (flood)
| Item | Description |
|---|---|
| Goal | Saturate the bus so real frames are delayed or lost |
| Target ID | 0x000 (wins arbitration against every other ID) |
| Method | Send frames back to back at the maximum possible rate |
| Parameters | rate (frames/s, default 4000), duration (s) |
| Expected symptom | Bus load rises sharply; real ECU frames arrive late or not at all |
| Should be caught by | RateMonitor (frames per second, bus load), Whitelist (0x000 not allowed) |
| Success criterion | Alert raised within 50 ms; load graph shows the attack window |

## 4. Fuzzing
| Item | Description |
|---|---|
| Goal | Find unexpected behaviour by sending random input |
| Target ID | Random IDs (log marks it as 0xFFFF) |
| Method | Random IDs, random payloads, occasionally invalid lengths |
| Parameters | rate (frames/s, default 200), duration (s), seed |
| Expected symptom | Many IDs not in the vehicle's message list |
| Should be caught by | Whitelist (unknown ID, wrong DLC) |
| Success criterion | Every unknown-ID frame flagged |

---

## Test matrix (fill in during testing)
| Scenario | Runs | Detected | Missed | Median latency (ms) | False positives on normal traffic |
|---|---|---|---|---|---|
| Spoofing | | | | | |
| Replay | | | | | |
| Flood | | | | | |
| Fuzzing | | | | | |
