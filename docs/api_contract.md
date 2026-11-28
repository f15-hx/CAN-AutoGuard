# api_contract.md

Owner: M4 | (contract) REST + WebSocket formats | Status: DRAFT v0.1 (needs M1, M2, M3 review, then freeze)

This file is the agreement between the C++ backend (`Server.cpp`, `routes/`) and the dashboard (`frontend/js/api.js`, `socket.js`). `tools/mock_server.py` implements the same contract so the dashboard can be built before the backend is finished. If this file and the code disagree, the code is wrong.

## 1. General rules

| Item | Value |
|---|---|
| Base URL | `http://localhost:8080` |
| REST prefix | `/api` |
| WebSocket | `ws://localhost:8080/ws` |
| Format | JSON, UTF-8, `Content-Type: application/json` |
| Time | Microseconds since the start of the run, field names end in `Us` (same clock as `wire_format.md`) |
| CAN ID | Integer in `id` / `canId` fields (e.g. `580`), plus a display string in `idHex` (e.g. `"0x244"`) |
| Payload | `data` is an uppercase hex string without spaces, 0 to 16 chars (e.g. `"2319000000000000"`) |
| Field names | camelCase |
| CORS | Backend sends `Access-Control-Allow-Origin: *` (development only) |
| Static files | Backend serves `frontend/` at `/` |

### Enums

| Name | Values |
|---|---|
| `severity` | `low`, `medium`, `high`, `critical` |
| `detector` | `Whitelist`, `SignalValidator`, `RateMonitor`, `ReplayDetector` |
| `category` | `spoofing`, `replay`, `flood`, `fuzzing`, `unknown` |
| `rule` | `unknown_id`, `invalid_dlc`, `signal_range`, `signal_rate_of_change`, `period_violation`, `frame_rate`, `bus_load`, `duplicate_payload`, `counter_regression` |
| `mode` | `live` (frames from BusMaster over UDP), `replay` (frames from a log file) |
| `scenario` | `spoofing`, `replay`, `flood`, `fuzzing` |

### Errors

Every error uses the matching HTTP status and this body:

```json
{ "error": { "code": "bad_request", "message": "limit must be between 1 and 1000" } }
```

Codes: `bad_request` (400), `not_found` (404), `conflict` (409, e.g. attack already running), `internal` (500).

### Paging

List endpoints accept `limit` (default 100, max 1000) and `offset` (default 0). They return:

```json
{ "items": [ ... ], "total": 482, "limit": 100, "offset": 0 }
```

Lists are sorted newest first.

---

## 2. Data objects

### Frame

```json
{
  "seq": 1042,
  "timestampUs": 11749000,
  "id": 580,
  "idHex": "0x244",
  "dlc": 8,
  "data": "2312000000000001",
  "name": "Speed",
  "flagged": true,
  "alertIds": [17]
}
```

`name` comes from the DBC (`null` for unknown IDs). `flagged` is true when at least one alert references this frame. `seq` is a unique, increasing frame number.

### Alert

Must match `docs/alert_schema.json` and `Alert.h`.

```json
{
  "id": 17,
  "timestampUs": 11749000,
  "severity": "high",
  "category": "spoofing",
  "detector": "SignalValidator",
  "rule": "signal_range",
  "canId": 580,
  "idHex": "0x244",
  "frameSeq": 1042,
  "message": "Speed 255 km/h is outside the allowed range 0-250",
  "details": { "signal": "VehicleSpeed", "value": 255, "min": 0, "max": 250 },
  "acknowledged": false
}
```

`details` is a free-form object that depends on the rule (never required by the dashboard to render the table). `frameSeq` may be `null` for alerts that are not tied to one frame (e.g. `bus_load`).

### Ecu

```json
{ "name": "BrakeECU", "ids": [416], "status": "ok", "framesPerSec": 100.0, "lastSeenUs": 11749000, "alertCount": 0 }
```

`status`: `ok`, `warning`, `offline`.

### AttackRun

```json
{
  "runId": 3,
  "scenario": "flood",
  "targetId": 0,
  "params": { "rate": 4000, "duration": 5 },
  "startUs": 20000000,
  "endUs": 25000000,
  "state": "finished",
  "result": { "detected": true, "latencyMs": 12.4, "alertCount": 311, "falsePositives": 0 }
}
```

`state`: `running`, `finished`, `stopped`, `failed`. `result` is `null` until the run is finished.

---

## 3. REST endpoints

### System

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | `{ "ok": true }` |
| GET | `/api/status` | Current state of the backend (below) |
| PUT | `/api/mode` | Switch source. Body: `{ "mode": "replay", "file": "attack_spoof.log" }` (`file` only for replay). Returns the new status |

`GET /api/status` response:

```json
{
  "mode": "live",
  "source": "udp://0.0.0.0:5005",
  "running": true,
  "uptimeSec": 312.4,
  "framesTotal": 48210,
  "alertsTotal": 17,
  "version": "0.1"
}
```

### Frames

| Method | Path | Query | Description |
|---|---|---|---|
| GET | `/api/frames` | `limit`, `offset`, `id`, `flagged` (true/false), `sinceUs` | Recent frames from the ring buffer |
| GET | `/api/frames/{seq}` | | One frame, with its alerts embedded as `alerts: [Alert]` |

Only the most recent frames are kept (ring buffer), so old `seq` values return `not_found`.

### Alerts

| Method | Path | Query | Description |
|---|---|---|---|
| GET | `/api/alerts` | `limit`, `offset`, `severity`, `category`, `detector`, `canId`, `sinceUs` | Filtered alert list |
| GET | `/api/alerts/{id}` | | One alert, with the triggering frame embedded as `frame` |
| POST | `/api/alerts/{id}/ack` | | Mark as acknowledged. Returns the alert |
| POST | `/api/alerts/clear` | | Delete all alerts from memory (log files stay). Returns `{ "cleared": 17 }` |

### Statistics

| Method | Path | Description |
|---|---|---|
| GET | `/api/stats` | Summary for the Overview page |
| GET | `/api/stats/timeseries` | Per-second history for charts. Query: `windowSec` (default 60, max 600) |
| GET | `/api/stats/ids` | Frame rate and expected period per CAN ID |
| GET | `/api/ecus` | `{ "items": [Ecu] }` for the ECU health grid |

`GET /api/stats`:

```json
{
  "framesTotal": 48210,
  "framesPerSec": 640.0,
  "busLoadPct": 23.5,
  "alertsTotal": 17,
  "alertsBySeverity": { "low": 2, "medium": 5, "high": 8, "critical": 2 },
  "alertsByCategory": { "spoofing": 6, "replay": 3, "flood": 7, "fuzzing": 1, "unknown": 0 },
  "alertsByDetector": { "Whitelist": 4, "SignalValidator": 6, "RateMonitor": 5, "ReplayDetector": 2 },
  "topIds": [ { "id": 580, "idHex": "0x244", "count": 9000 } ]
}
```

`GET /api/stats/timeseries`:

```json
{
  "bucketSec": 1,
  "points": [ { "tUs": 11000000, "frames": 640, "busLoadPct": 23.5, "alerts": 0 } ]
}
```

`GET /api/stats/ids`:

```json
{ "items": [ { "id": 580, "idHex": "0x244", "name": "Speed", "framesPerSec": 100.2, "expectedPeriodMs": 10, "lastPeriodMs": 9.8 } ] }
```

### Settings

| Method | Path | Description |
|---|---|---|
| GET | `/api/settings/thresholds` | Current thresholds (mirrors `config/thresholds.json`) |
| PUT | `/api/settings/thresholds` | Replace thresholds. Returns the saved object |
| GET | `/api/settings/whitelist` | Allowed IDs (mirrors `config/whitelist.json`) |
| PUT | `/api/settings/whitelist` | Replace whitelist. Returns the saved object |

Thresholds object:

```json
{
  "rate": { "periodTolerancePct": 30, "floodFramesPerSec": 1500, "busLoadWarnPct": 70 },
  "replay": { "hashWindowFrames": 2000, "counterCheck": true },
  "signal": { "maxRateOfChangePerSec": 80 }
}
```

Whitelist object:

```json
{ "ids": [ { "id": 580, "idHex": "0x244", "name": "Speed", "dlc": 8, "periodMs": 10 } ] }
```

Validation errors return `bad_request` and nothing is saved.

### Attack lab (M2)

| Method | Path | Description |
|---|---|---|
| GET | `/api/attack/scenarios` | Available scenarios with default parameters |
| POST | `/api/attack/start` | Start a run. Body: `{ "scenario": "spoofing", "params": { "targetId": 580, "fakeValue": 255, "rate": 100, "duration": 5 } }`. Returns the `AttackRun`. `conflict` if one is already running |
| POST | `/api/attack/stop` | Stop the current run. Returns the `AttackRun` |
| GET | `/api/attack/status` | Current `AttackRun` or `null` |
| GET | `/api/attack/runs` | `{ "items": [AttackRun] }`, newest first |

Parameters per scenario (from `attack_scenarios.md`):

| Scenario | Params | Defaults |
|---|---|---|
| `spoofing` | `targetId`, `fakeValue`, `rate`, `duration` | 580 (0x244), 255, 100, 5 |
| `replay` | `targetId`, `recordWindow`, `delay` | 416 (0x1A0), 2, 5 |
| `flood` | `rate`, `duration` | 4000, 5 |
| `fuzzing` | `rate`, `duration`, `seed` | 200, 5, 1 |

---

## 4. WebSocket

Connect to `ws://localhost:8080/ws`. The server sends JSON text messages only; the client sends nothing (ping/pong handled by the library). Every message has the same envelope:

```json
{ "type": "alert", "tUs": 11749000, "data": { ... } }
```

| `type` | `data` | When |
|---|---|---|
| `hello` | `Status` object (same as `GET /api/status`) | Right after connecting |
| `frames` | `{ "items": [Frame] }` | Batched, at most 10 messages per second, so the browser is not flooded during a DoS |
| `alert` | `Alert` | Immediately for each new alert |
| `stats` | Same shape as `GET /api/stats` plus `ecus: [Ecu]` | Once per second |
| `attack` | `AttackRun` | On every state change of an attack run |
| `mode` | `Status` object | After a mode change |

Rules for the client (`socket.js`):
- Reconnect automatically with a 1 s delay, growing to a maximum of 5 s.
- After reconnecting, reload data with the REST endpoints (messages sent while disconnected are lost).
- Ignore unknown `type` values so new message types do not break old dashboards.

---

## 5. Change rules

1. This file is frozen once M1, M2 and M3 approve it.
2. Adding a new optional field or endpoint is allowed without a new version; tell the team.
3. Renaming or removing a field, or changing a type, needs agreement from everyone and a version bump.
4. `tools/mock_server.py` is updated in the same pull request as any change here.
