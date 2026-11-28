import argparse
import bisect
import csv
import json
import os
import queue
import threading
import time
from collections import Counter, deque

from flask import Flask, jsonify, request, send_from_directory

try:
    from flask_sock import Sock
except ImportError:  # REST still works, WebSocket does not
    Sock = None

VERSION = "0.1-mock"
BUS_BITRATE = 500_000          # bits/s, used for the bus load estimate
ALERT_COOLDOWN_US = 250_000    # same alert (rule + id) inside this window is merged, repeatCount counts them
TICK_S = 0.05                  # engine step (real time)
FRAME_BATCH_MAX = 100          # max frames per WebSocket "frames" message
FRAME_RING = 5000              # frames kept for GET /api/frames
ALERT_CAP = 20000
LEAD_IN_US = 2_000_000         # attack runs start this long before the attack window

SEVERITIES = ["low", "medium", "high", "critical"]
DETECTORS = ["Whitelist", "SignalValidator", "RateMonitor", "ReplayDetector"]
CATEGORIES = ["spoofing", "replay", "flood", "fuzzing", "unknown"]
RULES = ["unknown_id", "invalid_dlc", "signal_range", "signal_rate_of_change", "period_violation",
         "frame_rate", "bus_load", "duplicate_payload", "counter_regression"]
SCENARIOS = ["spoofing", "replay", "flood", "fuzzing"]
LOG_OF = {"spoofing": "attack_spoof.log", "replay": "attack_replay.log",
          "flood": "attack_flood.log", "fuzzing": "attack_fuzz.log"}
EVENT_OF = {"spoofing": "spoof", "replay": "replay", "flood": "flood", "fuzzing": "fuzz"}

# Placeholders until M1 finalizes vehicle.dbc (same values as tools/generate_attack_logs.py)
DEFAULT_WHITELIST = [
    {"id": 0x244, "name": "Speed", "dlc": 8, "periodMs": 10},
    {"id": 0x2C0, "name": "Engine", "dlc": 8, "periodMs": 20},
    {"id": 0x1A0, "name": "Brake", "dlc": 8, "periodMs": 20},
    {"id": 0x3B0, "name": "Door", "dlc": 8, "periodMs": 100},
    {"id": 0x4F0, "name": "Dashboard", "dlc": 8, "periodMs": 50},
]
ECUS = [("SpeedSensorECU", [0x244]), ("EngineECU", [0x2C0]), ("BrakeECU", [0x1A0]),
        ("DoorECU", [0x3B0]), ("DashboardECU", [0x4F0])]

DEFAULT_THRESHOLDS = {
    "rate": {"periodTolerancePct": 30, "floodFramesPerSec": 1500, "busLoadWarnPct": 70},
    "replay": {"hashWindowFrames": 2000, "counterCheck": True},
    "signal": {"maxRateOfChangePerSec": 80},
}
THRESHOLD_LIMITS = {
    ("rate", "periodTolerancePct"): (1, 99), ("rate", "floodFramesPerSec"): (1, 100000),
    ("rate", "busLoadWarnPct"): (1, 100), ("replay", "hashWindowFrames"): (10, 100000),
    ("signal", "maxRateOfChangePerSec"): (1, 10000),
}
# Speed signal (0x244): bytes 0-1 big endian, 0.01 km/h per bit, valid 0..250 km/h
SPEED_ID, SPEED_SCALE, SPEED_MAX = 0x244, 0.01, 250.0

ATTACK_DEFAULTS = {
    "spoofing": {"targetId": 0x244, "fakeValue": 255, "rate": 100, "duration": 5},
    "replay": {"targetId": 0x1A0, "recordWindow": 2, "delay": 5},
    "flood": {"rate": 4000, "duration": 5},
    "fuzzing": {"rate": 200, "duration": 5, "seed": 1},
}


# ------------------------------------------------------------------ errors / helpers
class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def bad(msg):
    return ApiError(400, "bad_request", msg)


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def parse_id(v):
    try:
        cid = int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        raise bad(f"invalid CAN id: {v!r}")
    if not 0 <= cid <= 0x7FF:
        raise bad(f"CAN id out of range (0..0x7FF): {v!r}")
    return cid


def hexid(cid):
    return None if cid is None else f"0x{cid:X}"


def qint(name, default, lo, hi):
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        raise bad(f"{name} must be an integer")
    if not lo <= val <= hi:
        raise bad(f"{name} must be between {lo} and {hi}")
    return val


def qbool(name):
    raw = request.args.get(name)
    if raw is None:
        return None
    if raw.lower() in ("true", "1"):
        return True
    if raw.lower() in ("false", "0"):
        return False
    raise bad(f"{name} must be true or false")


def page(items):
    limit = qint("limit", 100, 1, 1000)
    offset = qint("offset", 0, 0, 10**9)
    return {"items": items[offset:offset + limit], "total": len(items), "limit": limit, "offset": offset}


def body_json():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise bad("body must be a JSON object")
    return data


def load_log(path):
    """Wire format: timestampUs,id,dlc,hexbytes  ->  list of (ts, id, dlc, HEX)"""
    frames = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            try:
                frames.append((int(parts[0]), int(parts[1], 0), int(parts[2]), parts[3].strip().upper()))
            except ValueError:
                continue
    frames.sort(key=lambda f: f[0])
    return frames


def load_events(logdir):
    events = {}
    path = os.path.join(logdir, "attack_events.csv")
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    events[row["scenario"]] = {"targetId": int(row["targetId"], 0),
                                               "startUs": int(row["startUs"]), "endUs": int(row["endUs"])}
                except (KeyError, ValueError):
                    continue
    return events


def validate_thresholds(body):
    out = {}
    if set(body) != set(DEFAULT_THRESHOLDS):
        raise bad(f"thresholds must have exactly the groups {sorted(DEFAULT_THRESHOLDS)}")
    for group, keys in DEFAULT_THRESHOLDS.items():
        sub = body[group]
        if not isinstance(sub, dict) or set(sub) != set(keys):
            raise bad(f"{group} must have exactly the keys {sorted(keys)}")
        out[group] = {}
        for key, default in keys.items():
            val = sub[key]
            if isinstance(default, bool):
                if not isinstance(val, bool):
                    raise bad(f"{group}.{key} must be true or false")
            else:
                lo, hi = THRESHOLD_LIMITS[(group, key)]
                if not is_num(val) or not lo <= val <= hi:
                    raise bad(f"{group}.{key} must be a number between {lo} and {hi}")
            out[group][key] = val
    return out


def validate_whitelist(body):
    ids = body.get("ids")
    if set(body) != {"ids"} or not isinstance(ids, list):
        raise bad('whitelist must be {"ids": [ ... ]}')
    out = {}
    for i, e in enumerate(ids):
        if not isinstance(e, dict):
            raise bad(f"ids[{i}] must be an object")
        raw = e.get("id", e.get("idHex"))
        if raw is None:
            raise bad(f"ids[{i}] needs id or idHex")
        cid = parse_id(raw)
        if cid in out:
            raise bad(f"duplicate id {hexid(cid)}")
        name, dlc, period = e.get("name"), e.get("dlc", 8), e.get("periodMs")
        if not isinstance(name, str) or not name:
            raise bad(f"ids[{i}].name must be a non-empty string")
        if isinstance(dlc, bool) or not isinstance(dlc, int) or not 0 <= dlc <= 8:
            raise bad(f"ids[{i}].dlc must be an integer 0..8")
        if period is not None and (not is_num(period) or period <= 0):
            raise bad(f"ids[{i}].periodMs must be a positive number or null")
        out[cid] = {"id": cid, "idHex": hexid(cid), "name": name, "dlc": dlc, "periodMs": period}
    return out


# ------------------------------------------------------------------ engine
class Engine:
    def __init__(self, logdir, speed, config_dir):
        self.logdir, self.speed = logdir, speed
        self.lock = threading.RLock()
        self.clients = set()
        self.events = load_events(logdir)
        self._logs = {}
        self.started = time.monotonic()

        self.th = json.loads(json.dumps(DEFAULT_THRESHOLDS))
        self.whitelist = {e["id"]: dict(e, idHex=hexid(e["id"])) for e in DEFAULT_WHITELIST}
        self._load_config(config_dir)

        self.mode, self.file = "live", "normal_traffic.log"
        self.frames_src, self.ts_list = [], []
        self.base, self.pos, self.idx = 0, 0, 0
        self.next_seq, self.next_alert, self.next_run = 1, 1, 1
        self.frames = deque(maxlen=FRAME_RING)
        self.alerts = []
        self.frames_total = 0
        self.id_counts = Counter()
        self.by_sev, self.by_cat, self.by_det = Counter(), Counter(), Counter()
        self.series = {}           # second -> {"frames", "bits", "alerts"}
        self.runs, self.run, self.run_meta = [], None, {}
        self.pending_frames, self.pending_alerts, self.pending_msgs = [], [], []
        self._last_stats_push = 0.0
        self._reset_detectors()
        self._switch(self.file, 0)

    # ---- config
    def _load_config(self, config_dir):
        for name in ("thresholds.json", "whitelist.json"):
            path = os.path.join(config_dir, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                if not data:
                    continue
                if name == "thresholds.json":
                    self.th = validate_thresholds(data)
                else:
                    self.whitelist = validate_whitelist(data)
            except (OSError, ValueError, ApiError) as exc:
                print(f"[mock] ignoring {name}: {exc}")

    def _reset_detectors(self):
        self.win = {}              # id -> deque of timestamps (last 1 s)
        self.last_ts, self.last_period = {}, {}
        self.gwin, self.bits_sum = deque(), 0
        self.last_range_viol = {}
        self.last_val = {}         # id -> (ts, value)
        self.seen = {}             # id -> {payload: ts}
        self.order = {}            # id -> deque[(ts, payload)]
        self.last_counter = {}
        self.cool = {}             # cooldown key -> last alert
        self.last_seen = {}        # id -> ts (for ECU status)
        self.recent_alert_ts = {}  # id -> ts of last alert

    # ---- source handling
    def _switch(self, fname, start_pos):
        path = os.path.join(self.logdir, fname)
        if fname not in self._logs:
            self._logs[fname] = load_log(path)
        now = self.sim_now()
        self.frames_src = self._logs[fname]
        self.ts_list = [f[0] for f in self.frames_src]
        self.file = fname
        self.pos = start_pos
        self.base = now - int(start_pos)
        self.idx = bisect.bisect_left(self.ts_list, start_pos)
        self._reset_detectors()

    def sim_now(self):
        return int(self.base + self.pos)

    # ---- main loop
    def run_forever(self):
        last = time.monotonic()
        while True:
            time.sleep(TICK_S)
            cur = time.monotonic()
            dt, last = cur - last, cur
            with self.lock:
                self._advance(dt * self.speed * 1_000_000)
                self._finish_run_if_done()
                self._flush(cur)

    def _advance(self, dpos):
        self.pos += dpos
        src, ts_list = self.frames_src, self.ts_list
        while self.idx < len(src) and ts_list[self.idx] <= self.pos:
            ts, cid, dlc, data = src[self.idx]
            self.idx += 1
            self._process(ts, cid, dlc, data)
        if src and self.idx >= len(src) and self.pos >= ts_list[-1] + 100_000:
            self.base += int(self.pos)     # loop: the clock keeps counting up
            self.pos, self.idx = 0, 0
            self._reset_detectors()

    # ---- frame pipeline
    def _process(self, ts, cid, dlc, data):
        now = self.base + ts
        wl = self.whitelist.get(cid)
        f = {"seq": self.next_seq, "timestampUs": now, "id": cid, "idHex": hexid(cid), "dlc": dlc,
             "data": data, "name": wl["name"] if wl else None, "flagged": False, "alertIds": []}
        self.next_seq += 1
        self.frames.append(f)
        self.pending_frames.append(f)
        self.frames_total += 1
        self.id_counts[cid] += 1
        bits = 47 + 8 * dlc
        sec = self.series.setdefault(now // 1_000_000, {"frames": 0, "bits": 0, "alerts": 0})
        sec["frames"] += 1
        sec["bits"] += bits
        self.last_seen[cid] = now
        self._detect(f, now, wl, bits)

    def _detect(self, f, now, wl, bits):
        cid, dlc, data, th = f["id"], f["dlc"], f["data"], self.th

        # Whitelist (M3)
        if wl is None:
            self._emit(f, now, "high" if cid == 0 else "medium", "flood" if cid == 0 else "fuzzing",
                       "Whitelist", "unknown_id", f"CAN ID 0x{cid:X} is not in the whitelist",
                       {"dlc": dlc}, key=("unknown_id",))
        elif dlc != wl["dlc"] or len(data) != dlc * 2:
            self._emit(f, now, "medium", "fuzzing", "Whitelist", "invalid_dlc",
                       f"0x{cid:X} ({wl['name']}) has DLC {dlc}, expected {wl['dlc']}",
                       {"dlc": dlc, "expectedDlc": wl["dlc"], "payloadBytes": len(data) // 2},
                       key=("invalid_dlc",))

        # RateMonitor (M4)
        win = self.win.setdefault(cid, deque())
        win.append(now)
        while win and win[0] < now - 1_000_000:
            win.popleft()
        prev = self.last_ts.get(cid)
        interval = None if prev is None else now - prev
        self.last_ts[cid] = now
        if interval is not None:
            self.last_period[cid] = interval / 1000.0
        period_us = wl["periodMs"] * 1000 if wl and wl.get("periodMs") else None
        extra_frame = False
        if period_us and interval is not None:
            limit = period_us * (1 - th["rate"]["periodTolerancePct"] / 100.0)
            if interval < limit:
                extra_frame = True
                self._emit(f, now, "medium", "spoofing", "RateMonitor", "period_violation",
                           f"0x{cid:X} ({wl['name']}) arrived {interval / 1000:.1f} ms after the previous frame, "
                           f"expected every {wl['periodMs']} ms",
                           {"intervalMs": round(interval / 1000, 2), "expectedMs": wl["periodMs"]})
        if len(win) > th["rate"]["floodFramesPerSec"]:
            self._emit(f, now, "high", "flood", "RateMonitor", "frame_rate",
                       f"0x{cid:X} is sent {len(win)} frames/s (limit {th['rate']['floodFramesPerSec']})",
                       {"framesPerSec": len(win), "limit": th["rate"]["floodFramesPerSec"]})
        self.gwin.append((now, bits))
        self.bits_sum += bits
        while self.gwin and self.gwin[0][0] < now - 1_000_000:
            self.bits_sum -= self.gwin.popleft()[1]
        load = min(100.0, self.bits_sum / BUS_BITRATE * 100.0)
        if load >= th["rate"]["busLoadWarnPct"]:
            self._emit(None, now, "critical", "flood", "RateMonitor", "bus_load",
                       f"Bus load is {load:.0f}% (warning at {th['rate']['busLoadWarnPct']}%)",
                       {"busLoadPct": round(load, 1)}, key=("bus_load",), can_id=None)

        # SignalValidator (M1): only the speed signal in this mock
        if cid == SPEED_ID and dlc >= 2 and len(data) >= 4:
            value = int(data[:4], 16) * SPEED_SCALE
            if value > SPEED_MAX:
                self.last_range_viol[cid] = now
                self._emit(f, now, "high", "spoofing", "SignalValidator", "signal_range",
                           f"Speed {value:.0f} km/h is outside the allowed range 0-{SPEED_MAX:.0f}",
                           {"signal": "VehicleSpeed", "value": round(value, 2), "min": 0, "max": SPEED_MAX})
            last = self.last_val.get(cid)
            self.last_val[cid] = (now, value)
            if last:
                dt = max((now - last[0]) / 1e6, 0.001)
                rate = abs(value - last[1]) / dt
                if rate > th["signal"]["maxRateOfChangePerSec"]:
                    self._emit(f, now, "medium", "spoofing", "SignalValidator", "signal_rate_of_change",
                               f"Speed changed {rate:.0f} km/h per second (limit {th['signal']['maxRateOfChangePerSec']})",
                               {"signal": "VehicleSpeed", "ratePerSec": round(rate, 1),
                                "limit": th["signal"]["maxRateOfChangePerSec"]})

        # ReplayDetector (M4): old payload re-sent as an extra frame, not explained by a range violation
        if wl is not None:
            seen = self.seen.setdefault(cid, {})
            order = self.order.setdefault(cid, deque())
            first_ts = seen.get(data)
            counter = int(data[-2:], 16) & 0x0F if len(data) >= 16 else None
            expected = None if cid not in self.last_counter else (self.last_counter[cid] + 1) & 0x0F
            quiet = now - self.last_range_viol.get(cid, -10**12) > 500_000
            if extra_frame and quiet and first_ts is not None and 1_000_000 <= now - first_ts <= 10_000_000:
                age = (now - first_ts) / 1e6
                if th["replay"]["counterCheck"] and counter is not None and counter != expected:
                    self._emit(f, now, "high", "replay", "ReplayDetector", "counter_regression",
                               f"0x{cid:X} ({wl['name']}) counter {counter} does not follow the previous counter; "
                               f"payload was already seen {age:.1f} s ago",
                               {"counter": counter, "expectedCounter": expected, "payloadAgeSec": round(age, 2)})
                else:
                    self._emit(f, now, "high", "replay", "ReplayDetector", "duplicate_payload",
                               f"0x{cid:X} ({wl['name']}) payload was already seen {age:.1f} s ago",
                               {"payloadAgeSec": round(age, 2)})
            seen[data] = now
            order.append((now, data))
            while len(order) > th["replay"]["hashWindowFrames"]:
                old_ts, old = order.popleft()
                if seen.get(old) == old_ts:
                    del seen[old]
            if counter is not None:
                self.last_counter[cid] = counter

    def _emit(self, frame, now, severity, category, detector, rule, message, details, key=None, can_id="frame"):
        if can_id == "frame":
            cid = frame["id"] if frame else None
        else:
            cid = can_id
        key = key or (rule, cid)
        last = self.cool.get(key)
        if last and now - last["timestampUs"] < ALERT_COOLDOWN_US:
            last["details"]["repeatCount"] = last["details"].get("repeatCount", 0) + 1
            if frame is not None and last["id"] not in frame["alertIds"]:
                frame["alertIds"].append(last["id"])
                frame["flagged"] = True
            return
        alert = {"id": self.next_alert, "timestampUs": now, "severity": severity, "category": category,
                 "detector": detector, "rule": rule, "canId": cid, "idHex": hexid(cid),
                 "frameSeq": frame["seq"] if frame else None, "message": message,
                 "details": dict(details), "acknowledged": False}
        self.next_alert += 1
        self.alerts.append(alert)
        if len(self.alerts) > ALERT_CAP:
            del self.alerts[:ALERT_CAP // 4]
        self.cool[key] = alert
        self.by_sev[severity] += 1
        self.by_cat[category] += 1
        self.by_det[detector] += 1
        self.series.setdefault(now // 1_000_000, {"frames": 0, "bits": 0, "alerts": 0})["alerts"] += 1
        if cid is not None:
            self.recent_alert_ts[cid] = now
        if frame is not None:
            frame["alertIds"].append(alert["id"])
            frame["flagged"] = True
        self.pending_alerts.append(alert)

    # ---- attack runs
    def _finish_run_if_done(self):
        if self.run and self.run["state"] == "running" and self.sim_now() >= self.run["endUs"] + 1_000_000:
            self._close_run("finished")

    def _close_run(self, state):
        run, meta = self.run, self.run_meta
        in_win = [a for a in self.alerts if run["startUs"] <= a["timestampUs"] <= run["endUs"] + 1_000_000]
        fps = [a for a in self.alerts if meta["leadUs"] <= a["timestampUs"] < run["startUs"]]
        latency = None
        if in_win:
            latency = round(max(0, min(a["timestampUs"] for a in in_win) - run["startUs"]) / 1000.0, 1)
        run["state"] = state
        run["result"] = {"detected": bool(in_win), "latencyMs": latency,
                         "alertCount": len(in_win), "falsePositives": len(fps)}
        self.run = None
        self.mode = "live"
        self._switch("normal_traffic.log", 0)
        self.pending_msgs.append({"type": "attack", "tUs": self.sim_now(), "data": dict(run)})
        self.pending_msgs.append({"type": "mode", "tUs": self.sim_now(), "data": self.status()})

    def start_attack(self, scenario, params):
        if self.run:
            raise ApiError(409, "conflict", "an attack run is already in progress")
        ev = self.events.get(EVENT_OF[scenario], {"targetId": ATTACK_DEFAULTS[scenario].get("targetId", 0),
                                                  "startUs": 10_000_000, "endUs": 20_000_000})
        fname = LOG_OF[scenario]
        if not os.path.exists(os.path.join(self.logdir, fname)):
            raise ApiError(500, "internal", f"log file {fname} not found")
        self.mode = "replay"
        self._switch(fname, max(0, ev["startUs"] - LEAD_IN_US))
        run = {"runId": self.next_run, "scenario": scenario, "targetId": params.get("targetId", ev["targetId"]),
               "params": params, "startUs": self.base + ev["startUs"], "endUs": self.base + ev["endUs"],
               "state": "running", "result": None}
        self.next_run += 1
        self.runs.append(run)
        self.run = run
        self.run_meta = {"leadUs": self.sim_now()}
        self.pending_msgs.append({"type": "attack", "tUs": self.sim_now(), "data": dict(run)})
        self.pending_msgs.append({"type": "mode", "tUs": self.sim_now(), "data": self.status()})
        return run

    def stop_attack(self):
        if not self.run:
            raise ApiError(409, "conflict", "no attack run in progress")
        self._close_run("stopped")
        return self.runs[-1]

    # ---- views
    def status(self):
        return {"mode": self.mode, "source": f"mock://{self.file}", "running": True,
                "uptimeSec": round(time.monotonic() - self.started, 1), "framesTotal": self.frames_total,
                "alertsTotal": self.next_alert - 1, "version": VERSION}

    def _prune(self, now):
        for win in self.win.values():
            while win and win[0] < now - 1_000_000:
                win.popleft()
        while self.gwin and self.gwin[0][0] < now - 1_000_000:
            self.bits_sum -= self.gwin.popleft()[1]

    def stats(self):
        now = self.sim_now()
        self._prune(now)
        fps = sum(len(w) for w in self.win.values())
        return {"framesTotal": self.frames_total, "framesPerSec": float(fps),
                "busLoadPct": round(min(100.0, self.bits_sum / BUS_BITRATE * 100.0), 1),
                "alertsTotal": self.next_alert - 1,
                "alertsBySeverity": {s: self.by_sev.get(s, 0) for s in SEVERITIES},
                "alertsByCategory": {c: self.by_cat.get(c, 0) for c in CATEGORIES},
                "alertsByDetector": {d: self.by_det.get(d, 0) for d in DETECTORS},
                "topIds": [{"id": i, "idHex": hexid(i), "count": c} for i, c in self.id_counts.most_common(5)]}

    def timeseries(self, window):
        cur = self.sim_now() // 1_000_000
        for old in [s for s in self.series if s < cur - 700]:
            del self.series[old]
        points = []
        for s in range(max(0, cur - window + 1), cur + 1):
            b = self.series.get(s, {"frames": 0, "bits": 0, "alerts": 0})
            points.append({"tUs": s * 1_000_000, "frames": b["frames"],
                           "busLoadPct": round(min(100.0, b["bits"] / BUS_BITRATE * 100.0), 1), "alerts": b["alerts"]})
        return {"bucketSec": 1, "points": points}

    def id_stats(self):
        now = self.sim_now()
        self._prune(now)
        ids = set(self.whitelist) | {i for i, w in self.win.items() if w}
        items = []
        for cid in sorted(ids):
            wl = self.whitelist.get(cid)
            last_p = self.last_period.get(cid)
            items.append({"id": cid, "idHex": hexid(cid), "name": wl["name"] if wl else None,
                          "framesPerSec": float(len(self.win.get(cid, ()))),
                          "expectedPeriodMs": wl["periodMs"] if wl else None,
                          "lastPeriodMs": None if last_p is None else round(last_p, 2)})
        return {"items": items}

    def ecus(self):
        now = self.sim_now()
        self._prune(now)
        items = []
        for name, ids in ECUS:
            ids = [i for i in ids if i in self.whitelist] or ids
            seen = [self.last_seen[i] for i in ids if i in self.last_seen]
            last_seen = max(seen) if seen else None
            if last_seen is None or now - last_seen > 1_000_000:
                status = "offline"
            elif any(now - self.recent_alert_ts.get(i, -10**12) < 3_000_000 for i in ids):
                status = "warning"
            else:
                status = "ok"
            items.append({"name": name, "ids": ids, "status": status,
                          "framesPerSec": float(sum(len(self.win.get(i, ())) for i in ids)),
                          "lastSeenUs": last_seen,
                          "alertCount": sum(1 for a in self.alerts if a["canId"] in ids)})
        return items

    # ---- websocket output
    def _flush(self, real_now):
        out = []
        if self.pending_frames:
            fr, self.pending_frames = self.pending_frames, []
            if len(fr) > FRAME_BATCH_MAX:
                flagged = [f for f in fr if f["flagged"]][:FRAME_BATCH_MAX]
                rest = [f for f in fr if not f["flagged"]]
                room = FRAME_BATCH_MAX - len(flagged)
                step = max(1, len(rest) // room) if room else 1
                fr = sorted(flagged + (rest[::step][:room] if room else []), key=lambda f: f["seq"])
            out.append({"type": "frames", "tUs": self.sim_now(), "data": {"items": fr}})
        for a in self.pending_alerts:
            out.append({"type": "alert", "tUs": a["timestampUs"], "data": a})
        self.pending_alerts = []
        out.extend(self.pending_msgs)
        self.pending_msgs = []
        if real_now - self._last_stats_push >= 1.0:
            self._last_stats_push = real_now
            data = self.stats()
            data["ecus"] = self.ecus()
            out.append({"type": "stats", "tUs": self.sim_now(), "data": data})
        if self.clients and out:
            texts = [json.dumps(m) for m in out]
            for q in list(self.clients):
                for t in texts:
                    try:
                        q.put_nowait(t)
                    except queue.Full:
                        break


# ------------------------------------------------------------------ flask app
def create_app(engine, frontend_dir):
    app = Flask(__name__, static_folder=None)

    @app.after_request
    def cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    @app.errorhandler(ApiError)
    def api_error(e):
        return jsonify({"error": {"code": e.code, "message": e.message}}), e.status

    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith("/api"):
            return jsonify({"error": {"code": "not_found", "message": f"no such endpoint: {request.path}"}}), 404
        return "Not found", 404

    @app.errorhandler(405)
    def not_allowed(_e):
        return jsonify({"error": {"code": "bad_request", "message": "method not allowed"}}), 405

    @app.errorhandler(500)
    def internal(_e):
        return jsonify({"error": {"code": "internal", "message": "internal error"}}), 500

    @app.route("/api/<path:_any>", methods=["OPTIONS"])
    def preflight(_any):
        return "", 204

    # ---- system
    @app.get("/api/health")
    def health():
        return jsonify({"ok": True})

    @app.get("/api/status")
    def status():
        with engine.lock:
            return jsonify(engine.status())

    @app.put("/api/mode")
    def set_mode():
        body = body_json()
        mode = body.get("mode")
        if mode not in ("live", "replay"):
            raise bad('mode must be "live" or "replay"')
        with engine.lock:
            if engine.run:
                raise ApiError(409, "conflict", "stop the attack run first")
            if mode == "live":
                fname = "normal_traffic.log"
            else:
                fname = body.get("file")
                if not isinstance(fname, str) or os.path.basename(fname) != fname or not fname.endswith(".log"):
                    raise bad("file must be the name of a .log file in busmaster/logs")
                if not os.path.exists(os.path.join(engine.logdir, fname)):
                    raise bad(f"log file not found: {fname}")
            engine.mode = mode
            engine._switch(fname, 0)
            st = engine.status()
            engine.pending_msgs.append({"type": "mode", "tUs": engine.sim_now(), "data": st})
            return jsonify(st)

    # ---- frames
    @app.get("/api/frames")
    def frames():
        raw_id = request.args.get("id")
        cid = parse_id(raw_id) if raw_id else None
        flagged, since = qbool("flagged"), qint("sinceUs", None, 0, 10**15)
        with engine.lock:
            items = [f for f in reversed(engine.frames)
                     if (cid is None or f["id"] == cid) and (flagged is None or f["flagged"] == flagged)
                     and (since is None or f["timestampUs"] >= since)]
            return jsonify(page(items))

    @app.get("/api/frames/<int:seq>")
    def frame(seq):
        with engine.lock:
            if not engine.frames or not engine.frames[0]["seq"] <= seq <= engine.frames[-1]["seq"]:
                raise ApiError(404, "not_found", f"frame {seq} is no longer in the buffer")
            f = dict(engine.frames[seq - engine.frames[0]["seq"]])
            ids = set(f["alertIds"])
            f["alerts"] = [a for a in engine.alerts if a["id"] in ids]
            return jsonify(f)

    # ---- alerts
    @app.get("/api/alerts")
    def alerts():
        sev, cat, det = request.args.get("severity"), request.args.get("category"), request.args.get("detector")
        for name, val, allowed in (("severity", sev, SEVERITIES), ("category", cat, CATEGORIES),
                                   ("detector", det, DETECTORS)):
            if val is not None and val not in allowed:
                raise bad(f"{name} must be one of {allowed}")
        can_raw = request.args.get("canId")
        cid = parse_id(can_raw) if can_raw is not None else None
        since = qint("sinceUs", None, 0, 10**15)
        with engine.lock:
            items = [a for a in reversed(engine.alerts)
                     if (sev is None or a["severity"] == sev) and (cat is None or a["category"] == cat)
                     and (det is None or a["detector"] == det) and (cid is None or a["canId"] == cid)
                     and (since is None or a["timestampUs"] >= since)]
            return jsonify(page(items))

    def find_alert(alert_id):
        for a in engine.alerts:
            if a["id"] == alert_id:
                return a
        raise ApiError(404, "not_found", f"alert {alert_id} not found")

    @app.get("/api/alerts/<int:alert_id>")
    def alert(alert_id):
        with engine.lock:
            a = dict(find_alert(alert_id))
            fr = next((f for f in engine.frames if f["seq"] == a["frameSeq"]), None)
            a["frame"] = fr
            return jsonify(a)

    @app.post("/api/alerts/<int:alert_id>/ack")
    def ack(alert_id):
        with engine.lock:
            a = find_alert(alert_id)
            a["acknowledged"] = True
            return jsonify(a)

    @app.post("/api/alerts/clear")
    def clear():
        with engine.lock:
            n = len(engine.alerts)
            engine.alerts.clear()
            engine.cool.clear()
            return jsonify({"cleared": n})

    # ---- stats
    @app.get("/api/stats")
    def stats():
        with engine.lock:
            return jsonify(engine.stats())

    @app.get("/api/stats/timeseries")
    def timeseries():
        window = qint("windowSec", 60, 1, 600)
        with engine.lock:
            return jsonify(engine.timeseries(window))

    @app.get("/api/stats/ids")
    def stats_ids():
        with engine.lock:
            return jsonify(engine.id_stats())

    @app.get("/api/ecus")
    def ecus():
        with engine.lock:
            return jsonify({"items": engine.ecus()})

    # ---- settings
    @app.get("/api/settings/thresholds")
    def get_thresholds():
        with engine.lock:
            return jsonify(engine.th)

    @app.put("/api/settings/thresholds")
    def put_thresholds():
        new = validate_thresholds(body_json())
        with engine.lock:
            engine.th = new
            return jsonify(engine.th)

    @app.get("/api/settings/whitelist")
    def get_whitelist():
        with engine.lock:
            return jsonify({"ids": [engine.whitelist[i] for i in sorted(engine.whitelist)]})

    @app.put("/api/settings/whitelist")
    def put_whitelist():
        new = validate_whitelist(body_json())
        with engine.lock:
            engine.whitelist = new
            return jsonify({"ids": [new[i] for i in sorted(new)]})

    # ---- attack lab
    @app.get("/api/attack/scenarios")
    def scenarios():
        return jsonify({"items": [{"scenario": s, "params": ATTACK_DEFAULTS[s]} for s in SCENARIOS]})

    @app.post("/api/attack/start")
    def attack_start():
        body = body_json()
        scenario = body.get("scenario")
        if scenario not in SCENARIOS:
            raise bad(f"scenario must be one of {SCENARIOS}")
        given = body.get("params", {})
        if not isinstance(given, dict):
            raise bad("params must be an object")
        params = dict(ATTACK_DEFAULTS[scenario])
        for k, v in given.items():
            if k not in params:
                raise bad(f"unknown parameter for {scenario}: {k}")
            if not is_num(v) or v < 0:
                raise bad(f"parameter {k} must be a non-negative number")
            params[k] = v
        with engine.lock:
            return jsonify(engine.start_attack(scenario, params))

    @app.post("/api/attack/stop")
    def attack_stop():
        with engine.lock:
            return jsonify(engine.stop_attack())

    @app.get("/api/attack/status")
    def attack_status():
        with engine.lock:
            return jsonify(engine.run)

    @app.get("/api/attack/runs")
    def attack_runs():
        with engine.lock:
            return jsonify({"items": list(reversed(engine.runs))})

    # ---- websocket
    if Sock is not None:
        sock = Sock(app)

        @sock.route("/ws")
        def ws(conn):
            q = queue.Queue(maxsize=2000)
            with engine.lock:
                engine.clients.add(q)
                hello = {"type": "hello", "tUs": engine.sim_now(), "data": engine.status()}
            try:
                conn.send(json.dumps(hello))
                while True:
                    try:
                        conn.send(q.get(timeout=0.5))
                    except queue.Empty:
                        pass
                    conn.receive(timeout=0)       # raises when the browser has gone away
            except Exception:
                pass
            finally:
                with engine.lock:
                    engine.clients.discard(q)
    else:
        print("[mock] flask-sock is not installed: /ws is disabled (pip install -r tools/requirements.txt)")

    # ---- static dashboard
    @app.get("/")
    def index():
        return send_from_directory(frontend_dir, "index.html")

    @app.get("/<path:path>")
    def static_files(path):
        if path.startswith("api/"):
            raise ApiError(404, "not_found", f"no such endpoint: /{path}")
        return send_from_directory(frontend_dir, path)

    return app


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap = argparse.ArgumentParser(description="CAN Guard mock backend (api_contract.md v0.1)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--speed", type=float, default=1.0, help="playback speed, 1.0 = real time")
    ap.add_argument("--logs", default=os.path.join(root, "busmaster", "logs"))
    ap.add_argument("--frontend", default=os.path.join(root, "frontend"))
    ap.add_argument("--config", default=os.path.join(root, "backend", "config"))
    args = ap.parse_args()
    if args.speed <= 0:
        ap.error("--speed must be positive")
    if not os.path.exists(os.path.join(args.logs, "normal_traffic.log")):
        ap.error(f"normal_traffic.log not found in {args.logs} (run tools/generate_attack_logs.py)")

    engine = Engine(args.logs, args.speed, args.config)
    threading.Thread(target=engine.run_forever, daemon=True).start()
    app = create_app(engine, args.frontend)
    print(f"[mock] http://{args.host}:{args.port}/  (API under /api, WebSocket /ws, speed x{args.speed})")
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
