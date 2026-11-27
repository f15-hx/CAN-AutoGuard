#!/usr/bin/env python3
"""
Owner: M2 | Generates synthetic CAN logs (normal traffic + each attack) in the team wire format:
    timestampUs,id,dlc,hexbytes          e.g.  1234567,0x244,8,005A00001100007F

Why: lets M3 (engine) and M4 (detectors/UI) test against attack data BEFORE BusMaster is ready.
When BusMaster nodes work, record real logs and keep this script for repeatable test data.

IMPORTANT: the IDs, cycle times and payload layout below are PLACEHOLDERS.
Update the CONFIG section when M1 finalizes vehicle.dbc.

Usage:
    python tools/generate_attack_logs.py                 # writes into busmaster/logs/
    python tools/generate_attack_logs.py --out some/dir --seed 7
"""
import argparse, csv, os, random

# ---------------- CONFIG (match vehicle.dbc once M1 finishes it) ----------------
MESSAGES = {            # id: (name, cycle_us, dlc)
    0x244: ("Speed",     10_000, 8),
    0x2C0: ("Engine",    20_000, 8),
    0x1A0: ("Brake",     20_000, 8),
    0x3B0: ("Door",     100_000, 8),
    0x4F0: ("Dashboard", 50_000, 8),
}
# Assumed payload layout: bytes 0-1 = value (big endian), byte 7 low nibble = rolling counter 0..15
TOTAL_S      = 30          # length of each log
ATTACK_START = 10          # attack window start (seconds)
ATTACK_END   = 20          # attack window end (seconds)
JITTER_US    = 200         # +/- timing jitter on normal frames
# ----------------------------------------------------------------------------------

def payload(value, counter, dlc=8):
    b = bytearray(dlc)
    b[0] = (value >> 8) & 0xFF
    b[1] = value & 0xFF
    if dlc >= 8:
        b[7] = counter & 0x0F
    return bytes(b)

def line(ts, cid, data):
    return (int(ts), cid, len(data), data)

def normal_traffic(rng, total_us):
    frames = []
    for cid, (name, cycle, dlc) in MESSAGES.items():
        counter, t = 0, rng.randint(0, cycle)
        value = 9000 if cid == 0x244 else rng.randint(1000, 4000)   # 9000 = 90.00 km/h
        while t < total_us:
            if cid == 0x244:
                value = max(0, min(20000, value + rng.randint(-15, 15)))     # slow drift, no jumps
            else:
                value = max(0, min(65535, value + rng.randint(-40, 40)))
            frames.append(line(t + rng.randint(-JITTER_US, JITTER_US), cid, payload(value, counter, dlc)))
            counter = (counter + 1) & 0x0F
            t += cycle
    return frames

def attack_spoof(rng, a0, a1):
    """Fake speed frames on 0x244, interleaved with the real ones (doubles the rate, wild value)."""
    out, t, counter = [], a0 + 5_000, 0
    while t < a1:
        out.append(line(t, 0x244, payload(25500, counter)))      # 255.00 km/h
        counter = (counter + 1) & 0x0F
        t += 10_000
    return out, 0x244

def attack_replay(rng, a0, a1, normal):
    """Replay brake frames captured from 2 s before the attack, resent verbatim (old counters/payloads)."""
    window = [f for f in normal if f[1] == 0x1A0 and a0 - 2_000_000 <= f[0] < a0]
    out, offset = [], 2_000_000
    for ts, cid, dlc, data in window:
        t = ts + offset
        if a0 <= t < a1:
            out.append((t + 3_000, cid, dlc, data))
    return out, 0x1A0

def attack_flood(rng, a0, a1):
    """Highest-priority ID 0x000 at ~4000 frames/s."""
    out, t = [], a0
    while t < a1:
        out.append(line(t, 0x000, bytes(8)))
        t += 250
    return out, 0x000

def attack_fuzz(rng, a0, a1):
    """Random IDs, random payloads and some invalid lengths at ~200 frames/s."""
    out, t = [], a0
    while t < a1:
        cid = rng.choice([rng.randint(0, 0x7FF), 0x7FF, 0x7DF])
        dlc = rng.choice([8, 8, 8, 4, 2, 1])
        out.append(line(t, cid, bytes(rng.randint(0, 255) for _ in range(dlc))))
        t += 5_000
    return out, 0xFFFF   # 0xFFFF = "many / random IDs"

def write_log(path, frames):
    frames = sorted(frames, key=lambda f: f[0])
    with open(path, "w", newline="") as fh:
        for ts, cid, dlc, data in frames:
            fh.write(f"{max(ts,0)},0x{cid:X},{dlc},{data.hex().upper()}\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join("busmaster", "logs"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    total, a0, a1 = TOTAL_S * 1_000_000, ATTACK_START * 1_000_000, ATTACK_END * 1_000_000
    rng = random.Random(args.seed)
    normal = normal_traffic(rng, total)
    write_log(os.path.join(args.out, "normal_traffic.log"), normal)

    events = []
    for name, fn in [("spoof", lambda: attack_spoof(rng, a0, a1)),
                     ("replay", lambda: attack_replay(rng, a0, a1, normal)),
                     ("flood", lambda: attack_flood(rng, a0, a1)),
                     ("fuzz", lambda: attack_fuzz(rng, a0, a1))]:
        extra, target = fn()
        write_log(os.path.join(args.out, f"attack_{name}.log"), normal + extra)
        events.append((name, f"0x{target:X}", min(f[0] for f in extra), max(f[0] for f in extra)))   # real attack window
        print(f"attack_{name}.log: {len(normal)} normal + {len(extra)} attack frames")

    with open(os.path.join(args.out, "attack_events.csv"), "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n"); w.writerow(["scenario", "targetId", "startUs", "endUs"]); w.writerows(events)
    print(f"normal_traffic.log: {len(normal)} frames; wrote attack_events.csv to {args.out}")

if __name__ == "__main__":
    main()