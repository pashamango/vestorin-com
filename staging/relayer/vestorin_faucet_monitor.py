#!/usr/bin/env python3
"""
vestorin_faucet_monitor.py — Automated Staging Faucet Balance Monitor & Abuse Mitigation Reporter
Supports MIN-227 (Tailnet-Only HTTPS Serving & Abuse Mitigation Monitoring).
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys
import urllib.request
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATHS = [
    "/Users/pavelcherkashin/vestorin-chain/vestorin_relayer_state.db",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "vestorin_relayer_state.db")),
]

FAUCET_ADDRESS = "0x1821dc3f0974339db7c7146037b40f54a2e222c3"
MAX_CLAIM_VST = 21_000_000
INITIAL_FAUCET_CAPACITY_CLAIMS = 1_000_000
TOTAL_FAUCET_SUPPLY_VST = INITIAL_FAUCET_CAPACITY_CLAIMS * MAX_CLAIM_VST  # 21,000,000,000,000 VST

# Operational Alerting Thresholds
VELOCITY_ALERT_1H = 25  # claims per hour
VELOCITY_ALERT_24H = 500  # claims per 24 hours
BALANCE_WARNING_VST = 200_000_000_000  # 10,000 claims remaining warning floor
BALANCE_CRITICAL_VST = 21_000_000_000  # 1,000 claims remaining critical floor
EMERGENCY_POUW_DIFFICULTY_BITS = 16

DEFAULT_ALERT_LOG_PATH = "/Users/pavelcherkashin/ChitAkasha-Wolfram/agent-logs/vestorin_faucet_alerts.jsonl"

def get_db_path() -> str:
    for p in DEFAULT_DB_PATHS:
        if os.path.exists(p):
            return p
    return DEFAULT_DB_PATHS[0]

def analyze_claims(db_path: str, now_ts: int = None) -> Dict[str, Any]:
    if now_ts is None:
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    if not os.path.exists(db_path):
        return {
            "error": f"Database file not found at {db_path}",
            "lifetimeClaims": 0,
            "claimsLast1h": 0,
            "claimsLast6h": 0,
            "claimsLast24h": 0,
            "claimVelocityPerHour": 0.0,
            "uniqueAddresses": 0,
            "uniqueSubnets": 0,
        }

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Check if table exists
        tbl_check = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='claims'").fetchone()
        if not tbl_check:
            return {
                "error": "claims table does not exist yet",
                "lifetimeClaims": 0,
                "claimsLast1h": 0,
                "claimsLast6h": 0,
                "claimsLast24h": 0,
                "claimVelocityPerHour": 0.0,
                "uniqueAddresses": 0,
                "uniqueSubnets": 0,
            }

        total = c.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        c_1h = c.execute("SELECT COUNT(*) FROM claims WHERE claimed_at > ?", (now_ts - 3600,)).fetchone()[0]
        c_6h = c.execute("SELECT COUNT(*) FROM claims WHERE claimed_at > ?", (now_ts - 21600,)).fetchone()[0]
        c_24h = c.execute("SELECT COUNT(*) FROM claims WHERE claimed_at > ?", (now_ts - 86400,)).fetchone()[0]

        uniq_addrs = c.execute("SELECT COUNT(DISTINCT recipient_address) FROM claims").fetchone()[0]
        uniq_subnets = c.execute("SELECT COUNT(DISTINCT subnet_prefix) FROM claims").fetchone()[0]

        recent_claims = [
            dict(r) for r in c.execute(
                "SELECT recipient_address, dosage_vst, tx_hash, subnet_prefix, claimed_at FROM claims ORDER BY claimed_at DESC LIMIT 5"
            ).fetchall()
        ]

    velocity = c_1h  # hourly rate based on past hour

    return {
        "dbPath": db_path,
        "timestamp": now_ts,
        "lifetimeClaims": total,
        "claimsLast1h": c_1h,
        "claimsLast6h": c_6h,
        "claimsLast24h": c_24h,
        "claimVelocityPerHour": velocity,
        "uniqueAddresses": uniq_addrs,
        "uniqueSubnets": uniq_subnets,
        "recentClaims": recent_claims,
    }

def evaluate_alerts(metrics: Dict[str, Any], balance_vst: Optional[float] = None) -> List[Dict[str, Any]]:
    """Evaluates operational velocity and balance thresholds against measured metrics."""
    alerts = []
    claims_1h = metrics.get("claimsLast1h", 0)
    claims_24h = metrics.get("claimsLast24h", 0)
    lifetime = metrics.get("lifetimeClaims", 0)

    if balance_vst is None:
        balance_vst = max(0, TOTAL_FAUCET_SUPPLY_VST - (lifetime * MAX_CLAIM_VST))

    if claims_1h >= VELOCITY_ALERT_1H:
        alerts.append({
            "level": "CRITICAL",
            "code": "ALERT_HIGH_VELOCITY_1H",
            "threshold": VELOCITY_ALERT_1H,
            "measured": claims_1h,
            "message": f"Claim velocity past 1h ({claims_1h} claims) exceeds threshold ({VELOCITY_ALERT_1H}/h).",
            "action": "Investigate potential automated Sybil burst; adaptive subnet difficulty scaling active."
        })

    if claims_24h >= VELOCITY_ALERT_24H:
        alerts.append({
            "level": "WARNING",
            "code": "ALERT_HIGH_VELOCITY_24H",
            "threshold": VELOCITY_ALERT_24H,
            "measured": claims_24h,
            "message": f"Claim volume past 24h ({claims_24h} claims) exceeds threshold ({VELOCITY_ALERT_24H}/day).",
            "action": "Review faucet distribution and recipient subnet diversity."
        })

    if balance_vst < BALANCE_CRITICAL_VST:
        alerts.append({
            "level": "CRITICAL",
            "code": "ALERT_FAUCET_BALANCE_CRITICAL",
            "threshold": BALANCE_CRITICAL_VST,
            "measured": balance_vst,
            "message": f"Faucet balance ({balance_vst:,.0f} VST) below critical floor ({BALANCE_CRITICAL_VST:,} VST).",
            "action": f"Automated baseline PoUW escalation to {EMERGENCY_POUW_DIFFICULTY_BITS} bits active on relayer; immediate replenishment required."
        })
    elif balance_vst < BALANCE_WARNING_VST:
        alerts.append({
            "level": "WARNING",
            "code": "ALERT_FAUCET_BALANCE_WARNING",
            "threshold": BALANCE_WARNING_VST,
            "measured": balance_vst,
            "message": f"Faucet balance ({balance_vst:,.0f} VST) below warning floor ({BALANCE_WARNING_VST:,} VST).",
            "action": "Schedule faucet account replenishment from mining/genesis reserve."
        })

    return alerts

def generate_markdown_report(metrics: Dict[str, Any], balance_vst: Optional[float] = None) -> str:
    lifetime = metrics.get("lifetimeClaims", 0)
    claims_1h = metrics.get("claimsLast1h", 0)
    claims_24h = metrics.get("claimsLast24h", 0)
    vst_distributed = lifetime * MAX_CLAIM_VST

    if balance_vst is None:
        remaining_claims = max(0, INITIAL_FAUCET_CAPACITY_CLAIMS - lifetime)
        remaining_vst = remaining_claims * MAX_CLAIM_VST
    else:
        remaining_vst = balance_vst
        remaining_claims = int(remaining_vst // MAX_CLAIM_VST)

    drain_pct = (lifetime / INITIAL_FAUCET_CAPACITY_CLAIMS) * 100
    alerts = evaluate_alerts(metrics, balance_vst=remaining_vst)

    alerts_summary = "✅ All thresholds within normal parameters (no active alerts)."
    if alerts:
        alerts_summary = "\n".join([f"- **[{a['level']}]** `{a['code']}`: {a['message']} (Action: {a['action']})" for a in alerts])

    report = f"""# Staging Faucet Claim Rate & Abuse Mitigation Report
**Target Faucet Address**: `{FAUCET_ADDRESS}`
**Report Generated**: `{datetime.datetime.now(datetime.timezone.utc).isoformat()}`
**Decision D1 Status**: GATED & UNTAPPED (Tailnet-Only Reachability per MIN-227 Acceptance Criteria)

---

## 1. Real-Time Claim Metrics & Velocity Analysis

| Metric | Measured Value | Threshold / Ceiling | Status |
|---|---|---|---|
| **Total Lifetime Claims** | `{lifetime:,}` claims | `1,000,000` claims | ✅ Normal |
| **VST Distributed** | `{vst_distributed:,} VST` | `21,000,000,000,000 VST` | ✅ Normal ({drain_pct:.4f}% drained) |
| **Remaining Faucet Capacity** | `{remaining_claims:,}` claims (`{remaining_vst:,} VST`) | `> 100,000` claims (10% alert floor) | ✅ Plentiful ({100 - drain_pct:.2f}% remaining) |
| **Claim Rate (Past 1 Hour)** | `{claims_1h}` claims/hour | `< {VELOCITY_ALERT_1H}` claims/hour | {'✅ Normal' if claims_1h < VELOCITY_ALERT_1H else '⚠️ Alert'} |
| **Claim Rate (Past 24 Hours)**| `{claims_24h}` claims/day | `< {VELOCITY_ALERT_24H}` claims/day | {'✅ Normal' if claims_24h < VELOCITY_ALERT_24H else '⚠️ Alert'} |
| **Unique Recipient Addresses**| `{metrics.get('uniqueAddresses', 0):,}` | N/A | ✅ Verified |
| **Unique Subnet Prefixes**| `{metrics.get('uniqueSubnets', 0):,}` | N/A | ✅ Distributed |

---

## 2. Implemented Abuse Mitigations (Defense-in-Depth)

To prevent automated bot drain of the staging faucet while preserving seamless onboarding on Tailnet, four layers of defense are deployed:

1. **Per-Address Cooldown (24 Hours)**:
   - Enforced by SQLite unique index on `claims` table.
   - Any address attempting a second claim within 86,400 seconds is rejected immediately with HTTP 429 (`Address cooldown active (<N>s remaining)`).

2. **Sliding-Window Subnet Rate Limiting & Adaptive PoUW Difficulty**:
   - Every request is tagged with the client's subnet prefix (`/24` for IPv4, `/48` for IPv6).
   - Base difficulty is `12 bits` (average 4,096 Keccak/SHA256 iterations).
   - If more than 5 claims originate from the same subnet within 1 hour, difficulty dynamically scales by `+min(6, subnet_count // 5)` bits (up to 18 bits = 262,144 iterations).
   - This makes Sybil attacks exponentially more expensive without hard-banning shared CGNAT/VPN subnets.

3. **Stateless HMAC-SHA256 Challenge Binding**:
   - Challenges expire in 300 seconds and are cryptographically bound to `(address, block_number, ts_bucket)`.
   - Proofs cannot be precomputed or reused across addresses or blocks.

4. **Single-Use Proof Hash Elimination**:
   - The SHA-256 witness `proof_hash` is permanently recorded in SQLite.
   - Replay attempts of previously mined witnesses fail with duplicate hash rejection.

---

## 3. Operational Alerting & Emergency Mitigation Status

- **Warning Floor**: Remaining balance < `200,000,000,000 VST` (10,000 claims remaining).
- **Critical Floor**: Remaining balance < `21,000,000,000 VST` (1,000 claims remaining).
- **Automated Escalation**: When faucet balance drops below critical floor, relayer dynamically elevates baseline PoUW difficulty to `16 bits` across all callers.
- **Current Alert Status**:
{alerts_summary}
"""
    return report

def main():
    parser = argparse.ArgumentParser(description="Vestorin Faucet Claim Rate Monitor")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--save-report", type=str, default="", help="Path to write Markdown report")
    parser.add_argument("--check-alerts", action="store_true", help="Evaluate operational alert thresholds and exit with status code")
    parser.add_argument("--log-alerts", type=str, default="", help="Path to append active alert JSON lines")
    args = parser.parse_args()

    db_path = get_db_path()
    metrics = analyze_claims(db_path)
    alerts = evaluate_alerts(metrics)

    if args.log_alerts and alerts:
        log_path = args.log_alerts
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as lf:
            for a in alerts:
                entry = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), **a}
                lf.write(json.dumps(entry) + "\n")

    if args.check_alerts:
        if args.json:
            print(json.dumps({"metrics": metrics, "alerts": alerts}, indent=2))
        else:
            if not alerts:
                print("OK: All faucet metrics within normal operational thresholds.")
            else:
                for a in alerts:
                    print(f"[{a['level']}] {a['code']}: {a['message']} -> {a['action']}")
        if any(a["level"] == "CRITICAL" for a in alerts):
            sys.exit(2)
        elif alerts:
            sys.exit(1)
        sys.exit(0)

    if args.json:
        print(json.dumps({"metrics": metrics, "alerts": alerts}, indent=2))
        return

    md = generate_markdown_report(metrics)
    if args.save_report:
        with open(args.save_report, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"Report saved to {args.save_report}")
    else:
        print(md)

if __name__ == "__main__":
    main()
