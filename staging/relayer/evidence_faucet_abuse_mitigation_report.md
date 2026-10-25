# Staging Faucet Claim Rate & Abuse Mitigation Report
**Target Faucet Address**: `0x1821dc3f0974339db7c7146037b40f54a2e222c3`  
**Report Generated**: `2026-10-25T18:27:07.200192+00:00`  
**Decision D1 Status**: Authorized by Principal Pavel Cherkashin (2026-10-25 10:16 PDT)  

---

## 1. Real-Time Claim Metrics & Velocity Analysis

| Metric | Measured Value | Threshold / Ceiling | Status |
|---|---|---|---|
| **Total Lifetime Claims** | `5` claims | `1,000,000` claims | ✅ Normal |
| **VST Distributed** | `105,000,000 VST` | `21,000,000,000,000 VST` | ✅ Normal (0.0005% drained) |
| **Remaining Faucet Capacity** | `999,995` claims (`20,999,895,000,000 VST`) | `> 100,000` claims (10% alert floor) | ✅ Plentiful (100.00% remaining) |
| **Claim Rate (Past 1 Hour)** | `1` claims/hour | `< 25` claims/hour | ✅ Normal |
| **Claim Rate (Past 24 Hours)**| `5` claims/day | `< 500` claims/day | ✅ Normal |
| **Unique Recipient Addresses**| `5` | N/A | ✅ Verified |
| **Unique Subnet Prefixes (/24)**| `2` | N/A | ✅ Distributed |

---

## 2. Implemented Abuse Mitigations (Defense-in-Depth)

To prevent automated bot drain of the public staging faucet without blocking legitimate users, four layers of mitigation are deployed:

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

## 3. Operational Alerting & Emergency Drainage Mitigation

- **Warning Threshold**: Remaining balance < `200,000,000,000 VST` (under 10,000 claims remaining).
- **Critical Threshold**: Remaining balance < `21,000,000,000 VST` (under 1,000 claims remaining).
- **Automated Action**:
  - The relayer triggers adaptive difficulty increase to `16 bits` baseline across all callers.
  - Alert is dispatched to Linear / Watchdog for faucet replenishment.
  - Test coins have zero monetary value; empty faucet does not compromise chain integrity, only faucet user experience.
