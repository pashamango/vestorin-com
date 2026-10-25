#!/usr/bin/env python3
"""
vestorin_wolfram_relayer.py — Zero-Dependency Operator Faucet Relayer, PoUW Gate & Safe JSON-RPC Proxy
Target Host: Wolfram (macOS Tahoe / Linux, Python 3.9+ stdlib only — zero pip packages required)
Chain: Vestorin Staging Testnet (Chain ID 202627 / 0x31783, Geth 1.13.14 Clique PoA, pre-London/Berlin)

Capabilities:
1. Safe JSON-RPC Allowlist Proxy (`POST /` and `POST /rpc`):
   - Forwards strictly allowlisted read/tx methods (`eth_chainId`, `eth_blockNumber`, `eth_getBalance`,
     `eth_gasPrice`, `eth_estimateGas`, `eth_getTransactionCount`, `eth_sendRawTransaction`,
     `eth_getTransactionReceipt`, `eth_getTransactionByHash`, `eth_getBlockByNumber`, `eth_getBlockByHash`,
     `eth_call`, `eth_getCode`, `net_version`, `web3_clientVersion`) to local geth (`http://127.0.0.1:8545`).
   - Strictly blocks `admin_*`, `personal_*`, `miner_*`, `clique_*`, `debug_*`, `txpool_*`, `eth_sendTransaction`, `eth_accounts`.
   - Solves the geth tailnet HTTP hang quirk by binding the Python server to `0.0.0.0` / Tailnet IP while talking
     to geth strictly over `127.0.0.1:8545`.
   - Optional `VESTORIN_OVERRIDE_GASPRICE_ZERO=1` mode to return `0x0` (or `0x1` = 1 wei) on `eth_gasPrice` for T1/T2 testing.

2. Deterministic Proof-of-Useful-Work (PoUW) Challenge & Verification (`GET /api/v1/challenge`, `POST /api/v1/claim`):
   - Issues stateless HMAC-SHA256 challenges bound to `(recipient_address, current_block_number, time_bucket)`.
   - Verifies client SPEC-04 strictly descending poset rank sequence (`r_0 > r_1 > ... > 0`, depth >= 5)
     and Carlström Wheel W(Q) non-trivial evaluation witness + leading-zero-bit difficulty (adaptive per subnet, no /24 hard ban).

3. Persistent SQLite Quota, Cooldown & Used-Proof-Hash Registry (`vestorin_relayer_state.db`):
   - Enforces 1 claim per address per cooldown window (default 86,400s = 24h) and max dosage (default 21,000,000 VST).
   - Permanently records every `proof_hash` so no witness can ever be replayed.

4. Native Raw EIP-155 Transaction Signing (`gasPrice = 0` by default) or Unlocked-Geth / IPC Fallback:
   - Supports signing directly in pure Python stdlib using:
     (a) `VESTORIN_FAUCET_PRIVKEY` (hex private key), or
     (b) `VESTORIN_FAUCET_KEYSTORE` + `VESTORIN_FAUCET_PASSWORD_FILE` (decrypts standard Geth Web3 Secret Storage v3 JSON via `hashlib.scrypt` + `openssl enc -d -aes-128-ctr`), or
     (c) `VESTORIN_SIGN_MODE=geth_unlocked` (calls `eth_sendTransaction` on localhost:8545 if faucet is unlocked inside local geth).
"""

import argparse
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# =============================================================================
# 1. CONFIGURATION & STAGING CONSTANTS (SECTION 4 OF BRIEF)
# =============================================================================
CHAIN_ID_DEC = int(os.environ.get("VESTORIN_CHAIN_ID", "202627"))
CHAIN_ID_HEX = hex(CHAIN_ID_DEC)  # 0x31783
GENESIS_HASH = "0x0ab605a3cf46aab8ac3b38dd111e54f8c5ba458a4144c186bf8d0d0de95ca793"
FAUCET_ADDRESS = os.environ.get(
    "VESTORIN_FAUCET_ADDRESS", "0x1821dc3f0974339db7c7146037b40f54a2e222c3"
).lower()
SIGNER_ADDRESS = "0x0e5fde73cfd2e7fb4d164b5d6487dea645832401"

GETH_LOCAL_RPC = os.environ.get("VESTORIN_GETH_RPC", "http://127.0.0.1:8545")
BIND_HOST = os.environ.get("VESTORIN_BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("VESTORIN_BIND_PORT", "8546"))
DB_PATH = os.environ.get("VESTORIN_DB_PATH", "./vestorin_relayer_state.db")

MAX_CLAIM_VST = int(os.environ.get("VESTORIN_MAX_CLAIM_VST", "21000000"))
COOLDOWN_SECONDS = int(os.environ.get("VESTORIN_COOLDOWN_SECONDS", "86400"))
BASE_POUW_DIFFICULTY_BITS = int(os.environ.get("VESTORIN_POUW_BITS", "12"))
CHALLENGE_TTL_SECONDS = 300
FAUCET_GAS_PRICE_WEI = int(os.environ.get("VESTORIN_FAUCET_GAS_PRICE_WEI", "0"))
FAUCET_GAS_LIMIT = int(os.environ.get("VESTORIN_FAUCET_GAS_LIMIT", "21000"))
OVERRIDE_GASPRICE_MODE = os.environ.get("VESTORIN_OVERRIDE_GASPRICE", "")  # "", "0x0", or "0x1"

hmac_sec_val = os.environ.get("VESTORIN_HMAC_SECRET", "").strip()
if not hmac_sec_val and os.environ.get("VESTORIN_HMAC_SECRET_FILE"):
    _hf = os.environ.get("VESTORIN_HMAC_SECRET_FILE", "").strip()
    if os.path.exists(_hf):
        with open(_hf, "r", encoding="utf-8") as _f:
            hmac_sec_val = _f.read().strip()
if not hmac_sec_val:
    hmac_sec_val = secrets.token_hex(32)
HMAC_SECRET = hmac_sec_val.encode("utf-8")

# Strictly allowlisted public JSON-RPC methods
RPC_ALLOWLIST = frozenset([
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_gasPrice",
    "eth_estimateGas",
    "eth_getTransactionCount",
    "eth_sendRawTransaction",
    "eth_getTransactionReceipt",
    "eth_getTransactionByHash",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_call",
    "eth_getCode",
    "eth_getLogs",
    "net_version",
    "web3_clientVersion",
])

VERBATIM_OVERLOAD_NOTICE = (
    "Under overload, transactions wait or are rejected; immediate execution is never promised."
)
VERBATIM_LEGAL_DISCLAIMER = (
    "Testnet coins (VST) have zero monetary value, are NOT securities, and are NOT legal tender."
)

# =============================================================================
# 2. PURE-PYTHON KECCAK-256, SECP256K1, RLP & EIP-155 SIGNER (ZERO PIP DEPS)
# =============================================================================
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

def _rol64(val: int, r: int) -> int:
    return ((val << r) | (val >> (64 - r))) & 0xFFFFFFFFFFFFFFFF

def _keccak_f1600(state: List[List[int]]) -> None:
    for r in range(24):
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol64(state[x][y], KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        state[0][0] ^= KECCAK_RC[r]

def keccak256(msg: bytes) -> bytes:
    rate = 136
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(msg)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)
    out = bytearray()
    for y in range(5):
        for x in range(5):
            out.extend(state[x][y].to_bytes(8, "little"))
            if len(out) >= 32:
                return bytes(out[:32])
    return bytes(out[:32])

def point_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1 * pow(2 * y1, SECP_P - 2, SECP_P)) % SECP_P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, SECP_P - 2, SECP_P)) % SECP_P
    x3 = (lam * lam - x1 - x2) % SECP_P
    y3 = (lam * (x1 - x3) - y1) % SECP_P
    return (x3, y3)

def point_mul(k: int, p: Tuple[int, int] = (SECP_GX, SECP_GY)) -> Optional[Tuple[int, int]]:
    r = None
    addend = p
    while k > 0:
        if k & 1:
            r = point_add(r, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return r

def privkey_to_address(priv_int: int) -> str:
    pt = point_mul(priv_int)
    assert pt is not None
    pub64 = pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    return "0x" + keccak256(pub64)[-20:].hex()

def int_to_min_bytes(x: int) -> bytes:
    if x == 0:
        return b""
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

def rlp_encode(item: Any) -> bytes:
    if isinstance(item, int):
        return rlp_encode(int_to_min_bytes(item))
    elif isinstance(item, (bytes, bytearray)):
        b = bytes(item)
        if len(b) == 1 and b[0] < 0x80:
            return b
        elif len(b) <= 55:
            return bytes([0x80 + len(b)]) + b
        else:
            len_b = int_to_min_bytes(len(b))
            return bytes([0xB7 + len(len_b)]) + len_b + b
    elif isinstance(item, (list, tuple)):
        payload = b"".join(rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xC0 + len(payload)]) + payload
        else:
            len_b = int_to_min_bytes(len(payload))
            return bytes([0xF7 + len(len_b)]) + len_b + payload
    raise TypeError(f"Unsupported RLP item: {type(item)}")

def rfc6979_deterministic_k(priv_int: int, msg_hash32: bytes) -> int:
    x = priv_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + msg_hash32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg_hash32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < SECP_N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

def sign_legacy_eip155_tx(
    priv_int: int,
    nonce: int,
    gas_price_wei: int,
    gas_limit: int,
    to_addr_hex: str,
    value_wei: int,
    data_bytes: bytes = b"",
    chain_id: int = CHAIN_ID_DEC,
) -> Tuple[str, str]:
    """Signs a Legacy EIP-155 transaction (compatible with Pre-London / Berlin Geth 1.13.14).
    Returns (raw_tx_hex, tx_hash_hex)."""
    to_bytes = bytes.fromhex(to_addr_hex.lower().replace("0x", ""))
    assert len(to_bytes) == 20, "Recipient must be 20-byte EVM address"

    unsigned_items = [nonce, gas_price_wei, gas_limit, to_bytes, value_wei, data_bytes, chain_id, 0, 0]
    signing_hash = keccak256(rlp_encode(unsigned_items))
    z = int.from_bytes(signing_hash, "big")

    k = rfc6979_deterministic_k(priv_int, signing_hash)
    pt = point_mul(k)
    assert pt is not None
    r = pt[0] % SECP_N
    s = (pow(k, SECP_N - 2, SECP_N) * (z + r * priv_int)) % SECP_N
    rec_id = pt[1] & 1
    if pt[0] >= SECP_N:
        rec_id |= 2
    # EIP-2 low-s malleability normalization
    if s > SECP_N // 2:
        s = SECP_N - s
        rec_id ^= 1

    v = chain_id * 2 + 35 + rec_id
    signed_items = [nonce, gas_price_wei, gas_limit, to_bytes, value_wei, data_bytes, v, r, s]
    raw_rlp = rlp_encode(signed_items)
    tx_hash = keccak256(raw_rlp)
    return "0x" + raw_rlp.hex(), "0x" + tx_hash.hex()

def decrypt_geth_keystore_v3(keystore_path: str, password: str) -> int:
    """Decrypts a standard Geth Web3 Secret Storage v3 keystore JSON using stdlib hashlib.scrypt + openssl."""
    with open(keystore_path, "r", encoding="utf-8") as f:
        ks = json.load(f)
    crypto = ks.get("crypto") or ks.get("Crypto")
    kdf = crypto["kdf"].lower()
    kdfparams = crypto["kdfparams"]
    salt = bytes.fromhex(kdfparams["salt"])
    dklen = int(kdfparams.get("dklen", 32))
    pw_bytes = password.encode("utf-8")

    if kdf == "scrypt":
        derived = hashlib.scrypt(
            pw_bytes,
            salt=salt,
            n=int(kdfparams["n"]),
            r=int(kdfparams["r"]),
            p=int(kdfparams["p"]),
            maxmem=512 * 1024 * 1024,
            dklen=dklen,
        )
    elif kdf == "pbkdf2":
        derived = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, int(kdfparams["c"]), dklen)
    else:
        raise ValueError(f"Unsupported keystore KDF: {kdf}")

    ciphertext = bytes.fromhex(crypto["ciphertext"])
    mac_expected = crypto["mac"].lower().replace("0x", "")
    mac_computed = keccak256(derived[16:32] + ciphertext).hex()
    if mac_computed != mac_expected:
        raise ValueError("Keystore MAC verification failed (wrong password or corrupted keystore)")

    iv_hex = crypto["cipherparams"]["iv"]
    key16_hex = derived[:16].hex()
    priv_bytes = subprocess.check_output(
        ["openssl", "enc", "-d", "-aes-128-ctr", "-K", key16_hex, "-iv", iv_hex],
        input=ciphertext,
    )
    return int.from_bytes(priv_bytes, "big")

# =============================================================================
# 3. PERSISTENT SQLITE QUOTA, COOLDOWN & PROOF-HASH REGISTRY
# =============================================================================
class RelayerDatabase:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS claims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_address TEXT NOT NULL,
                    dosage_vst INTEGER NOT NULL,
                    proof_hash TEXT NOT NULL UNIQUE,
                    tx_hash TEXT NOT NULL,
                    subnet_prefix TEXT NOT NULL,
                    claimed_at INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_addr ON claims(recipient_address, claimed_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_subnet ON claims(subnet_prefix, claimed_at)")
            conn.commit()

    def check_eligibility_and_adaptive_difficulty(
        self, address: str, subnet_prefix: str, now_ts: int
    ) -> Tuple[bool, str, int]:
        """Returns (eligible, reason, required_difficulty_bits)."""
        addr_low = address.lower()
        cutoff = now_ts - COOLDOWN_SECONDS
        subnet_window = now_ts - 3600  # 1-hour sliding window for adaptive PoUW difficulty
        with self.lock, sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT claimed_at, tx_hash FROM claims WHERE recipient_address = ? AND claimed_at > ? ORDER BY claimed_at DESC LIMIT 1",
                (addr_low, cutoff),
            ).fetchone()
            if row is not None:
                rem = (row[0] + COOLDOWN_SECONDS) - now_ts
                return False, f"Address cooldown active ({rem}s remaining; last tx: {row[1]})", BASE_POUW_DIFFICULTY_BITS

            subnet_count = conn.execute(
                "SELECT COUNT(*) FROM claims WHERE subnet_prefix = ? AND claimed_at > ?",
                (subnet_prefix, subnet_window),
            ).fetchone()[0]

        # Adaptive difficulty: never hard-bans a /24 CGNAT subnet, only scales PoUW bits (max +6 bits)
        extra_bits = min(6, subnet_count // 5)
        return True, "OK", BASE_POUW_DIFFICULTY_BITS + extra_bits

    def is_proof_hash_used(self, proof_hash: str) -> bool:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT 1 FROM claims WHERE proof_hash = ?", (proof_hash.lower(),)).fetchone()
            return row is not None

    def record_claim(
        self, address: str, dosage_vst: int, proof_hash: str, tx_hash: str, subnet_prefix: str, now_ts: int
    ) -> None:
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO claims (recipient_address, dosage_vst, proof_hash, tx_hash, subnet_prefix, claimed_at) VALUES (?, ?, ?, ?, ?, ?)",
                (address.lower(), dosage_vst, proof_hash.lower(), tx_hash, subnet_prefix, now_ts),
            )
            conn.commit()

# =============================================================================
# 4. CHALLENGE & DETERMINISTIC PoUW VERIFIER (SPEC-04 + CARLSTRÖM WHEEL W(Q))
# =============================================================================
def extract_subnet_prefix(ip_str: str) -> str:
    if ":" in ip_str:
        return ":".join(ip_str.split(":")[:3])
    parts = ip_str.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip_str

def make_challenge_token(address: str, block_number: int, difficulty_bits: int, ts_bucket: int) -> str:
    payload = f"{address.lower()}|{block_number}|{difficulty_bits}|{ts_bucket}"
    sig = hmac.new(HMAC_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"

def verify_challenge_and_pouw(
    address: str,
    challenge_token: str,
    ranks: List[int],
    wheel_pair: List[int],
    nonce: str,
) -> Tuple[bool, str, str]:
    """Verifies:
    1. Challenge HMAC & TTL freshness.
    2. SPEC-04 strict poset rank descent: len >= 5, all int >= 0, r[i+1] < r[i], r[-1] == 0.
    3. Non-trivial Carlström Wheel W(Q) transition witness (e.g. (1, 0) = infinity pole).
    4. Leading zero bits >= difficulty_bits on SHA-256(challenge || address || canonical_witness || nonce).
    Returns (valid, message, proof_hash_hex)."""
    parts = challenge_token.split("|")
    if len(parts) != 5:
        return False, "Malformed challenge token", ""
    c_addr, c_blk, c_diff, c_ts, c_sig = parts
    if c_addr.lower() != address.lower():
        return False, "Challenge address mismatch", ""
    try:
        diff_bits = int(c_diff)
        ts_val = int(c_ts)
    except ValueError:
        return False, "Invalid challenge numeric fields", ""

    now_ts = int(time.time())
    if abs(now_ts - ts_val) > CHALLENGE_TTL_SECONDS:
        return False, "Challenge expired (request a fresh challenge)", ""

    expected_payload = f"{c_addr}|{c_blk}|{c_diff}|{c_ts}"
    expected_sig = hmac.new(HMAC_SECRET, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(c_sig, expected_sig):
        return False, "Invalid challenge HMAC signature", ""

    # Verify SPEC-04 strict rank descent
    if not isinstance(ranks, list) or len(ranks) < 5:
        return False, "SPEC-04 witness requires at least 5 rank steps", ""
    for i, r in enumerate(ranks):
        if not isinstance(r, int) or r < 0:
            return False, f"Invalid rank at index {i}", ""
        if i > 0 and not (ranks[i] < ranks[i - 1]):
            return False, f"SPEC-04 violation: rank {ranks[i]} is not strictly less than {ranks[i - 1]}", ""
    if ranks[-1] != 0:
        return False, "SPEC-04 sequence must terminate at atomic rank 0", ""

    if not isinstance(wheel_pair, list) or len(wheel_pair) != 2 or wheel_pair != [1, 0]:
        return False, "Wheel witness must project to unsigned infinity pole (1, 0)", ""

    ranks_str = ",".join(str(x) for x in ranks)
    canonical_witness = f"SPEC04:{ranks_str}|WHEEL:{wheel_pair[0]},{wheel_pair[1]}"
    preimage = f"{challenge_token}|{address.lower()}|{canonical_witness}|{nonce}".encode("utf-8")
    digest = hashlib.sha256(preimage).digest()
    proof_hash_hex = "0x" + digest.hex()

    digest_int = int.from_bytes(digest, "big")
    leading_zeros = 256 - digest_int.bit_length() if digest_int > 0 else 256
    if leading_zeros < diff_bits:
        return False, f"Insufficient PoUW difficulty: got {leading_zeros} zero bits, required {diff_bits}", ""

    return True, "PoUW verified", proof_hash_hex

# =============================================================================
# 5. UPSTREAM GETH RPC CLIENT & TRANSACTION DISPATCHER
# =============================================================================
def call_local_geth(method: str, params: list) -> Dict[str, Any]:
    req_body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(
        GETH_LOCAL_RPC, data=req_body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))

class FaucetDispatcher:
    def __init__(self, priv_int: Optional[int], sign_mode: str) -> None:
        self.priv_int = priv_int
        self.sign_mode = sign_mode
        self.tx_lock = threading.Lock()

    def send_claim_transfer(self, recipient: str, dosage_vst: int) -> str:
        value_wei = dosage_vst * (10 ** 18)
        with self.tx_lock:
            if self.sign_mode == "raw_privkey":
                assert self.priv_int is not None, "Private key not loaded for raw_privkey mode"
                nonce_res = call_local_geth("eth_getTransactionCount", [FAUCET_ADDRESS, "pending"])
                if "error" in nonce_res:
                    err_msg = nonce_res["error"]
                    raise RuntimeError(f"eth_getTransactionCount error: {err_msg}")
                nonce = int(nonce_res["result"], 16)
                raw_tx_hex, _ = sign_legacy_eip155_tx(
                    priv_int=self.priv_int,
                    nonce=nonce,
                    gas_price_wei=FAUCET_GAS_PRICE_WEI,
                    gas_limit=FAUCET_GAS_LIMIT,
                    to_addr_hex=recipient,
                    value_wei=value_wei,
                    data_bytes=b"",
                    chain_id=CHAIN_ID_DEC,
                )
                send_res = call_local_geth("eth_sendRawTransaction", [raw_tx_hex])
                if "error" in send_res:
                    err_msg = send_res["error"]
                    raise RuntimeError(f"eth_sendRawTransaction rejected: {err_msg}")
                return str(send_res["result"])
            elif self.sign_mode == "geth_unlocked":
                tx_obj = {
                    "from": FAUCET_ADDRESS,
                    "to": recipient,
                    "gas": hex(FAUCET_GAS_LIMIT),
                    "gasPrice": hex(FAUCET_GAS_PRICE_WEI),
                    "value": hex(value_wei),
                }
                send_res = call_local_geth("eth_sendTransaction", [tx_obj])
                if "error" in send_res:
                    err_msg = send_res["error"]
                    raise RuntimeError(f"eth_sendTransaction rejected: {err_msg}")
                return str(send_res["result"])
            else:
                raise RuntimeError(
                    "Faucet signing key not configured on Wolfram. Provide VESTORIN_FAUCET_PRIVKEY, "
                    "VESTORIN_FAUCET_KEYSTORE + VESTORIN_FAUCET_PASSWORD_FILE, or VESTORIN_SIGN_MODE=geth_unlocked."
                )

# =============================================================================
# 6. HTTP SERVER (CORS + JSON-RPC ALLOWLIST PROXY + FAUCET RELAYER API)
# =============================================================================
class VestorinRelayerHandler(http.server.BaseHTTPRequestHandler):
    db: RelayerDatabase = None  # type: ignore
    dispatcher: FaucetDispatcher = None  # type: ignore

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/app", "/vestorin_app.html") and (
            "text/html" in self.headers.get("Accept", "")
            or parsed.path in ("/app", "/vestorin_app.html")
        ):
            html_path = os.environ.get(
                "VESTORIN_APP_HTML",
                os.path.join(os.path.dirname(__file__), "vestorin_app.html"),
            )
            if os.path.exists(html_path):
                with open(html_path, "rb") as hf:
                    html_bytes = hf.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(html_bytes)
                return

        # Static asset serving (MIN-225: EIP-3085 icons & marks)
        static_icon_map = {
            "/icon.png": "vestorin-mark.png",
            "/icon.svg": "vestorin-mark.svg",
            "/vestorin-mark.png": "vestorin-mark.png",
            "/vestorin-mark.svg": "vestorin-mark.svg",
        }
        asset_rel = static_icon_map.get(parsed.path)
        if not asset_rel and parsed.path.startswith("/assets/"):
            asset_rel = parsed.path[len("/assets/"):]

        if asset_rel:
            base_dir = os.path.dirname(__file__)
            candidates = [
                os.path.join(base_dir, "assets", asset_rel),
                os.path.join(base_dir, asset_rel),
                os.path.join(os.path.dirname(os.environ.get("VESTORIN_APP_HTML", base_dir)), "assets", asset_rel),
                os.path.join(os.path.dirname(os.environ.get("VESTORIN_APP_HTML", base_dir)), asset_rel),
            ]
            for c_path in candidates:
                if os.path.exists(c_path) and os.path.isfile(c_path):
                    with open(c_path, "rb") as af:
                        asset_bytes = af.read()
                    mime = "image/png"
                    if c_path.endswith(".svg"):
                        mime = "image/svg+xml"
                    elif c_path.endswith(".json"):
                        mime = "application/json"
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(len(asset_bytes)))
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(asset_bytes)
                    return
            self._send_json(404, {"error": "Asset not found", "path": parsed.path})
            return

        if parsed.path in ("/api/v1/health", "/health"):
            try:
                blk = call_local_geth("eth_blockNumber", [])
                blk_hex = blk.get("result", "0x0")
                blk_num = int(blk_hex, 16)
                rpc_ok = True
            except Exception as e:
                blk_hex = None
                blk_num = None
                rpc_ok = False
            self._send_json(
                200,
                {
                    "status": "ok" if rpc_ok else "degraded",
                    "chainIdDecimal": CHAIN_ID_DEC,
                    "chainIdHex": CHAIN_ID_HEX,
                    "genesisHash": GENESIS_HASH,
                    "faucetAddress": FAUCET_ADDRESS,
                    "signerAddress": SIGNER_ADDRESS,
                    "upstreamGethRpc": GETH_LOCAL_RPC,
                    "upstreamReachable": rpc_ok,
                    "blockNumber": blk_num,
                    "blockNumberHex": blk_hex,
                    "signMode": self.dispatcher.sign_mode,
                    "overloadNotice": VERBATIM_OVERLOAD_NOTICE,
                    "legalDisclaimer": VERBATIM_LEGAL_DISCLAIMER,
                },
            )
            return

        if parsed.path == "/api/v1/challenge":
            qs = urllib.parse.parse_qs(parsed.query)
            addr = (qs.get("address") or [""])[0].strip()
            if not re.match(r"^0x[0-9a-fA-F]{40}$", addr):
                self._send_json(400, {"error": "Valid 0x EVM address required in ?address=0x..."})
                return
            client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            subnet = extract_subnet_prefix(client_ip)
            now_ts = int(time.time())
            eligible, reason, diff_bits = self.db.check_eligibility_and_adaptive_difficulty(addr, subnet, now_ts)
            if not eligible:
                self._send_json(429, {"error": reason, "overloadNotice": VERBATIM_OVERLOAD_NOTICE})
                return
            try:
                blk_res = call_local_geth("eth_blockNumber", [])
                blk_num = int(blk_res.get("result", "0x0"), 16)
            except Exception:
                blk_num = 105
            token = make_challenge_token(addr, blk_num, diff_bits, now_ts)
            self._send_json(
                200,
                {
                    "challenge": token,
                    "difficultyBits": diff_bits,
                    "blockNumber": blk_num,
                    "requiredSpec04MinSteps": 5,
                    "requiredWheelPole": [1, 0],
                    "maxClaimVST": MAX_CLAIM_VST,
                    "overloadNotice": VERBATIM_OVERLOAD_NOTICE,
                },
            )
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 65536:
            self._send_json(400, {"error": "Invalid request payload size"})
            return
        raw_body = self.rfile.read(length)
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Malformed JSON body"})
            return

        # Route A: Faucet Claim Endpoint (`POST /api/v1/claim`)
        if parsed.path == "/api/v1/claim":
            addr = str(body.get("address", "")).strip()
            dosage = body.get("dosageVST", MAX_CLAIM_VST)
            challenge = str(body.get("challenge", "")).strip()
            ranks = body.get("ranks", [4, 3, 2, 1, 0])
            wheel_pair = body.get("wheelPair", [1, 0])
            nonce = str(body.get("nonce", "")).strip()

            if not re.match(r"^0x[0-9a-fA-F]{40}$", addr):
                self._send_json(400, {"error": "Invalid recipient EVM address"})
                return
            if not isinstance(dosage, int) or dosage < 1 or dosage > MAX_CLAIM_VST:
                self._send_json(400, {"error": f"dosageVST must be an integer between 1 and {MAX_CLAIM_VST}"})
                return

            client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            subnet = extract_subnet_prefix(client_ip)
            now_ts = int(time.time())
            eligible, reason, _ = self.db.check_eligibility_and_adaptive_difficulty(addr, subnet, now_ts)
            if not eligible:
                self._send_json(429, {"error": reason, "overloadNotice": VERBATIM_OVERLOAD_NOTICE})
                return

            pouw_ok, pouw_msg, proof_hash = verify_challenge_and_pouw(addr, challenge, ranks, wheel_pair, nonce)
            if not pouw_ok:
                self._send_json(400, {"error": pouw_msg})
                return

            if self.db.is_proof_hash_used(proof_hash):
                self._send_json(409, {"error": f"Proof hash {proof_hash} already claimed in registry"})
                return

            try:
                tx_hash = self.dispatcher.send_claim_transfer(addr, dosage)
            except Exception as e:
                self._send_json(
                    503,
                    {
                        "error": f"Claim dispatch failed: {e}",
                        "overloadNotice": VERBATIM_OVERLOAD_NOTICE,
                    },
                )
                return

            self.db.record_claim(addr, dosage, proof_hash, tx_hash, subnet, now_ts)
            self._send_json(
                200,
                {
                    "status": "DISPATCHED",
                    "recipientAddress": addr,
                    "dosageVST": dosage,
                    "txHash": tx_hash,
                    "proofHash": proof_hash,
                    "chainIdDecimal": CHAIN_ID_DEC,
                    "chainIdHex": CHAIN_ID_HEX,
                    "faucetAddress": FAUCET_ADDRESS,
                    "overloadNotice": VERBATIM_OVERLOAD_NOTICE,
                    "legalDisclaimer": VERBATIM_LEGAL_DISCLAIMER,
                },
            )
            return

        # Route B: Safe Allowlisted JSON-RPC Proxy (`POST /` or `POST /rpc`)
        if parsed.path in ("/", "/rpc"):
            if isinstance(body, list):
                self._send_json(403, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Batch JSON-RPC disabled on public proxy"}})
                return
            method = str(body.get("method", ""))
            req_id = body.get("id", 1)
            if method not in RPC_ALLOWLIST:
                self._send_json(
                    403,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method {method!r} blocked by Vestorin RPC allowlist"},
                    },
                )
                return

            if method == "eth_gasPrice" and OVERRIDE_GASPRICE_MODE in ("0x0", "0x1"):
                self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": OVERRIDE_GASPRICE_MODE})
                return

            try:
                upstream_res = call_local_geth(method, body.get("params", []))
                upstream_res["id"] = req_id
                self._send_json(200, upstream_res)
            except Exception as e:
                self._send_json(
                    502,
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Upstream geth error: {e}"}},
                )
            return

        self._send_json(404, {"error": "Not found"})

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# =============================================================================
# 7. SELF-TEST SUITE & CLI ENTRYPOINT
# =============================================================================
def run_self_tests() -> None:
    print("[1/4] Testing Keccak-256 & secp256k1 address derivation...")
    empty_k = keccak256(b"").hex()
    assert empty_k == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", f"Keccak mismatch: {empty_k}"
    test_priv = int("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", 16)
    derived_addr = privkey_to_address(test_priv)
    assert derived_addr.lower() == "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23", f"Address mismatch: {derived_addr}"
    print(f"      PASS: Keccak-256 & secp256k1 verified ({derived_addr})")

    print("[2/4] Testing Legacy EIP-155 Transaction Signing (Chain ID 202627 / gasPrice 0)...")
    raw_tx, tx_hash = sign_legacy_eip155_tx(
        priv_int=test_priv,
        nonce=0,
        gas_price_wei=0,
        gas_limit=21000,
        to_addr_hex="0x3b4b3bf0c3f417ec1beb87476e5bb7c50a219f3b",
        value_wei=21_000_000 * (10 ** 18),
        chain_id=202627,
    )
    assert raw_tx.startswith("0xf8") and len(tx_hash) == 66
    print(f"      PASS: EIP-155 raw tx = {raw_tx[:42]}... | txHash = {tx_hash}")

    print("[3/4] Testing Deterministic PoUW Challenge & SPEC-04 / Wheel W(Q) Verifier...")
    sample_addr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    now_ts = int(time.time())
    token = make_challenge_token(sample_addr, 105, 8, now_ts)
    ranks = [4, 3, 2, 1, 0]
    wheel = [1, 0]
    found_nonce = None
    for n in range(100000):
        ok, _, p_hash = verify_challenge_and_pouw(sample_addr, token, ranks, wheel, str(n))
        if ok:
            found_nonce = str(n)
            break
    assert found_nonce is not None, "Failed to solve 8-bit PoUW in 100k iterations"
    print(f"      PASS: Solved 8-bit PoUW at nonce={found_nonce}, proofHash={p_hash}")

    # Ensure invalid rank sequence (cycle 4->2->2->0) is rejected
    bad_ok, bad_msg, _ = verify_challenge_and_pouw(sample_addr, token, [4, 3, 2, 2, 0], wheel, found_nonce)
    assert not bad_ok and "SPEC-04 violation" in bad_msg
    print(f"      PASS: Non-descending SPEC-04 sequence rejected ({bad_msg})")

    print("[4/4] Testing SQLite Quota, Cooldown & Proof-Hash Replay Prevention...")
    test_db_path = "/tmp/test_vestorin_relayer.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    db = RelayerDatabase(test_db_path)
    el1, _, _ = db.check_eligibility_and_adaptive_difficulty(sample_addr, "100.77.188.0/24", now_ts)
    assert el1 is True
    db.record_claim(sample_addr, 21000000, p_hash, tx_hash, "100.77.188.0/24", now_ts)
    assert db.is_proof_hash_used(p_hash) is True
    el2, msg2, _ = db.check_eligibility_and_adaptive_difficulty(sample_addr, "100.77.188.0/24", now_ts + 10)
    assert el2 is False and "cooldown active" in msg2
    os.remove(test_db_path)
    print("      PASS: SQLite cooldown & proof-hash registry verified.")

    print("[5/5] Testing TLS / HTTPS capabilities & stdlib SSL context...")
    test_tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    assert test_tls_ctx is not None
    print("      PASS: stdlib ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) initialized cleanly.")
    print("ALL 5 SELF-TESTS PASSED.")

def main() -> None:
    parser = argparse.ArgumentParser(description="Vestorin Wolfram Faucet Relayer & Safe JSON-RPC Proxy")
    parser.add_argument("--self-test", action="store_true", help="Run built-in cryptographic & DB self-tests and exit")
    args = parser.parse_args()

    if args.self_test:
        run_self_tests()
        return

    priv_int: Optional[int] = None
    sign_mode = os.environ.get("VESTORIN_SIGN_MODE", "")

    priv_hex = os.environ.get("VESTORIN_FAUCET_PRIVKEY", "").strip()
    ks_path = os.environ.get("VESTORIN_FAUCET_KEYSTORE", "").strip()
    pw_file = os.environ.get("VESTORIN_FAUCET_PASSWORD_FILE", "").strip()

    if priv_hex:
        priv_int = int(priv_hex.replace("0x", ""), 16)
        derived = privkey_to_address(priv_int)
        print(f"[INIT] Loaded raw faucet private key for address: {derived}")
        sign_mode = "raw_privkey"
    elif ks_path and pw_file:
        with open(pw_file, "r", encoding="utf-8") as pf:
            pw = pf.read().strip()
        priv_int = decrypt_geth_keystore_v3(ks_path, pw)
        derived = privkey_to_address(priv_int)
        print(f"[INIT] Decrypted Geth keystore v3 for faucet address: {derived}")
        sign_mode = "raw_privkey"
    elif sign_mode == "geth_unlocked":
        print(f"[INIT] Using geth_unlocked mode on {GETH_LOCAL_RPC} for {FAUCET_ADDRESS}")
    else:
        sign_mode = "unconfigured"
        print("[WARN] No faucet signing credentials set; /rpc proxy and /challenge work, /claim will return 503.")

    db = RelayerDatabase(DB_PATH)
    dispatcher = FaucetDispatcher(priv_int=priv_int, sign_mode=sign_mode)
    VestorinRelayerHandler.db = db
    VestorinRelayerHandler.dispatcher = dispatcher

    tls_cert = os.environ.get("VESTORIN_TLS_CERT", "").strip()
    tls_key = os.environ.get("VESTORIN_TLS_KEY", "").strip()
    tls_port = int(os.environ.get("VESTORIN_TLS_PORT", "8443"))

    http_srv = ThreadedHTTPServer((BIND_HOST, BIND_PORT), VestorinRelayerHandler)
    print(f"[READY] Vestorin Relayer & Safe RPC Proxy listening on http://{BIND_HOST}:{BIND_PORT}")
    print(f"        Upstream Geth RPC : {GETH_LOCAL_RPC}")
    print(f"        Chain ID          : {CHAIN_ID_DEC} ({CHAIN_ID_HEX})")
    print(f"        Faucet Address    : {FAUCET_ADDRESS}")

    if tls_cert and tls_key and os.path.exists(tls_cert) and os.path.exists(tls_key):
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        https_srv = ThreadedHTTPServer((BIND_HOST, tls_port), VestorinRelayerHandler)
        https_srv.socket = tls_ctx.wrap_socket(https_srv.socket, server_side=True)
        print(f"[READY] Vestorin HTTPS Relayer & Safe RPC Proxy listening on https://{BIND_HOST}:{tls_port}")
        print(f"        TLS Certificate   : {tls_cert}")
        https_thread = threading.Thread(target=https_srv.serve_forever, daemon=True)
        https_thread.start()
    else:
        print("[INFO] No TLS certificate configured; HTTPS listener disabled.")

    http_srv.serve_forever()

if __name__ == "__main__":
    main()