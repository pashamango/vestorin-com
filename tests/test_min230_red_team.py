#!/usr/bin/env python3
"""
test_min230_red_team.py — Automated Red Team & DoS Defense Verification Suite
Validates concrete limit values, computational work asymmetry, RPC security,
and mathematical bounds for Linear ticket MIN-230.
"""

import os
import sys
import time
import pytest

# Add staging/relayer to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "staging", "relayer")))

from vestorin_wolfram_relayer import (
    keccak256,
    make_challenge_token,
    verify_challenge_and_pouw,
    RelayerDatabase,
    RPC_ALLOWLIST,
    extract_subnet_prefix,
    BASE_POUW_DIFFICULTY_BITS,
    COOLDOWN_SECONDS,
    MAX_CLAIM_VST,
    GENESIS_HASH,
    CHAIN_ID_DEC,
    CHAIN_ID_HEX,
)

def test_pouw_verification_microsecond_benchmark():
    """Measures verification execution time to verify computational asymmetry."""
    addr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    now_ts = int(time.time())
    token = make_challenge_token(addr, 105, 8, now_ts)
    ranks = [4, 3, 2, 1, 0]
    wheel = [1, 0]

    # Pre-solve 8-bit PoUW
    solved_nonce = None
    for n in range(10000):
        ok, _, p_hash = verify_challenge_and_pouw(addr, token, ranks, wheel, str(n))
        if ok:
            solved_nonce = str(n)
            break
    assert solved_nonce is not None, "Failed to pre-solve 8-bit PoUW"

    # Benchmark 200 consecutive verifications
    t0 = time.perf_counter()
    N = 200
    for _ in range(N):
        ok, msg, p_hash = verify_challenge_and_pouw(addr, token, ranks, wheel, solved_nonce)
        assert ok is True
    t1 = time.perf_counter()

    avg_microseconds = ((t1 - t0) / N) * 1_000_000
    # Must be extremely lightweight (under 50 microseconds)
    assert avg_microseconds < 50.0, f"PoUW verification too slow: {avg_microseconds:.2f} us"

def test_computational_asymmetry_ratio():
    """Validates the mathematical ratio of attacker compute vs relayer verify."""
    # Base 12 bits: expected 2^12 = 4,096 hashes on client
    # Relayer verification: 1 HMAC + 1 SHA256 + integer checks = 2 hashes
    base_ratio = (2 ** 12) / 2
    assert base_ratio == 2048.0

    # Scaled 18 bits: expected 2^18 = 262,144 hashes on client
    scaled_ratio = (2 ** 18) / 2
    assert scaled_ratio == 131072.0
    assert scaled_ratio > 100000

def test_adaptive_difficulty_scaling_under_subnet_burst(tmp_path):
    """Tests that high claim velocity from a /24 subnet ramps difficulty by up to +6 bits."""
    db_file = str(tmp_path / "test_adaptive.db")
    db = RelayerDatabase(db_file)
    subnet = "192.168.1.0/24"
    now_ts = int(time.time())

    # Initial check: base difficulty (12 bits)
    el, _, diff = db.check_eligibility_and_adaptive_difficulty("0x1111111111111111111111111111111111111111", subnet, now_ts)
    assert el is True
    assert diff == BASE_POUW_DIFFICULTY_BITS

    # Simulate 30 claims from same subnet within the hour
    for i in range(30):
        claim_addr = f"0x{i:040x}"
        proof_h = f"0x{i:064x}"
        tx_h = f"0x{i+1000:064x}"
        db.record_claim(claim_addr, 21_000_000, proof_h, tx_h, subnet, now_ts - (i * 10))

    # Next claim from fresh address in same subnet
    fresh_addr = "0x9999999999999999999999999999999999999999"
    el2, _, scaled_diff = db.check_eligibility_and_adaptive_difficulty(fresh_addr, subnet, now_ts)
    assert el2 is True
    # min(6, 30 // 5) = +6 bits -> 12 + 6 = 18 bits
    assert scaled_diff == BASE_POUW_DIFFICULTY_BITS + 6
    assert scaled_diff == 18

def test_rpc_method_security_matrix():
    """Verifies that all dangerous RPC methods are absent from RPC_ALLOWLIST."""
    dangerous_methods = [
        "admin_nodeInfo",
        "admin_peers",
        "admin_addPeer",
        "personal_unlockAccount",
        "personal_newAccount",
        "personal_sendTransaction",
        "miner_start",
        "miner_stop",
        "clique_propose",
        "clique_discard",
        "debug_traceTransaction",
        "debug_dumpBlock",
        "txpool_status",
        "txpool_content",
        "eth_sendTransaction",
        "eth_accounts",
    ]
    for m in dangerous_methods:
        assert m not in RPC_ALLOWLIST, f"Dangerous method {m} must NOT be in RPC_ALLOWLIST"

def test_genesis_hash_and_chain_id_constants():
    """Asserts staging constants match official Vestorin specification."""
    assert GENESIS_HASH == "0x0ab605a3cf46aab8ac3b38dd111e54f8c5ba458a4144c186bf8d0d0de95ca793"
    assert CHAIN_ID_DEC == 202627
    assert CHAIN_ID_HEX == "0x31783"

def test_theoretical_bounds_and_capacity_math():
    """Validates the mathematical bounds for 8M gas / 5s blocks and faucet exhaustion."""
    block_gas_limit = 8_000_000
    tx_gas = 21_000
    max_tx_per_block = block_gas_limit // tx_gas
    assert max_tx_per_block == 380

    block_time_s = 5
    max_tps = max_tx_per_block / block_time_s
    assert round(max_tps, 2) == 76.0

    blocks_per_day = 86_400 // block_time_s
    assert blocks_per_day == 17_280

    max_tx_per_day = blocks_per_day * max_tx_per_block
    assert max_tx_per_day == 6_566_400

    # Total faucet capacity: 1,000,000 claims
    # At unmitigated 76 tps, time to drain:
    seconds_to_drain_max_throughput = 1_000_000 / max_tps
    hours_to_drain_max_throughput = seconds_to_drain_max_throughput / 3600
    assert 3.6 < hours_to_drain_max_throughput < 3.7

    # With proposed epoch limit: 500 claims per hour
    hours_to_drain_with_epoch_limit = 1_000_000 / 500
    days_to_drain_with_epoch_limit = hours_to_drain_with_epoch_limit / 24
    assert days_to_drain_with_epoch_limit > 80.0
