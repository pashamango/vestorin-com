#!/usr/bin/env python3
"""
Unit and integration test suite for Vestorin Wolfram Staging Relayer & HTTPS Server.
Addresses MIN-227 acceptance criteria and QA verification gates.
"""

import os
import sys
import time
import ssl
import subprocess
import pytest

# Add staging/relayer to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "staging", "relayer")))

from vestorin_wolfram_relayer import (
    keccak256,
    privkey_to_address,
    sign_legacy_eip155_tx,
    make_challenge_token,
    verify_challenge_and_pouw,
    RelayerDatabase,
    RPC_ALLOWLIST,
    extract_subnet_prefix,
    BASE_POUW_DIFFICULTY_BITS,
    COOLDOWN_SECONDS,
    MAX_CLAIM_VST,
)

def test_keccak_and_secp256k1():
    empty_k = keccak256(b"").hex()
    assert empty_k == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    test_priv = int("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", 16)
    derived = privkey_to_address(test_priv)
    assert derived.lower() == "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"

def test_eip155_tx_signing():
    test_priv = int("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", 16)
    raw_tx, tx_hash = sign_legacy_eip155_tx(
        priv_int=test_priv,
        nonce=0,
        gas_price_wei=0,
        gas_limit=21000,
        to_addr_hex="0x3b4b3bf0c3f417ec1beb87476e5bb7c50a219f3b",
        value_wei=21_000_000 * (10 ** 18),
        chain_id=202627,
    )
    assert raw_tx.startswith("0xf8")
    assert len(tx_hash) == 66
    assert tx_hash.startswith("0x")

def test_pouw_challenge_and_verification():
    sample_addr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    now_ts = int(time.time())
    token = make_challenge_token(sample_addr, 105, 8, now_ts)
    ranks = [4, 3, 2, 1, 0]
    wheel = [1, 0]
    found = False
    for n in range(50000):
        ok, _, p_hash = verify_challenge_and_pouw(sample_addr, token, ranks, wheel, str(n))
        if ok:
            found = True
            assert p_hash.startswith("0x")
            break
    assert found, "Expected to solve 8-bit PoUW challenge"

def test_spec04_non_descending_rejected():
    sample_addr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    now_ts = int(time.time())
    token = make_challenge_token(sample_addr, 105, 8, now_ts)
    bad_ranks = [4, 3, 2, 2, 0]
    ok, msg, _ = verify_challenge_and_pouw(sample_addr, token, bad_ranks, [1, 0], "0")
    assert not ok
    assert "SPEC-04 violation" in msg

def test_sqlite_cooldown_and_replay_prevention(tmp_path):
    db_file = str(tmp_path / "test_state.db")
    db = RelayerDatabase(db_file)
    sample_addr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    now_ts = int(time.time())

    el1, _, _ = db.check_eligibility_and_adaptive_difficulty(sample_addr, "100.77.188.0/24", now_ts)
    assert el1 is True

    proof_hash = "0x" + "a" * 64
    tx_hash = "0x" + "b" * 64
    db.record_claim(sample_addr, 21000000, proof_hash, tx_hash, "100.77.188.0/24", now_ts)

    assert db.is_proof_hash_used(proof_hash) is True
    assert db.is_proof_hash_used("0x" + "c" * 64) is False

    el2, reason, _ = db.check_eligibility_and_adaptive_difficulty(sample_addr, "100.77.188.0/24", now_ts + 10)
    assert el2 is False
    assert "cooldown active" in reason

def test_tls_context_certificate_loading_and_handshake(tmp_path):
    cert_path = str(tmp_path / "test_cert.pem")
    key_path = str(tmp_path / "test_key.pem")

    staging_cert = "/Users/pavelcherkashin/.certbot/config/live/app-staging.vestorin.com/fullchain.pem"
    staging_key = "/Users/pavelcherkashin/.certbot/config/live/app-staging.vestorin.com/privkey.pem"
    using_staging = os.path.exists(staging_cert) and os.path.exists(staging_key)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if using_staging:
        server_ctx.load_cert_chain(certfile=staging_cert, keyfile=staging_key)
    else:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path, "-out", cert_path, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    client_ctx = ssl.create_default_context()
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE

    c_to_s = ssl.MemoryBIO()
    s_to_c = ssl.MemoryBIO()
    server_ssl = server_ctx.wrap_bio(incoming=c_to_s, outgoing=s_to_c, server_side=True)
    client_ssl = client_ctx.wrap_bio(incoming=s_to_c, outgoing=c_to_s, server_side=False)

    for _ in range(12):
        try:
            client_ssl.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        try:
            server_ssl.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass

    cipher = client_ssl.cipher()
    assert cipher is not None
    assert client_ssl.version() in ("TLSv1.3", "TLSv1.2")

def test_rpc_allowlist_security():
    assert "eth_chainId" in RPC_ALLOWLIST
    assert "eth_blockNumber" in RPC_ALLOWLIST
    assert "eth_sendRawTransaction" in RPC_ALLOWLIST
    assert "admin_nodeInfo" not in RPC_ALLOWLIST
    assert "personal_unlockAccount" not in RPC_ALLOWLIST
    assert "eth_sendTransaction" not in RPC_ALLOWLIST

def test_frontend_banner_contract():
    html_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "staging", "relayer", "vestorin_app.html"))
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Assert strict check window.isSecureContext === true is present
    assert "const isSecure = window.isSecureContext === true;" in content
    # Assert loose check window.isSecureContext || window.location.protocol === 'https:' is removed
    assert "(window.isSecureContext || window.location.protocol === 'https:')" not in content
    # Assert unverified claims were purged
    assert "Hardware Acceleration Active" not in content
    assert "trusted Let's Encrypt TLS certificate" not in content
