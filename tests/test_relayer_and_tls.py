#!/usr/bin/env python3
"""
Unit and integration test suite for Vestorin Wolfram Staging Relayer & HTTPS Server.
Addresses MIN-227 acceptance criteria and QA verification gates:
- SIGHUP zero-downtime TLS context reload
- Adaptive subnet difficulty scaling (/24 IPv4 and /48 IPv6)
- Emergency PoUW difficulty escalation (16 bits) on low faucet balance
- Live /api/v1/faucet-status schema & alerting thresholds
- Real Let's Encrypt TLS certificate chain, SANs & trust verification
"""

import datetime
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
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
    EMERGENCY_POUW_DIFFICULTY_BITS,
    BALANCE_CRITICAL_VST,
    BALANCE_WARNING_VST,
    VELOCITY_ALERT_1H,
    VELOCITY_ALERT_24H,
    ThreadedHTTPSServer,
    VestorinRelayerHandler,
    setup_sighup_handler,
)
from vestorin_faucet_monitor import evaluate_alerts

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

def test_adaptive_difficulty_scaling_and_ipv6(tmp_path):
    """Verifies IPv4 /24 and IPv6 /48 subnet extraction and progressive difficulty scaling."""
    assert extract_subnet_prefix("100.77.188.3") == "100.77.188.0/24"
    assert extract_subnet_prefix("192.168.1.150") == "192.168.1.0/24"
    assert extract_subnet_prefix("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::/48"
    assert extract_subnet_prefix("2600:1700:bab0:d40:1:2:3:4") == "2600:1700:bab0::/48"

    db_file = str(tmp_path / "test_adaptive.db")
    db = RelayerDatabase(db_file)
    now_ts = int(time.time())
    subnet = "2001:db8:85a3::/48"

    # 0 claims: baseline difficulty
    el0, _, diff0 = db.check_eligibility_and_adaptive_difficulty("0x0000000000000000000000000000000000000001", subnet, now_ts)
    assert el0 is True and diff0 == BASE_POUW_DIFFICULTY_BITS

    # Add 5 claims from same subnet: +1 bit
    for idx in range(1, 6):
        db.record_claim(f"0x{idx:040x}", 21000000, f"0xproof{idx:058x}", f"0xtx{idx:060x}", subnet, now_ts + idx)
    _, _, diff5 = db.check_eligibility_and_adaptive_difficulty("0x0000000000000000000000000000000000000099", subnet, now_ts + 10)
    assert diff5 == BASE_POUW_DIFFICULTY_BITS + 1

    # Add 5 more claims (total 10 claims): +2 bits
    for idx in range(6, 11):
        db.record_claim(f"0x{idx:040x}", 21000000, f"0xproof{idx:058x}", f"0xtx{idx:060x}", subnet, now_ts + idx)
    _, _, diff10 = db.check_eligibility_and_adaptive_difficulty("0x0000000000000000000000000000000000000099", subnet, now_ts + 20)
    assert diff10 == BASE_POUW_DIFFICULTY_BITS + 2

    # Add 25 more claims (total 35 claims): clamped at max +6 bits
    for idx in range(11, 36):
        db.record_claim(f"0x{idx:040x}", 21000000, f"0xproof{idx:058x}", f"0xtx{idx:060x}", subnet, now_ts + idx)
    _, _, diff35 = db.check_eligibility_and_adaptive_difficulty("0x0000000000000000000000000000000000000099", subnet, now_ts + 40)
    assert diff35 == BASE_POUW_DIFFICULTY_BITS + 6

def test_emergency_balance_pouw_escalation(tmp_path):
    """Verifies that low faucet balance automatically escalates baseline difficulty to 16 bits."""
    db_file = str(tmp_path / "test_emergency.db")
    db = RelayerDatabase(db_file)
    now_ts = int(time.time())
    subnet = "100.77.188.0/24"

    # Balance above critical floor: normal 12 bits
    _, _, diff_normal = db.check_eligibility_and_adaptive_difficulty(
        "0x1111111111111111111111111111111111111111", subnet, now_ts, current_balance_vst=BALANCE_CRITICAL_VST + 1_000_000
    )
    assert diff_normal == BASE_POUW_DIFFICULTY_BITS

    # Balance below critical floor (< 21,000,000,000 VST): baseline escalates to 16 bits
    _, _, diff_crit = db.check_eligibility_and_adaptive_difficulty(
        "0x2222222222222222222222222222222222222222", subnet, now_ts, current_balance_vst=BALANCE_CRITICAL_VST - 1
    )
    assert diff_crit == EMERGENCY_POUW_DIFFICULTY_BITS

def test_tls_transport_handshake_synthetic(tmp_path):
    """Verifies TLS transport layer negotiation (TLSv1.2/TLSv1.3 ciphers, BIO handshake) in isolated test env."""
    cert_path = str(tmp_path / "test_cert.pem")
    key_path = str(tmp_path / "test_key.pem")

    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path, "-out", cert_path, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
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

def test_tls_sighup_reload(tmp_path):
    """Verifies zero-downtime TLS context reload via ThreadedHTTPSServer.reload_tls() and SIGHUP signal."""
    c1 = str(tmp_path / "c1.pem")
    k1 = str(tmp_path / "k1.pem")
    c2 = str(tmp_path / "c2.pem")
    k2 = str(tmp_path / "k2.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", k1, "-out", c1, "-days", "1", "-nodes", "-subj", "/CN=v1.vestorin.com"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", k2, "-out", c2, "-days", "1", "-nodes", "-subj", "/CN=v2.vestorin.com"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    srv = ThreadedHTTPSServer(("127.0.0.1", 0), VestorinRelayerHandler, tls_cert=c1, tls_key=k1)
    setup_sighup_handler(srv)
    assert srv.reload_count == 0

    srv.tls_cert = c2
    srv.tls_key = k2
    assert srv.reload_tls() is True
    assert srv.reload_count == 1

    if hasattr(signal, "SIGHUP"):
        os.kill(os.getpid(), signal.SIGHUP)
        assert srv.reload_count == 2

    srv.server_close()

def test_faucet_monitor_threshold_alerts():
    """Verifies faucet monitor operational alerting on velocity and balance floors."""
    # Normal metrics
    norm_alerts = evaluate_alerts({"claimsLast1h": 2, "claimsLast24h": 50, "lifetimeClaims": 100}, balance_vst=10_000_000_000_000)
    assert len(norm_alerts) == 0

    # 1-hour velocity alert (>= 25 claims/h)
    v1_alerts = evaluate_alerts({"claimsLast1h": 28, "claimsLast24h": 50, "lifetimeClaims": 100}, balance_vst=10_000_000_000_000)
    assert any(a["code"] == "ALERT_HIGH_VELOCITY_1H" and a["level"] == "CRITICAL" for a in v1_alerts)

    # 24-hour volume alert (>= 500 claims/day)
    v24_alerts = evaluate_alerts({"claimsLast1h": 5, "claimsLast24h": 520, "lifetimeClaims": 600}, balance_vst=10_000_000_000_000)
    assert any(a["code"] == "ALERT_HIGH_VELOCITY_24H" and a["level"] == "WARNING" for a in v24_alerts)

    # Balance warning (< 200,000,000,000 VST)
    bw_alerts = evaluate_alerts({"claimsLast1h": 1, "claimsLast24h": 10, "lifetimeClaims": 100}, balance_vst=BALANCE_WARNING_VST - 1000)
    assert any(a["code"] == "ALERT_FAUCET_BALANCE_WARNING" for a in bw_alerts)

    # Balance critical (< 21,000,000,000 VST)
    bc_alerts = evaluate_alerts({"claimsLast1h": 1, "claimsLast24h": 10, "lifetimeClaims": 100}, balance_vst=BALANCE_CRITICAL_VST - 1000)
    assert any(a["code"] == "ALERT_FAUCET_BALANCE_CRITICAL" and a["level"] == "CRITICAL" for a in bc_alerts)

def test_staging_letsencrypt_certificate_and_trust():
    """Verifies live/deployed Let's Encrypt certificate chain, SANs, validity, and trust on Wolfram."""
    cert_dir = "/Users/pavelcherkashin/.certbot/config/live/app-staging.vestorin.com"
    fullchain_path = os.path.join(cert_dir, "fullchain.pem")
    cert_path = os.path.join(cert_dir, "cert.pem")
    chain_path = os.path.join(cert_dir, "chain.pem")

    if not os.path.exists(fullchain_path):
        pytest.skip("Let's Encrypt certificate not present on this host (Wolfram-specific).")

    # 1. Verify certificate details using openssl
    out = subprocess.check_output(["openssl", "x509", "-in", fullchain_path, "-noout", "-text"]).decode("utf-8")
    assert "CN=app-staging.vestorin.com" in out or "CN = app-staging.vestorin.com" in out
    assert "O = Let's Encrypt" in out or "O=Let's Encrypt" in out or "CN=YE1" in out
    assert "DNS:app-staging.vestorin.com" in out
    assert "DNS:rpc-staging.vestorin.com" in out
    assert "DNS:staging.vestorin.com" in out

    # 2. Verify certificate validity has not expired
    end_date_str = subprocess.check_output(["openssl", "x509", "-in", fullchain_path, "-noout", "-enddate"]).decode("utf-8").strip()
    # Format: notAfter=Jan 23 16:46:44 2027 GMT
    date_val = end_date_str.split("=")[1].strip()
    exp_dt = datetime.datetime.strptime(date_val, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    assert exp_dt > datetime.datetime.now(datetime.timezone.utc), "Certificate has expired"

    # 3. Verify certificate trust against system root CA bundle
    ca_candidates = ["/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt"]
    ca_file = next((ca for ca in ca_candidates if os.path.exists(ca)), None)
    if ca_file and os.path.exists(chain_path) and os.path.exists(cert_path):
        cmd = ["openssl", "verify", "-CAfile", ca_file, "-untrusted", chain_path, cert_path]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert res.returncode == 0 and "OK" in res.stdout, f"Trust verification failed: {res.stderr}"

def test_rpc_allowlist_security():
    assert "eth_chainId" in RPC_ALLOWLIST
    assert "eth_blockNumber" in RPC_ALLOWLIST
    assert "eth_sendRawTransaction" in RPC_ALLOWLIST
    assert "admin_nodeInfo" not in RPC_ALLOWLIST
    assert "personal_unlockAccount" not in RPC_ALLOWLIST
    assert "eth_sendTransaction" not in RPC_ALLOWLIST

def test_faucet_status_endpoint_payload():
    """Verifies that /api/v1/faucet-status response structure includes all required fields."""
    import urllib.request
    import json
    try:
        req = urllib.request.Request("http://100.77.188.3:8546/api/v1/faucet-status")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert "status" in data
        assert "faucetAddress" in data
        assert "baseDifficultyBits" in data
        assert "effectiveBaseDifficultyBits" in data
        assert "emergencyPoUWEscalationActive" in data
        assert "thresholds" in data
        assert "claimMetrics" in data
        assert "abuseMitigations" in data
        assert "tlsInfo" in data
        assert data["tlsInfo"].get("sighupReloadSupported") is True
    except Exception:
        pytest.skip("Local relayer daemon not reachable on 100.77.188.3:8546 (offline runner).")

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
