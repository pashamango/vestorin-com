#!/usr/bin/env python3
"""
tests/test_relayer_assets.py — Regression and integration tests for Vestorin relayer asset handling.
Verifies:
- Path traversal prevention under /assets/ (arbitrary local file disclosure fix for MIN-225).
- Dedicated asset directory containment (requests resolving outside /assets/ return 404).
- Safe default BIND_HOST (defaults to loopback '127.0.0.1', not '0.0.0.0').
- Static asset serving for EIP-3085 icons: /icon.png, /icon.svg, /assets/vestorin-mark.png, /assets/vestorin-mark.svg.
"""

import http.client
import json
import os
import socket
import sys
import threading
import time
import pytest

# Ensure staging/relayer is on sys.path
RELAYER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "staging", "relayer"))
if RELAYER_DIR not in sys.path:
    sys.path.insert(0, RELAYER_DIR)

import vestorin_wolfram_relayer as relayer_mod
from vestorin_wolfram_relayer import (
    VestorinRelayerHandler,
    ThreadedHTTPServer,
    BIND_HOST,
)


def test_default_bind_host_is_not_wildcard():
    """Verify BIND_HOST defaults to loopback 127.0.0.1, not wildcard 0.0.0.0."""
    assert relayer_mod.BIND_HOST != "0.0.0.0", "Default BIND_HOST must not be 0.0.0.0"
    assert relayer_mod.BIND_HOST == "127.0.0.1", f"Expected default 127.0.0.1, got {relayer_mod.BIND_HOST}"


@pytest.fixture(scope="module")
def relayer_server():
    """Spins up a lightweight in-process test server on an ephemeral loopback port."""
    # Find free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = ThreadedHTTPServer(("127.0.0.1", port), VestorinRelayerHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.2)

    yield f"127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


def make_raw_get_request(host_port: str, path: str):
    """Executes a raw GET request preserving exact path characters (no client-side normalization)."""
    conn = http.client.HTTPConnection(host_port, timeout=5)
    # putrequest with skip_host=False, and send raw path
    conn.putrequest("GET", path, skip_host=False, skip_accept_encoding=True)
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, resp.headers, body


def test_path_traversal_etc_passwd_blocked(relayer_server):
    """
    CRITICAL REGRESSION TEST (MIN-225):
    Verifies that directory traversal payloads like /assets/../../../../../../etc/passwd
    return 404 and NEVER return 200 or disclose host files.
    """
    traversal_paths = [
        "/assets/../../../../../../etc/passwd",
        "/assets/..%2f..%2f..%2fetc%2fpasswd",
        "/assets/....//....//etc/passwd",
        "/assets/../../../../etc/shadow",
        "/assets/../../../etc/hosts",
    ]

    for path in traversal_paths:
        status, headers, body = make_raw_get_request(relayer_server, path)
        assert status == 404, f"Path '{path}' expected HTTP 404, got {status}"
        assert b"root:" not in body, f"File disclosure detected for '{path}'!"
        assert b"nobody:" not in body, f"File disclosure detected for '{path}'!"
        try:
            data = json.loads(body.decode("utf-8"))
            assert data.get("error") == "Asset not found"
        except Exception:
            pass


def test_static_icon_png_served(relayer_server):
    """Verifies that canonical PNG mark is served with 200 and image/png."""
    for path in ["/icon.png", "/vestorin-mark.png", "/assets/vestorin-mark.png"]:
        status, headers, body = make_raw_get_request(relayer_server, path)
        assert status == 200, f"Expected 200 for '{path}', got {status}"
        content_type = headers.get("Content-Type", "")
        assert content_type == "image/png", f"Expected image/png, got {content_type}"
        assert len(body) > 1000, f"Asset body too small: {len(body)} bytes"
        # Check PNG magic header: 89 50 4E 47 0D 0A 1A 0A
        assert body.startswith(b"\x89PNG\r\n\x1a\n"), "Invalid PNG header"


def test_static_icon_svg_served(relayer_server):
    """Verifies that canonical SVG mark is served with 200 and image/svg+xml."""
    for path in ["/icon.svg", "/vestorin-mark.svg", "/assets/vestorin-mark.svg"]:
        status, headers, body = make_raw_get_request(relayer_server, path)
        assert status == 200, f"Expected 200 for '{path}', got {status}"
        content_type = headers.get("Content-Type", "")
        assert content_type == "image/svg+xml", f"Expected image/svg+xml, got {content_type}"
        assert b"<svg" in body, "Expected <svg tag in SVG asset"


def test_nonexistent_asset_returns_404(relayer_server):
    """Verifies that non-existent assets return 404 JSON error."""
    status, headers, body = make_raw_get_request(relayer_server, "/assets/does_not_exist_404.png")
    assert status == 404
    data = json.loads(body.decode("utf-8"))
    assert data.get("error") == "Asset not found"


def test_empty_assets_root_returns_404(relayer_server):
    """Verifies that requesting bare /assets/ or /assets returns 404, not directory listing."""
    for path in ["/assets", "/assets/"]:
        status, _, body = make_raw_get_request(relayer_server, path)
        assert status == 404
        assert b"vestorin-mark" not in body or b"Directory listing" not in body
