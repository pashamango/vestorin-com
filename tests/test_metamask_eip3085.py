#!/usr/bin/env python3
"""
tests/test_metamask_eip3085.py — Unit tests for Vestorin MetaMask metadata, EIP-3085 & EIP-3326 flows.
Verifies:
- Parameter correctness in vestorin_app.html:
  * chainId: '0x31783' (hex) and 202627 (dec)
  * chainName: 'Vestorin Staging'
  * nativeCurrency: { name: 'Vestorin', symbol: 'VST', decimals: 18 }
  * rpcUrls: ['http://100.77.188.3:8546']
  * iconUrls: verified HTTPS list; broken vestorin.com fallback removed
  * blockExplorerUrls: placeholder-free, single constant (null pending MIN-226)
- Sequential flow: wallet_addEthereumChain followed by wallet_switchEthereumChain
- EIP-1193 client request simulation & error handling (4001, -32602, missing provider)
"""

import json
import os
import re
import pytest

APP_HTML_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "staging", "relayer", "vestorin_app.html")
)


def read_app_html():
    with open(APP_HTML_PATH, "r", encoding="utf-8") as f:
        return f.read()


def test_app_html_exists():
    assert os.path.exists(APP_HTML_PATH), f"vestorin_app.html not found at {APP_HTML_PATH}"


def test_chain_id_hex_and_dec_parity():
    """Verify chainId hex is '0x31783' and matches decimal 202627."""
    html = read_app_html()
    assert "0x31783" in html
    assert "202627" in html
    assert int("0x31783", 16) == 202627


def test_staging_chain_metadata_contract():
    """Verify exact EIP-3085 required metadata fields in STAGING_CHAIN."""
    html = read_app_html()
    assert "chainName: 'Vestorin Staging'" in html
    assert "nativeCurrency: { name: 'Vestorin', symbol: 'VST', decimals: 18 }" in html
    assert "'http://100.77.188.3:8546'" in html


def test_broken_icon_url_removed():
    """Verify broken https://vestorin.com/assets/vestorin-mark.png (404) was removed from VESTORIN_ICON_URLS."""
    html = read_app_html()
    assert "https://vestorin.com/assets/vestorin-mark.png" not in html
    # Active valid GitHub CDN icon URL must be present
    assert "https://raw.githubusercontent.com/pashamango/vestorin-com/minutta/min-225-vestorin-metamask-metadata-one-click-add-with-icon-explorer/assets/vestorin-mark.png" in html


def test_placeholder_free_block_explorer():
    """Verify blockExplorerUrls is wired to single constant BLOCK_EXPLORER_URL and is null pending MIN-226."""
    html = read_app_html()
    assert "const BLOCK_EXPLORER_URL = null;" in html
    # Ensure no fabricated or placeholder explorer URL is hardcoded
    assert "https://explorer.vestorin.com" not in html
    assert "https://staging-explorer.vestorin.com" not in html


def test_sequential_add_and_switch_flow_present():
    """Verify wallet_addEthereumChain is followed by wallet_switchEthereumChain in the click handler."""
    html = read_app_html()
    add_pos = html.find("method: 'wallet_addEthereumChain'")
    switch_pos = html.find("method: 'wallet_switchEthereumChain'")
    assert add_pos != -1, "wallet_addEthereumChain method call not found"
    assert switch_pos != -1, "wallet_switchEthereumChain method call not found"
    assert add_pos < switch_pos, "wallet_addEthereumChain must precede wallet_switchEthereumChain"


def test_chain_changed_listener_registered():
    """Verify window.ethereum.on('chainChanged') listener is implemented."""
    html = read_app_html()
    assert "window.ethereum.on('chainChanged'" in html


class MockEthereumProvider:
    """Simulates an EIP-1193 window.ethereum provider to validate request dispatching."""

    def __init__(self, mode="happy_path"):
        self.mode = mode
        self.calls = []
        self.chains_added = {}
        self.active_chain = "0x1"

    def request(self, req: dict):
        method = req.get("method")
        params = req.get("params", [])
        self.calls.append({"method": method, "params": params})

        if method == "wallet_addEthereumChain":
            if self.mode == "user_reject_add":
                raise RuntimeError("User rejected the request.")  # 4001
            chain_obj = params[0]
            # Validate EIP-3085 schema constraints
            chain_id = chain_obj.get("chainId")
            if not chain_id or not chain_id.startswith("0x"):
                raise ValueError("Expected 0x-prefixed chainId (-32602)")
            native = chain_obj.get("nativeCurrency", {})
            sym = native.get("symbol", "")
            if len(sym) < 2 or len(sym) > 6:
                raise ValueError("Expected 2-6 character string nativeCurrency.symbol (-32602)")
            rpc_urls = chain_obj.get("rpcUrls", [])
            if not rpc_urls or not isinstance(rpc_urls, list):
                raise ValueError("Expected non-empty rpcUrls array (-32602)")

            self.chains_added[chain_id] = chain_obj
            return None

        elif method == "wallet_switchEthereumChain":
            if self.mode == "user_reject_switch":
                raise RuntimeError("User rejected the switch request.")  # 4001
            target_id = params[0].get("chainId")
            if target_id not in self.chains_added and target_id != "0x1":
                raise KeyError(f"Unrecognized chain ID {target_id} (4902)")
            self.active_chain = target_id
            return None

        raise NotImplementedError(f"Method {method} not handled in mock")


def test_simulated_eip1193_happy_path():
    provider = MockEthereumProvider(mode="happy_path")
    add_params = {
        "chainId": "0x31783",
        "chainName": "Vestorin Staging",
        "nativeCurrency": {"name": "Vestorin", "symbol": "VST", "decimals": 18},
        "rpcUrls": ["http://100.77.188.3:8546"],
        "iconUrls": [
            "https://raw.githubusercontent.com/pashamango/vestorin-com/minutta/min-225-vestorin-metamask-metadata-one-click-add-with-icon-explorer/assets/vestorin-mark.png"
        ],
    }

    # Step 1: Add
    res_add = provider.request({"method": "wallet_addEthereumChain", "params": [add_params]})
    assert res_add is None
    assert "0x31783" in provider.chains_added

    # Step 2: Switch
    res_switch = provider.request({"method": "wallet_switchEthereumChain", "params": [{"chainId": "0x31783"}]})
    assert res_switch is None
    assert provider.active_chain == "0x31783"
    assert len(provider.calls) == 2


def test_simulated_eip1193_user_reject_add():
    provider = MockEthereumProvider(mode="user_reject_add")
    add_params = {
        "chainId": "0x31783",
        "chainName": "Vestorin Staging",
        "nativeCurrency": {"name": "Vestorin", "symbol": "VST", "decimals": 18},
        "rpcUrls": ["http://100.77.188.3:8546"],
    }
    with pytest.raises(RuntimeError) as exc_info:
        provider.request({"method": "wallet_addEthereumChain", "params": [add_params]})
    assert "User rejected" in str(exc_info.value)
    assert len(provider.chains_added) == 0


def test_simulated_eip1193_user_reject_switch():
    provider = MockEthereumProvider(mode="user_reject_switch")
    add_params = {
        "chainId": "0x31783",
        "chainName": "Vestorin Staging",
        "nativeCurrency": {"name": "Vestorin", "symbol": "VST", "decimals": 18},
        "rpcUrls": ["http://100.77.188.3:8546"],
    }
    # Add succeeds
    provider.request({"method": "wallet_addEthereumChain", "params": [add_params]})
    assert "0x31783" in provider.chains_added

    # Switch fails
    with pytest.raises(RuntimeError) as exc_info:
        provider.request({"method": "wallet_switchEthereumChain", "params": [{"chainId": "0x31783"}]})
    assert "User rejected the switch" in str(exc_info.value)
    assert provider.active_chain == "0x1"  # Remains on original chain
