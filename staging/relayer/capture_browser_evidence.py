#!/usr/bin/env python3
"""
capture_browser_evidence.py — Automated CDP Browser Evidence Capture & Audit Suite for MIN-227.
Navigates to https://app-staging.vestorin.com:8443/ using Google Chrome over Chrome DevTools Protocol (CDP),
validates window.isSecureContext and active RPC configuration, executes the full PoUW claim flow,
captures raw console/network CDP events, and produces screenshots:
- staging/relayer/evidence_https_claim.png (Step 04 receipt with live on-chain txHash)
- staging/relayer/evidence_https_claim_trusted_browser.png (Step 01 secure context & active HTTPS RPC banner)
- staging/relayer/audit_console_network.json (reproducible raw CDP export)
"""

import asyncio
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import websockets

TARGET_URL = "https://app-staging.vestorin.com:8443/"
CHROME_BIN = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUTPUT_DIR = os.path.abspath(os.path.dirname(__file__))

async def main():
    if not os.path.exists(CHROME_BIN):
        print(f"ERROR: Chrome binary not found at {CHROME_BIN}", file=sys.stderr)
        sys.exit(1)

    profile_dir = tempfile.mkdtemp(prefix="vestorin_chrome_cdp_")
    cdp_port = 9222

    chrome_cmd = [
        CHROME_BIN,
        "--headless=new",
        f"--remote-debugging-port={cdp_port}",
        f"--user-data-dir={profile_dir}",
        "--window-size=1280,1024",
        "--hide-scrollbars",
        "about:blank",
    ]

    print(f"[1/6] Launching Google Chrome headless on port {cdp_port}...")
    proc = subprocess.Popen(chrome_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        await asyncio.sleep(1.5)
        with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json") as r:
            tabs = json.loads(r.read().decode("utf-8"))
        ws_url = tabs[0]["webSocketDebuggerUrl"]
        print(f"      Connected to Chrome CDP endpoint: {ws_url}")

        raw_cdp_events = []
        network_requests = []
        console_logs = []

        async with websockets.connect(ws_url, max_size=20 * 1024 * 1024) as ws:
            req_counter = 1

            async def cdp_send(method: str, params: dict = None) -> dict:
                nonlocal req_counter
                mid = req_counter
                req_counter += 1
                msg = {"id": mid, "method": method, "params": params or {}}
                await ws.send(json.dumps(msg))
                while True:
                    raw = await ws.recv()
                    data = json.loads(raw)
                    if "method" in data:
                        raw_cdp_events.append(data)
                        m = data["method"]
                        if m == "Runtime.consoleAPICalled":
                            console_logs.append(data["params"])
                        elif m == "Network.requestWillBeSent":
                            network_requests.append({
                                "requestId": data["params"].get("requestId"),
                                "url": data["params"].get("request", {}).get("url"),
                                "method": data["params"].get("request", {}).get("method"),
                                "headers": data["params"].get("request", {}).get("headers"),
                                "timestamp": data["params"].get("timestamp"),
                            })
                    if data.get("id") == mid:
                        return data

            async def eval_js(expr: str):
                res = await cdp_send("Runtime.evaluate", {"expression": expr, "returnByValue": True})
                return res.get("result", {}).get("result", {}).get("value")

            # Enable CDP domains
            await cdp_send("Page.enable")
            await cdp_send("Runtime.enable")
            await cdp_send("Network.enable")

            print(f"[2/6] Navigating to {TARGET_URL}...")
            await cdp_send("Page.navigate", {"url": TARGET_URL})
            await asyncio.sleep(2.0)

            # Check Secure Context & RPC endpoint
            is_secure = await eval_js("window.isSecureContext")
            page_title = await eval_js("document.title")
            page_url = await eval_js("window.location.href")
            meta_rpc = await eval_js("document.getElementById('metaStagingRpc') ? document.getElementById('metaStagingRpc').textContent : ''")
            banner_text = await eval_js("document.getElementById('cryptoBannerBody') ? document.getElementById('cryptoBannerBody').innerText : ''")

            print(f"      page_url: {page_url}")
            print(f"      isSecureContext: {is_secure}")
            print(f"      metaStagingRpc: {meta_rpc}")
            assert is_secure is True, "window.isSecureContext must be true"
            assert "https://app-staging.vestorin.com:8443" in meta_rpc, "Active RPC must resolve to HTTPS"

            # Capture Screenshot 1: Step 01 browser view with Secure Context banner
            print("[3/6] Capturing Step 01 trusted browser view screenshot...")
            snap1 = await cdp_send("Page.captureScreenshot", {"format": "png"})
            snap1_bytes = base64.b64decode(snap1["result"]["data"])
            path_snap1 = os.path.join(OUTPUT_DIR, "evidence_https_claim_trusted_browser.png")
            with open(path_snap1, "wb") as f:
                f.write(snap1_bytes)
            print(f"      Saved: {path_snap1} ({len(snap1_bytes):,} bytes)")

            # Step 1 -> Step 2: Generate BIP-39 Phrase
            print("[4/6] Executing claim flow: generating BIP-39 mnemonic phrase...")
            await eval_js("document.getElementById('startStep1Btn').click()")
            await asyncio.sleep(1.5)
            recipient_address = await eval_js("document.getElementById('step2DerivedAddress') ? document.getElementById('step2DerivedAddress').textContent : ''")
            print(f"      Derived Address: {recipient_address}")

            # Step 2 -> Step 3
            print("      Proceeding to Step 03...")
            await eval_js("document.getElementById('proceedToStep3Btn').click()")
            await asyncio.sleep(1.0)

            # Step 3 -> Step 4: Execute Claim over HTTPS
            print("[5/6] Submitting claim transfer via HTTPS relayer (/api/v1/claim)...")
            await eval_js("document.getElementById('executeClaimBtn').click()")

            # Wait for Step 04 receipt
            claim_dispatched = False
            for _ in range(30):
                await asyncio.sleep(1.0)
                badge_text = await eval_js("document.getElementById('claimDispatchBadge') ? document.getElementById('claimDispatchBadge').textContent : ''")
                if "DISPATCHED ON-CHAIN" in badge_text:
                    claim_dispatched = True
                    break

            assert claim_dispatched, "Claim did not reach DISPATCHED ON-CHAIN state within 30s"
            claim_explanation = await eval_js("document.getElementById('claimDispatchExplanation') ? document.getElementById('claimDispatchExplanation').innerText : ''")
            print(f"      Claim Result: {claim_explanation}")

            # Capture Screenshot 2: Step 04 receipt with live txHash
            snap2 = await cdp_send("Page.captureScreenshot", {"format": "png"})
            snap2_bytes = base64.b64decode(snap2["result"]["data"])
            path_snap2 = os.path.join(OUTPUT_DIR, "evidence_https_claim.png")
            with open(path_snap2, "wb") as f:
                f.write(snap2_bytes)
            print(f"      Saved: {path_snap2} ({len(snap2_bytes):,} bytes)")

            # Drain any trailing network/console events
            await asyncio.sleep(1.0)

            # Audit Network Requests: verify 0 mixed content / HTTP requests
            insecure_requests = [req for req in network_requests if req.get("url", "").startswith("http://")]
            mixed_content_warnings = [
                log for log in console_logs
                if any("mixed" in str(arg).lower() or "insecure" in str(arg).lower() for arg in log.get("args", []))
            ]

            print(f"[6/6] Verifying network & console integrity...")
            print(f"      Total Network Requests: {len(network_requests)}")
            print(f"      Insecure (HTTP) Requests: {len(insecure_requests)}")
            print(f"      Console Log Entries: {len(console_logs)}")
            print(f"      Mixed Content Warnings: {len(mixed_content_warnings)}")
            assert len(insecure_requests) == 0, f"Found insecure HTTP requests: {insecure_requests}"
            assert len(mixed_content_warnings) == 0, "Found mixed content warnings"

            # Write reproducible raw CDP audit file
            audit_path = os.path.join(OUTPUT_DIR, "audit_console_network.json")
            audit_data = {
                "auditTimestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "targetUrl": TARGET_URL,
                "browser": "Google Chrome (Headless CDP)",
                "verification": {
                    "isSecureContext": is_secure,
                    "activeRpcUrl": meta_rpc,
                    "recipientAddress": recipient_address,
                    "claimExplanation": claim_explanation,
                    "insecureHttpRequestsCount": len(insecure_requests),
                    "mixedContentWarningsCount": len(mixed_content_warnings),
                    "step1ScreenshotBytes": len(snap1_bytes),
                    "step4ScreenshotBytes": len(snap2_bytes),
                    "screenshotsDistinct": snap1_bytes != snap2_bytes,
                },
                "networkRequests": network_requests,
                "consoleLogs": console_logs,
                "rawCdpEventsCount": len(raw_cdp_events),
                "rawCdpEventsSample": raw_cdp_events[:50],
            }
            with open(audit_path, "w", encoding="utf-8") as f:
                json.dump(audit_data, f, indent=2)
            print(f"      Saved audit export: {audit_path}")

        print("CDP EVIDENCE CAPTURE COMPLETED SUCCESSFULLY.")

    finally:
        proc.terminate()
        proc.wait()
        shutil.rmtree(profile_dir, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(main())
