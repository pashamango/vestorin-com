#!/usr/bin/env python3
"""
capture_browser_evidence.py — Automated CDP Browser Evidence Capture & Audit Suite for MIN-227.
Navigates to https://app-staging.vestorin.com:8443/ using Google Chrome over Chrome DevTools Protocol (CDP),
validates window.isSecureContext, active HTTPS RPC, and TLS certificate trust, executes the full PoUW claim flow,
captures raw console/network/security CDP events, polls on-chain transaction receipt to status 0x1,
records OpenSSL s_client verification transcripts, and produces evidence artifacts:
- staging/relayer/evidence_https_claim.png (Step 04 receipt with live on-chain txHash)
- staging/relayer/evidence_https_claim_trusted_browser.png (Step 01 secure context & active HTTPS RPC banner)
- staging/relayer/evidence_claim_receipt.json (Mined tx receipt status 0x1 & recipient balance verification)
- staging/relayer/evidence_openssl_verify.txt (OpenSSL s_client live handshake transcripts for both hostnames)
- staging/relayer/audit_console_network.json (Full unsegmented CDP export with request/response headers and bodies)
- staging/relayer/evidence_faucet_abuse_mitigation_report.md (Refreshed faucet capacity & velocity report)
"""

import asyncio
import base64
import datetime
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

# Ensure websockets package is available, falling back to local venv if needed
try:
    import websockets
except ImportError:
    venv_py = "/Users/pavelcherkashin/ChitAkasha-Wolfram/venv/bin/python"
    if os.path.exists(venv_py) and sys.executable != venv_py:
        os.execv(venv_py, [venv_py] + sys.argv)
    raise

TARGET_URL = "https://app-staging.vestorin.com:8443/"
RPC_URL = "https://app-staging.vestorin.com:8443/"
CHROME_BIN = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUTPUT_DIR = os.path.abspath(os.path.dirname(__file__))

def call_https_rpc(method: str, params: list) -> dict:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations("/etc/ssl/cert.pem")
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(RPC_URL, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))

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

    print(f"[1/7] Launching Google Chrome headless on port {cdp_port}...")
    proc = subprocess.Popen(chrome_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        ws_url = None
        for _ in range(40):
            await asyncio.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json") as r:
                    tabs = json.loads(r.read().decode("utf-8"))
                    page_tabs = [t for t in tabs if t.get("type") == "page"]
                    if page_tabs and "webSocketDebuggerUrl" in page_tabs[0]:
                        ws_url = page_tabs[0]["webSocketDebuggerUrl"]
                        break
            except Exception:
                pass

        if not ws_url:
            raise RuntimeError(f"Could not connect to Chrome CDP /json endpoint on port {cdp_port}")
        print(f"      Connected to Chrome CDP page endpoint: {ws_url}")

        raw_cdp_events = []
        network_requests = []
        network_responses = []
        network_finished = []
        network_failed = []
        security_state_events = []
        console_logs = []
        response_bodies = {}
        claim_request_id = None

        async with websockets.connect(ws_url, max_size=50 * 1024 * 1024) as ws:
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
                        p = data.get("params", {})
                        if m == "Runtime.consoleAPICalled":
                            console_logs.append(p)
                        elif m == "Security.securityStateChanged":
                            security_state_events.append(p)
                        elif m == "Network.requestWillBeSent":
                            req_item = {
                                "requestId": p.get("requestId"),
                                "url": p.get("request", {}).get("url"),
                                "method": p.get("request", {}).get("method"),
                                "headers": p.get("request", {}).get("headers"),
                                "timestamp": p.get("timestamp"),
                            }
                            network_requests.append(req_item)
                            if "/api/v1/claim" in p.get("request", {}).get("url", ""):
                                nonlocal claim_request_id
                                claim_request_id = p.get("requestId")
                        elif m == "Network.responseReceived":
                            resp_item = {
                                "requestId": p.get("requestId"),
                                "url": p.get("response", {}).get("url"),
                                "status": p.get("response", {}).get("status"),
                                "statusText": p.get("response", {}).get("statusText"),
                                "headers": p.get("response", {}).get("headers"),
                                "mimeType": p.get("response", {}).get("mimeType"),
                                "securityState": p.get("response", {}).get("securityState"),
                                "securityDetails": p.get("response", {}).get("securityDetails"),
                                "timestamp": p.get("timestamp"),
                            }
                            network_responses.append(resp_item)
                        elif m == "Network.loadingFinished":
                            network_finished.append(p)
                        elif m == "Network.loadingFailed":
                            network_failed.append(p)

                    if data.get("id") == mid:
                        return data

            async def eval_js(expr: str):
                res = await cdp_send("Runtime.evaluate", {"expression": expr, "returnByValue": True})
                return res.get("result", {}).get("result", {}).get("value")

            # Enable CDP domains
            await cdp_send("Page.enable")
            await cdp_send("Runtime.enable")
            await cdp_send("Network.enable")
            await cdp_send("Security.enable")

            print(f"[2/7] Navigating to {TARGET_URL}...")
            await cdp_send("Page.navigate", {"url": TARGET_URL})
            await asyncio.sleep(2.0)

            # Query visible security state
            sec_state_res = await cdp_send("Security.getVisibleSecurityState")
            visible_sec = sec_state_res.get("result", {}).get("visibleSecurityState", {})

            # Check Secure Context & RPC endpoint
            is_secure = await eval_js("window.isSecureContext")
            page_title = await eval_js("document.title")
            page_url = await eval_js("window.location.href")
            meta_rpc = await eval_js("document.getElementById('metaStagingRpc') ? document.getElementById('metaStagingRpc').textContent : ''")
            banner_text = await eval_js("document.getElementById('cryptoBannerBody') ? document.getElementById('cryptoBannerBody').innerText : ''")

            print(f"      page_url: {page_url}")
            print(f"      isSecureContext: {is_secure}")
            print(f"      metaStagingRpc: {meta_rpc}")
            print(f"      securityState: {visible_sec.get('securityState')}")
            assert is_secure is True, "window.isSecureContext must be true"
            assert "https://app-staging.vestorin.com:8443" in meta_rpc, "Active RPC must resolve to HTTPS"

            # Capture Screenshot 1: Step 01 browser view with Secure Context banner
            print("[3/7] Capturing Step 01 trusted browser view screenshot...")
            snap1 = await cdp_send("Page.captureScreenshot", {"format": "png"})
            snap1_bytes = base64.b64decode(snap1["result"]["data"])
            path_snap1 = os.path.join(OUTPUT_DIR, "evidence_https_claim_trusted_browser.png")
            with open(path_snap1, "wb") as f:
                f.write(snap1_bytes)
            print(f"      Saved: {path_snap1} ({len(snap1_bytes):,} bytes)")

            # Step 1 -> Step 2: Generate BIP-39 Phrase
            print("[4/7] Executing claim flow: generating BIP-39 mnemonic phrase...")
            await eval_js("document.getElementById('startStep1Btn').click()")
            await asyncio.sleep(1.5)
            recipient_address = await eval_js("document.getElementById('step2DerivedAddress') ? document.getElementById('step2DerivedAddress').textContent : ''")
            print(f"      Derived Address: {recipient_address}")

            # Check initial on-chain balance
            bal_pre_res = call_https_rpc("eth_getBalance", [recipient_address, "latest"])
            bal_pre_wei = int(bal_pre_res.get("result", "0x0"), 16)
            print(f"      Pre-claim balance: {bal_pre_wei} wei ({bal_pre_wei / 10**18:.4f} VST)")

            # Step 2 -> Step 3
            print("      Proceeding to Step 03...")
            await eval_js("document.getElementById('proceedToStep3Btn').click()")
            await asyncio.sleep(1.0)

            # Step 3 -> Step 4: Execute Claim over HTTPS
            print("[5/7] Submitting claim transfer via HTTPS relayer (/api/v1/claim)...")
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

            # Fetch response body for /api/v1/claim if captured
            claim_body = {}
            if claim_request_id:
                try:
                    body_res = await cdp_send("Network.getResponseBody", {"requestId": claim_request_id})
                    raw_body = body_res.get("result", {}).get("body", "")
                    claim_body = json.loads(raw_body)
                    print(f"      Retrieved /api/v1/claim response body: {claim_body}")
                except Exception as e:
                    print(f"      Note: getResponseBody for claim: {e}")

            # Extract txHash
            tx_hash = claim_body.get("txHash")
            if not tx_hash:
                import re
                m = re.search(r"0x[a-fA-F0-9]{64}", claim_explanation)
                if m:
                    tx_hash = m.group(0)
            assert tx_hash, "Could not determine transaction hash from claim"
            print(f"      On-Chain Transaction Hash: {tx_hash}")

            # Drain trailing events
            await asyncio.sleep(1.0)

            # Audit Network Requests: verify 0 mixed content / HTTP requests
            insecure_requests = [req for req in network_requests if req.get("url", "").startswith("http://")]
            mixed_content_warnings = [
                log for log in console_logs
                if any("mixed" in str(arg).lower() or "insecure" in str(arg).lower() for arg in log.get("args", []))
            ]

            print(f"      Total Network Requests : {len(network_requests)}")
            print(f"      Total Network Responses: {len(network_responses)}")
            print(f"      Insecure HTTP Requests : {len(insecure_requests)}")
            print(f"      Console Log Entries    : {len(console_logs)}")
            print(f"      Mixed Content Warnings : {len(mixed_content_warnings)}")
            print(f"      Total Raw CDP Events   : {len(raw_cdp_events)}")
            assert len(insecure_requests) == 0, f"Found insecure HTTP requests: {insecure_requests}"
            assert len(mixed_content_warnings) == 0, "Found mixed content warnings"

        # Step 6: Verify Transaction Receipt on-chain
        print(f"[6/7] Polling eth_getTransactionReceipt for {tx_hash}...")
        receipt = None
        for attempt in range(30):
            receipt_res = call_https_rpc("eth_getTransactionReceipt", [tx_hash])
            r = receipt_res.get("result")
            if r is not None:
                receipt = r
                break
            time.sleep(1.0)

        assert receipt is not None, f"Transaction {tx_hash} was not mined within 30s"
        assert receipt.get("status") == "0x1", f"Transaction status is not 0x1 (success): {receipt}"
        block_num = int(receipt.get("blockNumber", "0x0"), 16)
        print(f"      Transaction confirmed in block: {block_num} (status: 0x1)")

        # Verify recipient balance
        bal_post_res = call_https_rpc("eth_getBalance", [recipient_address, "latest"])
        bal_post_wei = int(bal_post_res.get("result", "0x0"), 16)
        diff_vst = (bal_post_wei - bal_pre_wei) / 10**18
        print(f"      Post-claim balance: {bal_post_wei} wei (+{diff_vst:.4f} VST)")
        assert diff_vst >= 21_000_000, f"Recipient balance increase unexpected: {diff_vst}"

        # Write evidence_claim_receipt.json
        receipt_artifact_path = os.path.join(OUTPUT_DIR, "evidence_claim_receipt.json")
        receipt_data = {
            "verifiedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transactionHash": tx_hash,
            "recipientAddress": recipient_address,
            "expectedDosageVST": 21000000,
            "preClaimBalanceWei": str(bal_pre_wei),
            "postClaimBalanceWei": str(bal_post_wei),
            "balanceIncreaseVST": diff_vst,
            "receipt": {
                "blockNumber": receipt.get("blockNumber"),
                "blockNumberDec": block_num,
                "blockHash": receipt.get("blockHash"),
                "transactionHash": receipt.get("transactionHash"),
                "from": receipt.get("from"),
                "to": receipt.get("to"),
                "status": receipt.get("status"),
                "gasUsed": receipt.get("gasUsed"),
                "cumulativeGasUsed": receipt.get("cumulativeGasUsed"),
            }
        }
        with open(receipt_artifact_path, "w", encoding="utf-8") as f:
            json.dump(receipt_data, f, indent=2)
        print(f"      Saved on-chain receipt artifact: {receipt_artifact_path}")

        # Step 7: Live OpenSSL s_client Transcripts
        print("[7/7] Generating live OpenSSL s_client transcripts for staging hostnames...")
        cmd_app = [
            "openssl", "s_client",
            "-connect", "100.77.188.3:8443",
            "-servername", "app-staging.vestorin.com",
            "-verify_hostname", "app-staging.vestorin.com",
        ]
        cmd_rpc = [
            "openssl", "s_client",
            "-connect", "100.77.188.3:8443",
            "-servername", "rpc-staging.vestorin.com",
            "-verify_hostname", "rpc-staging.vestorin.com",
        ]

        p_app = subprocess.run(cmd_app, input="", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        p_rpc = subprocess.run(cmd_rpc, input="", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        openssl_evidence_path = os.path.join(OUTPUT_DIR, "evidence_openssl_verify.txt")
        with open(openssl_evidence_path, "w", encoding="utf-8") as f:
            f.write("=== OPENSSL S_CLIENT VERIFY: app-staging.vestorin.com ===\n")
            f.write(p_app.stdout.rstrip() + "\n\n")
            f.write("=== OPENSSL S_CLIENT VERIFY: rpc-staging.vestorin.com ===\n")
            f.write(p_rpc.stdout.rstrip() + "\n")
        print(f"      Saved OpenSSL s_client transcripts: {openssl_evidence_path}")
        assert "Verify return code: 0 (ok)" in p_app.stdout, "app-staging s_client verification failed"
        assert "Verify return code: 0 (ok)" in p_rpc.stdout, "rpc-staging s_client verification failed"

        # Write reproducible raw CDP audit file (FULL raw event stream, no [:50] truncation)
        audit_path = os.path.join(OUTPUT_DIR, "audit_console_network.json")
        audit_data = {
            "auditTimestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "targetUrl": TARGET_URL,
            "browser": "Google Chrome (Headless CDP)",
            "verification": {
                "isSecureContext": is_secure,
                "activeRpcUrl": meta_rpc,
                "recipientAddress": recipient_address,
                "claimTxHash": tx_hash,
                "claimExplanation": claim_explanation,
                "onChainReceiptStatus": receipt.get("status"),
                "onChainBlockNumber": block_num,
                "recipientBalanceIncreaseVST": diff_vst,
                "insecureHttpRequestsCount": len(insecure_requests),
                "mixedContentWarningsCount": len(mixed_content_warnings),
                "step1ScreenshotBytes": len(snap1_bytes),
                "step4ScreenshotBytes": len(snap2_bytes),
                "screenshotsDistinct": snap1_bytes != snap2_bytes,
                "rawCdpEventsCount": len(raw_cdp_events),
            },
            "security": {
                "visibleSecurityState": visible_sec,
                "securityStateEvents": security_state_events,
            },
            "claimResponseBody": claim_body,
            "networkRequests": network_requests,
            "networkResponses": network_responses,
            "networkFailures": network_failed,
            "consoleLogs": console_logs,
            "rawCdpEvents": raw_cdp_events,
        }
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2)
        print(f"      Saved full raw CDP audit export: {audit_path}")

        # Refresh Faucet Abuse Mitigation Report
        print("      Refreshing Faucet Abuse Mitigation & Velocity report...")
        report_script = os.path.join(OUTPUT_DIR, "vestorin_faucet_monitor.py")
        report_dest = os.path.join(OUTPUT_DIR, "evidence_faucet_abuse_mitigation_report.md")
        subprocess.run([sys.executable, report_script, "--save-report", report_dest], check=True)
        print(f"      Updated report: {report_dest}")

        print("\n========================================================")
        print("CDP EVIDENCE CAPTURE & AUDIT COMPLETED 100% SUCCESSFULLY")
        print(f"TxHash: {tx_hash} | Block: {block_num} | Status: 0x1")
        print("========================================================")

    finally:
        proc.terminate()
        proc.wait()
        shutil.rmtree(profile_dir, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(main())
