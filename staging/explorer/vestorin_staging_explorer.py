#!/usr/bin/env python3
"""
vestorin_staging_explorer.py - Ultra-lightweight Block Explorer for Vestorin Staging (chainId 202627)
Stdlib-only: SQLite indexer + JSON-RPC client + HTTP/HTTPS server + pure HTML/CSS UI.

Endpoints:
  GET /                     - Explorer Home (live stats, search bar, recent blocks & txs)
  GET /tx/<txHash>          - Transaction detail page
  GET /address/<address>    - Address detail page (native balance + indexed tx history)
  GET /block/<numOrHash>    - Block detail page
  GET /search?q=<query>     - Universal search redirect
  GET /api/v1/stats         - JSON network stats
  GET /api/v1/tx/<txHash>   - JSON transaction + receipt
  GET /api/v1/address/<addr>- JSON address balance + tx list
  GET /healthz              - Health check
"""

import os
import sys
import time
import json
import sqlite3
import threading
import urllib.request
import urllib.error
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

# ---------------------------------------------------------
# Default Configuration
# ---------------------------------------------------------
GETH_RPC = os.getenv("VESTORIN_GETH_RPC", "http://127.0.0.1:8545")
BIND_HOST = os.getenv("VESTORIN_EXPLORER_HOST", "127.0.0.1")
BIND_PORT = int(os.getenv("VESTORIN_EXPLORER_PORT", "8547"))
DB_PATH = os.getenv("VESTORIN_EXPLORER_DB", "/Users/pavelcherkashin/vestorin-chain/vestorin_explorer.db")
CHAIN_ID = 202627
CHAIN_NAME = "Vestorin Staging"
CURRENCY_SYMBOL = "VST"
DECIMALS = 18

KNOWN_LABELS = {
    "0x1821dc3f0974339db7c7146037b40f54a2e222c3": "Operator Faucet",
    "0x28ff6e54d5e93a2af588f1edca82144f82abfce2": "Pavel Cherkashin (Principal)",
    "0x0e5fde73cfd2e7fb4d164b5d6487dea645832401": "Clique Sealer (Validator)",
    "0x3b4b3bf0c3f417ec1beb87476e5bb7c50a219f3b": "Genesis Alloc / Test Account",
}


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def wei_to_vst(wei_val, precision=6):
    """Convert wei (int or hex str or dec str) to VST float string."""
    if isinstance(wei_val, str):
        if wei_val.startswith("0x") or wei_val.startswith("0X"):
            wei_int = int(wei_val, 16)
        else:
            wei_int = int(wei_val)
    else:
        wei_int = int(wei_val or 0)
    vst = wei_int / (10 ** DECIMALS)
    if vst == int(vst):
        return f"{int(vst):,}"
    fmt = f"{vst:,.{precision}f}".rstrip("0").rstrip(".")
    return fmt

def format_hex_int(val):
    if not val:
        return 0
    if isinstance(val, int):
        return val
    return int(val, 16) if val.startswith("0x") else int(val)

def time_ago(ts):
    now = int(time.time())
    diff = max(0, now - int(ts))
    if diff < 60:
        return f"{diff}s ago"
    elif diff < 3600:
        return f"{diff // 60}m {diff % 60}s ago"
    elif diff < 86400:
        return f"{diff // 3600}h {(diff % 3600) // 60}m ago"
    else:
        return f"{diff // 86400}d {(diff % 86400) // 3600}h ago"

def format_timestamp(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(ts)))


# ---------------------------------------------------------
# Geth RPC Client
# ---------------------------------------------------------
_no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def rpc_call(method, params=None, rpc_url=GETH_RPC, timeout=5):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with _no_proxy_opener.open(req, timeout=timeout) as resp:
        res = json.loads(resp.read().decode())
        if "error" in res:
            raise RuntimeError(f"RPC error: {res['error']}")
        return res.get("result")

def rpc_batch(calls, rpc_url=GETH_RPC, timeout=10):
    if not calls:
        return []
    payload = json.dumps(calls).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with _no_proxy_opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------
# SQLite Database & Indexer
# ---------------------------------------------------------
class ExplorerDB:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with self.get_conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    number INTEGER PRIMARY KEY,
                    hash TEXT UNIQUE,
                    parent_hash TEXT,
                    timestamp INTEGER,
                    miner TEXT,
                    gas_used INTEGER,
                    gas_limit INTEGER,
                    tx_count INTEGER
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    hash TEXT PRIMARY KEY,
                    block_number INTEGER,
                    block_hash TEXT,
                    tx_index INTEGER,
                    from_addr TEXT,
                    to_addr TEXT,
                    value TEXT,
                    gas INTEGER,
                    gas_price TEXT,
                    gas_used INTEGER,
                    effective_gas_price TEXT,
                    status INTEGER,
                    input TEXT,
                    nonce INTEGER,
                    timestamp INTEGER
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_addr);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_addr);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_number);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);")
            conn.commit()

    def get_last_synced_block(self):
        with self.get_conn() as conn:
            cur = conn.execute("SELECT value FROM sync_state WHERE key = 'last_synced_block'")
            row = cur.fetchone()
            return int(row["value"]) if row else -1

    def set_last_synced_block(self, bnum):
        with self.get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('last_synced_block', ?)", (str(bnum),))
            conn.commit()

    def save_block_and_txs(self, block_data, txs_data):
        with self.get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO blocks (number, hash, parent_hash, timestamp, miner, gas_used, gas_limit, tx_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                block_data["number"],
                block_data["hash"].lower(),
                block_data.get("parentHash", "").lower(),
                block_data["timestamp"],
                block_data.get("miner", "").lower(),
                block_data.get("gasUsed", 0),
                block_data.get("gasLimit", 0),
                block_data.get("tx_count", 0)
            ))
            for tx in txs_data:
                conn.execute("""
                    INSERT OR REPLACE INTO transactions (
                        hash, block_number, block_hash, tx_index, from_addr, to_addr,
                        value, gas, gas_price, gas_used, effective_gas_price, status,
                        input, nonce, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tx["hash"].lower(),
                    tx["blockNumber"],
                    tx["blockHash"].lower(),
                    tx.get("transactionIndex", 0),
                    tx["from"].lower(),
                    tx["to"].lower() if tx.get("to") else "",
                    str(tx.get("value", "0")),
                    tx.get("gas", 0),
                    str(tx.get("gasPrice", "0")),
                    tx.get("gasUsed", 0),
                    str(tx.get("effectiveGasPrice", "0")),
                    tx.get("status", 1),
                    tx.get("input", "0x"),
                    tx.get("nonce", 0),
                    tx.get("timestamp", block_data["timestamp"])
                ))
            conn.commit()

    def get_tx(self, tx_hash):
        with self.get_conn() as conn:
            cur = conn.execute("SELECT * FROM transactions WHERE hash = ?", (tx_hash.lower(),))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_block_by_number(self, bnum):
        with self.get_conn() as conn:
            cur = conn.execute("SELECT * FROM blocks WHERE number = ?", (bnum,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_block_by_hash(self, bhash):
        with self.get_conn() as conn:
            cur = conn.execute("SELECT * FROM blocks WHERE hash = ?", (bhash.lower(),))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_txs_for_address(self, addr, limit=100):
        addr_clean = addr.lower()
        with self.get_conn() as conn:
            cur = conn.execute("""
                SELECT * FROM transactions
                WHERE from_addr = ? OR to_addr = ?
                ORDER BY block_number DESC, tx_index DESC
                LIMIT ?
            """, (addr_clean, addr_clean, limit))
            return [dict(r) for r in cur.fetchall()]

    def get_txs_for_block(self, bnum):
        with self.get_conn() as conn:
            cur = conn.execute("""
                SELECT * FROM transactions
                WHERE block_number = ?
                ORDER BY tx_index ASC
            """, (bnum,))
            return [dict(r) for r in cur.fetchall()]

    def get_recent_transactions(self, limit=15):
        with self.get_conn() as conn:
            cur = conn.execute("""
                SELECT * FROM transactions
                ORDER BY block_number DESC, tx_index DESC
                LIMIT ?
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_recent_blocks(self, limit=10):
        with self.get_conn() as conn:
            cur = conn.execute("""
                SELECT * FROM blocks
                ORDER BY number DESC
                LIMIT ?
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_stats(self):
        with self.get_conn() as conn:
            cur_tx = conn.execute("SELECT COUNT(*) as c FROM transactions")
            total_txs = cur_tx.fetchone()["c"]
            cur_b = conn.execute("SELECT MAX(number) as m FROM blocks")
            head_block = cur_b.fetchone()["m"] or 0
            return {
                "chainId": CHAIN_ID,
                "chainName": CHAIN_NAME,
                "headBlock": head_block,
                "totalTransactions": total_txs
            }


# ---------------------------------------------------------
# Background Blockchain Synchronizer
# ---------------------------------------------------------
class Synchronizer(threading.Thread):
    def __init__(self, db: ExplorerDB, rpc_url=GETH_RPC, poll_interval=2.0):
        super().__init__(daemon=True, name="VestorinSynchronizer")
        self.db = db
        self.rpc_url = rpc_url
        self.poll_interval = poll_interval
        self.running = True

    def run(self):
        while self.running:
            try:
                self.sync_chain()
            except Exception as e:
                # Log error and sleep
                sys.stderr.write(f"[Synchronizer] Sync error: {e}\n")
            time.sleep(self.poll_interval)

    def sync_chain(self):
        hex_head = rpc_call("eth_blockNumber", [], rpc_url=self.rpc_url)
        chain_head = int(hex_head, 16)
        last_synced = self.db.get_last_synced_block()

        if last_synced >= chain_head:
            return

        start = last_synced + 1
        BATCH_SIZE = 100

        while start <= chain_head and self.running:
            end = min(start + BATCH_SIZE - 1, chain_head)
            calls = [
                {"jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber", "params": [hex(i), True]}
                for i in range(start, end + 1)
            ]
            resps = rpc_batch(calls, rpc_url=self.rpc_url)

            # Sort responses by block number
            blocks_to_save = []
            for r in resps:
                blk = r.get("result")
                if not blk:
                    continue
                bnum = int(blk["number"], 16)
                bhash = blk["hash"]
                ts = int(blk["timestamp"], 16)
                txs = blk.get("transactions", [])

                block_entry = {
                    "number": bnum,
                    "hash": bhash,
                    "parentHash": blk.get("parentHash", ""),
                    "timestamp": ts,
                    "miner": blk.get("miner", ""),
                    "gasUsed": int(blk.get("gasUsed", "0x0"), 16),
                    "gasLimit": int(blk.get("gasLimit", "0x0"), 16),
                    "tx_count": len(txs)
                }

                parsed_txs = []
                if txs:
                    receipt_calls = [
                        {"jsonrpc": "2.0", "id": idx, "method": "eth_getTransactionReceipt", "params": [t["hash"]]}
                        for idx, t in enumerate(txs)
                    ]
                    receipt_resps = rpc_batch(receipt_calls, rpc_url=self.rpc_url)
                    receipt_map = {rc["result"]["transactionHash"]: rc["result"] for rc in receipt_resps if rc.get("result")}

                    for t in txs:
                        thash = t["hash"]
                        rec = receipt_map.get(thash, {})
                        val_hex = t.get("value", "0x0")
                        val_int = int(val_hex, 16)
                        parsed_txs.append({
                            "hash": thash,
                            "blockNumber": bnum,
                            "blockHash": bhash,
                            "transactionIndex": int(t.get("transactionIndex", "0x0"), 16),
                            "from": t.get("from", ""),
                            "to": t.get("to") or "",
                            "value": str(val_int),
                            "gas": int(t.get("gas", "0x0"), 16),
                            "gasPrice": str(int(t.get("gasPrice", "0x0"), 16)),
                            "gasUsed": int(rec.get("gasUsed", "0x0"), 16),
                            "effectiveGasPrice": str(int(rec.get("effectiveGasPrice", t.get("gasPrice", "0x0")), 16)),
                            "status": int(rec.get("status", "0x1"), 16),
                            "input": t.get("input", "0x"),
                            "nonce": int(t.get("nonce", "0x0"), 16),
                            "timestamp": ts
                        })

                # Always save blocks with transactions, plus every 50th empty block and head block to keep sample history
                if parsed_txs or bnum % 50 == 0 or bnum == chain_head:
                    self.db.save_block_and_txs(block_entry, parsed_txs)

            self.db.set_last_synced_block(end)
            start = end + 1


# ---------------------------------------------------------
# HTML UI Templates & Rendering
# ---------------------------------------------------------
CSS_STYLES = """
:root {
  --bg-primary: #0b0f19;
  --bg-card: #111827;
  --bg-card-subtle: #1f2937;
  --border-color: #374151;
  --text-main: #f9fafb;
  --text-muted: #9ca3af;
  --text-dim: #6b7280;
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-indigo: #6366f1;
  --success-bg: rgba(16, 185, 129, 0.15);
  --success-text: #34d399;
  --fail-bg: rgba(239, 68, 68, 0.15);
  --fail-text: #f87171;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg-primary);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  line-height: 1.5;
  padding-bottom: 60px;
}
a { color: var(--accent-cyan); text-decoration: none; }
a:hover { text-decoration: underline; }
.font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }

header {
  background: linear-gradient(180deg, #111827 0%, rgba(17, 24, 39, 0.8) 100%);
  border-bottom: 1px solid var(--border-color);
  padding: 1rem 1.5rem;
  position: sticky;
  top: 0;
  z-index: 50;
  backdrop-filter: blur(8px);
}
.header-inner {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}
.logo-container {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  text-decoration: none;
}
.logo-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: linear-gradient(135deg, #06b6d4, #6366f1);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  color: #fff;
  font-size: 18px;
}
.logo-text { font-size: 1.15rem; font-weight: 700; color: #fff; }
.logo-badge {
  font-size: 0.7rem;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(6, 182, 212, 0.15);
  color: var(--accent-cyan);
  font-weight: 600;
  border: 1px solid rgba(6, 182, 212, 0.3);
}

.search-box {
  flex: 1;
  max-width: 550px;
  position: relative;
}
.search-input {
  width: 100%;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 0.5rem 1rem;
  border-radius: 8px;
  color: #fff;
  font-size: 0.85rem;
  font-family: inherit;
  transition: all 0.2s;
}
.search-input:focus {
  outline: none;
  border-color: var(--accent-cyan);
  box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.2);
}

.container {
  max-width: 1200px;
  margin: 2rem auto 0;
  padding: 0 1.5rem;
}

.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border-color);
}
.card-title { font-size: 1.1rem; font-weight: 600; color: #fff; }

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 1.25rem;
}
.stat-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem; }
.stat-val { font-size: 1.4rem; font-weight: 700; color: #fff; }
.stat-sub { font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem; }

.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}
.badge-success { background: var(--success-bg); color: var(--success-text); border: 1px solid rgba(52, 211, 153, 0.3); }
.badge-fail { background: var(--fail-bg); color: var(--fail-text); border: 1px solid rgba(248, 113, 113, 0.3); }
.badge-in { background: rgba(16, 185, 129, 0.2); color: #34d399; font-size: 0.7rem; font-weight: 700; padding: 2px 5px; border-radius: 4px; }
.badge-out { background: rgba(245, 158, 11, 0.2); color: #fbbf24; font-size: 0.7rem; font-weight: 700; padding: 2px 5px; border-radius: 4px; }
.badge-tag { background: rgba(99, 102, 241, 0.2); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3); font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; }

.kv-table { width: 100%; border-collapse: collapse; }
.kv-table tr { border-bottom: 1px solid var(--border-color); }
.kv-table tr:last-child { border-bottom: none; }
.kv-table td { padding: 0.85rem 0.5rem; font-size: 0.9rem; vertical-align: middle; }
.kv-table td.label { width: 220px; color: var(--text-muted); font-weight: 500; }
.kv-table td.value { color: var(--text-main); word-break: break-all; }

table.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
table.data-table th {
  text-align: left;
  padding: 0.75rem 0.5rem;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border-color);
  font-weight: 600;
}
table.data-table td {
  padding: 0.75rem 0.5rem;
  border-bottom: 1px solid rgba(55, 65, 81, 0.5);
  vertical-align: middle;
}
table.data-table tr:hover td { background: var(--bg-card-subtle); }

.copy-btn {
  background: transparent;
  border: none;
  cursor: pointer;
  color: var(--text-muted);
  padding: 2px 4px;
  border-radius: 4px;
  font-size: 0.75rem;
  margin-left: 6px;
  transition: all 0.2s;
}
.copy-btn:hover { color: var(--accent-cyan); background: rgba(6, 182, 212, 0.1); }

footer {
  max-width: 1200px;
  margin: 3rem auto 0;
  padding: 1.5rem;
  border-top: 1px solid var(--border-color);
  color: var(--text-dim);
  font-size: 0.8rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
"""

JS_SCRIPTS = """
function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(function() {
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    btn.style.color = '#34d399';
    setTimeout(function() {
      btn.innerText = orig;
      btn.style.color = '';
    }, 1500);
  });
}
"""

def page_layout(title, content):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} | Vestorin Staging Explorer</title>
  <style>{CSS_STYLES}</style>
</head>
<body>
  <header>
    <div class="header-inner">
      <a href="/" class="logo-container">
        <div class="logo-icon">V</div>
        <div class="logo-text">Vestorin <span class="logo-badge">Staging Explorer</span></div>
      </a>
      <form action="/search" method="get" class="search-box">
        <input type="text" name="q" class="search-input font-mono" placeholder="Search by Address / Txn Hash / Block (0x... or 12345)" required autocomplete="off">
      </form>
    </div>
  </header>

  <main class="container">
    {content}
  </main>

  <footer>
    <div>Vestorin Staging Testnet (chainId 202627 / 0x31783) &bull; Tailnet Light Explorer</div>
    <div>Wolfram Host &bull; Local RPC 127.0.0.1:8545</div>
  </footer>

  <script>{JS_SCRIPTS}</script>
</body>
</html>"""


# ---------------------------------------------------------
# View Renderers
# ---------------------------------------------------------
def render_home(db: ExplorerDB):
    stats = db.get_stats()
    recent_txs = db.get_recent_transactions(15)
    recent_blocks = db.get_recent_blocks(8)

    tx_rows = ""
    for tx in recent_txs:
        val_vst = wei_to_vst(tx["value"])
        short_hash = f"{tx['hash'][:10]}...{tx['hash'][-8:]}"
        short_from = f"{tx['from_addr'][:8]}...{tx['from_addr'][-6:]}"
        short_to = f"{tx['to_addr'][:8]}...{tx['to_addr'][-6:]}" if tx['to_addr'] else "Contract Creation"
        status_badge = '<span class="badge badge-success">&#10003;</span>' if tx["status"] == 1 else '<span class="badge badge-fail">&#10007;</span>'
        tx_rows += f"""<tr>
          <td><a href="/tx/{tx['hash']}" class="font-mono">{short_hash}</a></td>
          <td><a href="/block/{tx['block_number']}">#{tx['block_number']}</a></td>
          <td>{time_ago(tx['timestamp'])}</td>
          <td><a href="/address/{tx['from_addr']}" class="font-mono">{short_from}</a></td>
          <td><a href="/address/{tx['to_addr']}" class="font-mono">{short_to}</a></td>
          <td class="font-mono" style="font-weight:600;">{val_vst} VST</td>
          <td>{status_badge}</td>
        </tr>"""

    block_rows = ""
    for b in recent_blocks:
        short_hash = f"{b['hash'][:10]}...{b['hash'][-8:]}"
        short_miner = f"{b['miner'][:8]}...{b['miner'][-6:]}" if b['miner'] else "Clique"
        block_rows += f"""<tr>
          <td><a href="/block/{b['number']}" style="font-weight:600;">#{b['number']}</a></td>
          <td><a href="/block/{b['hash']}" class="font-mono">{short_hash}</a></td>
          <td>{time_ago(b['timestamp'])}</td>
          <td>{b['tx_count']} txs</td>
          <td><a href="/address/{b['miner']}" class="font-mono">{short_miner}</a></td>
        </tr>"""

    content = f"""
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Network Name</div>
        <div class="stat-val">{CHAIN_NAME}</div>
        <div class="stat-sub">ChainId: {CHAIN_ID} (0x{CHAIN_ID:x})</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Indexed Block Height</div>
        <div class="stat-val">#{stats['headBlock']:,}</div>
        <div class="stat-sub">Clique Sealing @ ~5s / block</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Indexed Transactions</div>
        <div class="stat-val">{stats['totalTransactions']}</div>
        <div class="stat-sub">All-time Staging Chain Txs</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Staging Faucet Gas Price</div>
        <div class="stat-val">0 Gwei</div>
        <div class="stat-sub">Zero Gas Testnet Setting</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 1.5rem; background: rgba(31, 41, 55, 0.4);">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
        <div>
          <span style="font-weight:600; color:#fff;">Quick Links:</span>
          <a href="/address/0x28ff6e54D5e93a2Af588f1EDca82144F82aBFce2" class="badge badge-tag" style="margin-left:8px;">Pavel Cherkashin (0x28ff...fce2)</a>
          <a href="/address/0x1821dc3f0974339db7c7146037b40f54a2e222c3" class="badge badge-tag" style="margin-left:4px;">Operator Faucet (0x1821...22c3)</a>
          <a href="/tx/0xdc1ff48d2f470af79bbc277c4c17cb2d2347eeadf4191bf2564684bfb7694185" class="badge badge-tag" style="margin-left:4px;">Pavel Claim Tx (0xdc1f...4185)</a>
        </div>
      </div>
    </div>

    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 1.5rem;">
      <div class="card">
        <div class="card-header">
          <div class="card-title">Recent Transactions</div>
          <span style="font-size:0.8rem; color:var(--text-muted);">{len(recent_txs)} shown</span>
        </div>
        <div style="overflow-x:auto;">
          <table class="data-table">
            <thead>
              <tr>
                <th>Txn Hash</th>
                <th>Block</th>
                <th>Age</th>
                <th>From</th>
                <th>To</th>
                <th>Value</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {tx_rows if tx_rows else '<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:2rem;">No indexed transactions yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Recent Sample Blocks</div>
          <span style="font-size:0.8rem; color:var(--text-muted);">{len(recent_blocks)} shown</span>
        </div>
        <div style="overflow-x:auto;">
          <table class="data-table">
            <thead>
              <tr>
                <th>Block</th>
                <th>Hash</th>
                <th>Age</th>
                <th>Txs</th>
                <th>Miner</th>
              </tr>
            </thead>
            <tbody>
              {block_rows if block_rows else '<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:2rem;">Syncing blocks...</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
    return page_layout("Overview", content)


def render_tx(tx_hash, db: ExplorerDB):
    tx = db.get_tx(tx_hash)
    # If not in local db, attempt live query from geth
    if not tx:
        try:
            live_tx = rpc_call("eth_getTransactionByHash", [tx_hash])
            live_rec = rpc_call("eth_getTransactionReceipt", [tx_hash])
            if live_tx and live_rec:
                bnum = int(live_tx["blockNumber"], 16)
                blk = rpc_call("eth_getBlockByNumber", [hex(bnum), False])
                ts = int(blk["timestamp"], 16) if blk else int(time.time())
                tx = {
                    "hash": live_tx["hash"].lower(),
                    "block_number": bnum,
                    "block_hash": live_tx["blockHash"].lower(),
                    "tx_index": int(live_tx.get("transactionIndex", "0x0"), 16),
                    "from_addr": live_tx["from"].lower(),
                    "to_addr": live_tx["to"].lower() if live_tx.get("to") else "",
                    "value": str(int(live_tx.get("value", "0x0"), 16)),
                    "gas": int(live_tx.get("gas", "0x0"), 16),
                    "gas_price": str(int(live_tx.get("gasPrice", "0x0"), 16)),
                    "gas_used": int(live_rec.get("gasUsed", "0x0"), 16),
                    "effective_gas_price": str(int(live_rec.get("effectiveGasPrice", live_tx.get("gasPrice", "0x0")), 16)),
                    "status": int(live_rec.get("status", "0x1"), 16),
                    "input": live_tx.get("input", "0x"),
                    "nonce": int(live_tx.get("nonce", "0x0"), 16),
                    "timestamp": ts
                }
        except Exception as e:
            sys.stderr.write(f"Live tx fetch error: {e}\n")

    if not tx:
        content = f"""
        <div class="card" style="text-align:center; padding:3rem 1.5rem;">
          <h2 style="color:#ef4444; margin-bottom:1rem;">Transaction Not Found</h2>
          <p style="color:var(--text-muted); font-family:monospace; margin-bottom:1.5rem;">{tx_hash}</p>
          <p style="color:var(--text-dim); font-size:0.9rem;">This transaction hash does not exist in the staging chain or has not yet been indexed.</p>
          <a href="/" style="display:inline-block; margin-top:1.5rem;" class="badge badge-tag">&larr; Return to Home</a>
        </div>
        """
        return page_layout("Tx Not Found", content)

    val_vst = wei_to_vst(tx["value"], precision=18)
    gas_price_wei = int(tx["gas_price"])
    gas_price_gwei = gas_price_wei / 10**9
    gas_used = tx["gas_used"]
    gas_limit = tx["gas"]
    gas_pct = (gas_used / gas_limit * 100) if gas_limit else 0
    fee_wei = gas_used * int(tx.get("effective_gas_price", tx["gas_price"]))
    fee_vst = wei_to_vst(fee_wei, precision=18)
    status_badge = '<span class="badge badge-success">&#10003; Success</span>' if tx["status"] == 1 else '<span class="badge badge-fail">&#10007; Reverted</span>'

    from_label = KNOWN_LABELS.get(tx["from_addr"], "")
    to_label = KNOWN_LABELS.get(tx["to_addr"], "")
    from_label_html = f'<span class="badge badge-tag" style="margin-left:6px;">{from_label}</span>' if from_label else ""
    if tx["to_addr"]:
        to_label_html = f'<span class="badge badge-tag" style="margin-left:6px;">{to_label}</span>' if to_label else ""
        to_html = f'<a href="/address/{tx["to_addr"]}">{tx["to_addr"]}</a>{to_label_html}<button class="copy-btn" onclick="copyText(this, \'{tx["to_addr"]}\')">Copy</button>'
    else:
        to_html = '<span style="color:var(--text-muted);">Contract Creation</span>'

    content = f"""
    <div style="margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem;">
      <a href="/">&larr; Back</a>
      <span style="color:var(--text-dim);">/</span>
      <span style="font-weight:600; color:#fff;">Transaction Details</span>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Transaction Information</div>
        <div>{status_badge}</div>
      </div>

      <table class="kv-table">
        <tr>
          <td class="label">Transaction Hash:</td>
          <td class="value font-mono">
            {tx['hash']}
            <button class="copy-btn" onclick="copyText(this, '{tx['hash']}')">Copy</button>
          </td>
        </tr>
        <tr>
          <td class="label">Status:</td>
          <td class="value">{status_badge}</td>
        </tr>
        <tr>
          <td class="label">Block:</td>
          <td class="value">
            <a href="/block/{tx['block_number']}">#{tx['block_number']}</a>
            <span style="color:var(--text-dim); margin-left:8px; font-family:monospace; font-size:0.8rem;">({tx['block_hash']})</span>
          </td>
        </tr>
        <tr>
          <td class="label">Timestamp:</td>
          <td class="value">
            {time_ago(tx['timestamp'])} ({format_timestamp(tx['timestamp'])})
          </td>
        </tr>
        <tr>
          <td class="label">From:</td>
          <td class="value font-mono">
            <a href="/address/{tx['from_addr']}">{tx['from_addr']}</a>
            {from_label_html}
            <button class="copy-btn" onclick="copyText(this, '{tx['from_addr']}')">Copy</button>
          </td>
        </tr>
        <tr>
          <td class="label">To:</td>
          <td class="value font-mono">
            {to_html}
          </td>
        </tr>
        <tr>
          <td class="label">Value:</td>
          <td class="value" style="font-size:1.1rem; font-weight:700; color:var(--accent-cyan);">
            {val_vst} VST
            <span style="font-size:0.8rem; color:var(--text-dim); font-weight:normal; margin-left:8px;">({tx['value']} wei)</span>
          </td>
        </tr>
        <tr>
          <td class="label">Transaction Fee:</td>
          <td class="value font-mono">
            {fee_vst} VST
            <span style="font-size:0.8rem; color:var(--text-dim); margin-left:6px;">({fee_wei} wei)</span>
          </td>
        </tr>
        <tr>
          <td class="label">Gas Price:</td>
          <td class="value font-mono">
            {gas_price_gwei} Gwei ({gas_price_wei} wei)
          </td>
        </tr>
        <tr>
          <td class="label">Gas Limit & Gas Used:</td>
          <td class="value font-mono">
            {gas_used:,} / {gas_limit:,} ({gas_pct:.1f}%)
          </td>
        </tr>
        <tr>
          <td class="label">Nonce:</td>
          <td class="value font-mono">{tx['nonce']}</td>
        </tr>
        <tr>
          <td class="label">Input Data:</td>
          <td class="value font-mono" style="font-size:0.8rem; background:var(--bg-card-subtle); padding:0.5rem 0.75rem; border-radius:6px; max-height:120px; overflow-y:auto;">
            {tx['input']}
          </td>
        </tr>
      </table>
    </div>
    """
    return page_layout(f"Tx {tx_hash[:12]}...", content)


def render_address(address, db: ExplorerDB):
    addr_clean = address.lower()
    txs = db.get_txs_for_address(addr_clean)

    # Fetch live native balance from geth
    balance_vst = "0"
    balance_wei = 0
    tx_count_nonce = 0
    try:
        bal_hex = rpc_call("eth_getBalance", [addr_clean, "latest"])
        balance_wei = int(bal_hex, 16)
        balance_vst = wei_to_vst(balance_wei, precision=6)
        nonce_hex = rpc_call("eth_getTransactionCount", [addr_clean, "latest"])
        tx_count_nonce = int(nonce_hex, 16)
    except Exception as e:
        sys.stderr.write(f"Live balance fetch error: {e}\n")

    label = KNOWN_LABELS.get(addr_clean, "")
    label_html = f'<span class="badge badge-tag">{label}</span>' if label else ""

    tx_rows = ""
    for tx in txs:
        val_vst = wei_to_vst(tx["value"])
        is_sender = (tx["from_addr"] == addr_clean)
        dir_badge = '<span class="badge badge-out">OUT</span>' if is_sender else '<span class="badge badge-in">IN</span>'
        counterparty = tx["to_addr"] if is_sender else tx["from_addr"]
        counter_short = f"{counterparty[:8]}...{counterparty[-6:]}" if counterparty else "Contract Creation"
        counter_label = KNOWN_LABELS.get(counterparty, "")
        counter_label_html = f'<span class="badge badge-tag" style="margin-left:4px;">{counter_label}</span>' if counter_label else ""
        short_hash = f"{tx['hash'][:10]}...{tx['hash'][-8:]}"

        tx_rows += f"""<tr>
          <td><a href="/tx/{tx['hash']}" class="font-mono">{short_hash}</a></td>
          <td><a href="/block/{tx['block_number']}">#{tx['block_number']}</a></td>
          <td>{time_ago(tx['timestamp'])}</td>
          <td>{dir_badge}</td>
          <td class="font-mono">
            <a href="/address/{counterparty}">{counter_short}</a>
            {counter_label_html}
          </td>
          <td class="font-mono" style="font-weight:600; color:{'#fbbf24' if is_sender else '#34d399'};">
            {'-' if is_sender else '+'}{val_vst} VST
          </td>
          <td class="font-mono" style="color:var(--text-muted); font-size:0.75rem;">
            {wei_to_vst(int(tx['gas_used']) * int(tx.get('effective_gas_price', tx['gas_price'])))} VST
          </td>
        </tr>"""

    content = f"""
    <div style="margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem;">
      <a href="/">&larr; Back</a>
      <span style="color:var(--text-dim);">/</span>
      <span style="font-weight:600; color:#fff;">Address Overview</span>
    </div>

    <div class="card">
      <div class="card-header">
        <div style="display:flex; align-items:center; gap:0.75rem;">
          <div class="card-title">Address</div>
          {label_html}
        </div>
        <div class="font-mono" style="font-size:0.9rem; color:var(--text-muted);">
          {address}
          <button class="copy-btn" onclick="copyText(this, '{address}')">Copy</button>
        </div>
      </div>

      <div class="stats-grid" style="margin-bottom:0;">
        <div class="stat-card" style="background:var(--bg-card-subtle);">
          <div class="stat-label">Native VST Balance</div>
          <div class="stat-val" style="color:var(--accent-cyan);">{balance_vst} VST</div>
          <div class="stat-sub">{balance_wei:,} wei on-chain</div>
        </div>
        <div class="stat-card" style="background:var(--bg-card-subtle);">
          <div class="stat-label">On-Chain Nonce / Sent Txs</div>
          <div class="stat-val">{tx_count_nonce}</div>
          <div class="stat-sub">From eth_getTransactionCount</div>
        </div>
        <div class="stat-card" style="background:var(--bg-card-subtle);">
          <div class="stat-label">Indexed Transaction History</div>
          <div class="stat-val">{len(txs)}</div>
          <div class="stat-sub">Indexed Staging Transfers</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Transaction History ({len(txs)})</div>
      </div>
      <div style="overflow-x:auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Txn Hash</th>
              <th>Block</th>
              <th>Age</th>
              <th>Dir</th>
              <th>Counterparty</th>
              <th>Amount</th>
              <th>Tx Fee</th>
            </tr>
          </thead>
          <tbody>
            {tx_rows if tx_rows else '<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:2rem;">No transactions found for this address.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    """
    return page_layout(f"Address {address[:10]}...", content)


def render_block(num_or_hash, db: ExplorerDB):
    blk = None
    if str(num_or_hash).startswith("0x") or str(num_or_hash).startswith("0X"):
        blk = db.get_block_by_hash(num_or_hash)
        if not blk:
            try:
                raw_b = rpc_call("eth_getBlockByHash", [num_or_hash, False])
                if raw_b:
                    blk = {
                        "number": int(raw_b["number"], 16),
                        "hash": raw_b["hash"].lower(),
                        "parent_hash": raw_b.get("parentHash", "").lower(),
                        "timestamp": int(raw_b["timestamp"], 16),
                        "miner": raw_b.get("miner", "").lower(),
                        "gas_used": int(raw_b.get("gasUsed", "0x0"), 16),
                        "gas_limit": int(raw_b.get("gasLimit", "0x0"), 16),
                        "tx_count": len(raw_b.get("transactions", []))
                    }
            except Exception:
                pass
    else:
        try:
            bnum = int(num_or_hash)
            blk = db.get_block_by_number(bnum)
            if not blk:
                raw_b = rpc_call("eth_getBlockByNumber", [hex(bnum), False])
                if raw_b:
                    blk = {
                        "number": bnum,
                        "hash": raw_b["hash"].lower(),
                        "parent_hash": raw_b.get("parentHash", "").lower(),
                        "timestamp": int(raw_b["timestamp"], 16),
                        "miner": raw_b.get("miner", "").lower(),
                        "gas_used": int(raw_b.get("gasUsed", "0x0"), 16),
                        "gas_limit": int(raw_b.get("gasLimit", "0x0"), 16),
                        "tx_count": len(raw_b.get("transactions", []))
                    }
        except ValueError:
            pass

    if not blk:
        content = f"""
        <div class="card" style="text-align:center; padding:3rem 1.5rem;">
          <h2 style="color:#ef4444; margin-bottom:1rem;">Block Not Found</h2>
          <p style="color:var(--text-muted); font-family:monospace; margin-bottom:1.5rem;">{num_or_hash}</p>
          <a href="/" class="badge badge-tag">&larr; Return to Home</a>
        </div>
        """
        return page_layout("Block Not Found", content)

    txs = db.get_txs_for_block(blk["number"])
    miner_label = KNOWN_LABELS.get(blk["miner"], "")

    tx_rows = ""
    for tx in txs:
        val_vst = wei_to_vst(tx["value"])
        short_hash = f"{tx['hash'][:10]}...{tx['hash'][-8:]}"
        short_from = f"{tx['from_addr'][:8]}...{tx['from_addr'][-6:]}"
        short_to = f"{tx['to_addr'][:8]}...{tx['to_addr'][-6:]}" if tx['to_addr'] else "Contract Creation"
        tx_rows += f"""<tr>
          <td><a href="/tx/{tx['hash']}" class="font-mono">{short_hash}</a></td>
          <td><a href="/address/{tx['from_addr']}" class="font-mono">{short_from}</a></td>
          <td><a href="/address/{tx['to_addr']}" class="font-mono">{short_to}</a></td>
          <td class="font-mono">{val_vst} VST</td>
          <td><span class="badge badge-success">&#10003; Success</span></td>
        </tr>"""

    miner_label_html = f'<span class="badge badge-tag" style="margin-left:6px;">{miner_label}</span>' if miner_label else ""

    txs_card_html = ""
    if txs:
        txs_card_html = f"""
    <div class="card">
      <div class="card-header">
        <div class="card-title">Transactions in Block ({len(txs)})</div>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Txn Hash</th>
            <th>From</th>
            <th>To</th>
            <th>Value</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {tx_rows}
        </tbody>
      </table>
    </div>
    """

    content = f"""
    <div style="margin-bottom:1rem; display:flex; align-items:center; gap:0.5rem;">
      <a href="/">&larr; Back</a>
      <span style="color:var(--text-dim);">/</span>
      <span style="font-weight:600; color:#fff;">Block #{blk['number']}</span>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Block Details</div>
      </div>
      <table class="kv-table">
        <tr>
          <td class="label">Block Height:</td>
          <td class="value font-mono" style="font-weight:700; color:var(--accent-cyan);">#{blk['number']}</td>
        </tr>
        <tr>
          <td class="label">Block Hash:</td>
          <td class="value font-mono">
            {blk['hash']}
            <button class="copy-btn" onclick="copyText(this, '{blk['hash']}')">Copy</button>
          </td>
        </tr>
        <tr>
          <td class="label">Parent Hash:</td>
          <td class="value font-mono"><a href="/block/{blk['parent_hash']}">{blk['parent_hash']}</a></td>
        </tr>
        <tr>
          <td class="label">Timestamp:</td>
          <td class="value">{time_ago(blk['timestamp'])} ({format_timestamp(blk['timestamp'])})</td>
        </tr>
        <tr>
          <td class="label">Transactions:</td>
          <td class="value font-mono">{blk['tx_count']} transactions in this block</td>
        </tr>
        <tr>
          <td class="label">Miner / Sealer:</td>
          <td class="value font-mono">
            <a href="/address/{blk['miner']}">{blk['miner']}</a>
            {miner_label_html}
          </td>
        </tr>
        <tr>
          <td class="label">Gas Used / Limit:</td>
          <td class="value font-mono">{blk['gas_used']:,} / {blk['gas_limit']:,}</td>
        </tr>
      </table>
    </div>

    {txs_card_html}
    """
    return page_layout(f"Block #{blk['number']}", content)


# ---------------------------------------------------------
# Request Handler
# ---------------------------------------------------------
class ExplorerRequestHandler(BaseHTTPRequestHandler):
    db: ExplorerDB = None

    def send_html(self, html, code=200):
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        query = ""
        if "?" in self.path:
            query = self.path.split("?", 1)[1]

        if path == "" or path == "/":
            return self.send_html(render_home(self.db))

        if path == "/healthz" or path == "/health":
            return self.send_json({"ok": True, "chainId": CHAIN_ID, "timestamp": int(time.time())})

        if path == "/search":
            q = ""
            for param in query.split("&"):
                if param.startswith("q="):
                    q = urllib.parse.unquote_plus(param[2:]).strip()
            if not q:
                return self.send_redirect("/")
            if q.startswith("0x") or q.startswith("0X"):
                if len(q) == 66:
                    # Tx hash or block hash
                    tx = self.db.get_tx(q)
                    if tx:
                        return self.send_redirect(f"/tx/{q}")
                    b = self.db.get_block_by_hash(q)
                    if b:
                        return self.send_redirect(f"/block/{q}")
                    return self.send_redirect(f"/tx/{q}")
                elif len(q) == 42:
                    # Address
                    return self.send_redirect(f"/address/{q}")
            elif q.isdigit():
                # Block number
                return self.send_redirect(f"/block/{q}")
            return self.send_redirect("/")

        if path.startswith("/tx/"):
            tx_hash = path[4:]
            return self.send_html(render_tx(tx_hash, self.db))

        if path.startswith("/address/"):
            addr = path[9:]
            return self.send_html(render_address(addr, self.db))

        if path.startswith("/block/"):
            num_or_hash = path[7:]
            return self.send_html(render_block(num_or_hash, self.db))

        # API Endpoints
        if path == "/api/v1/stats":
            return self.send_json(self.db.get_stats())

        if path.startswith("/api/v1/tx/"):
            tx_hash = path[11:]
            tx = self.db.get_tx(tx_hash)
            if tx:
                return self.send_json(tx)
            return self.send_json({"error": "Tx not found"}, code=404)

        if path.startswith("/api/v1/address/"):
            addr = path[16:]
            txs = self.db.get_txs_for_address(addr)
            return self.send_json({"address": addr, "transactions": txs})

        if path.startswith("/api/v1/block/"):
            num_or_hash = path[14:]
            b = self.db.get_block_by_number(int(num_or_hash)) if num_or_hash.isdigit() else self.db.get_block_by_hash(num_or_hash)
            if b:
                return self.send_json(b)
            return self.send_json({"error": "Block not found"}, code=404)

        self.send_html(page_layout("404 Not Found", "<div class='card' style='text-align:center;'><h2>404 Page Not Found</h2><p><a href='/'>Return to Home</a></p></div>"), code=404)

    def log_message(self, format, *args):
        # Concise logging
        sys.stdout.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()


# ---------------------------------------------------------
# Self-Test Mode
# ---------------------------------------------------------
def run_self_test():
    print("=== Running Vestorin Staging Explorer Self-Test ===")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db") as tf:
        db = ExplorerDB(tf.name)
        print("[1/5] Database schema initialization: OK")

        # Test block and tx save
        test_block = {
            "number": 11621,
            "hash": "0xab584d309e8a4a4abe6e7f6a68a6389bd32a7b92601e3ff2b75201d4d17e08b2",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "timestamp": 1729860000,
            "miner": "0x0e5fde73cfd2e7fb4d164b5d6487dea645832401",
            "gasUsed": 21000,
            "gasLimit": 30000000,
            "tx_count": 1
        }
        test_tx = [{
            "hash": "0xdc1ff48d2f470af79bbc277c4c17cb2d2347eeadf4191bf2564684bfb7694185",
            "blockNumber": 11621,
            "blockHash": "0xab584d309e8a4a4abe6e7f6a68a6389bd32a7b92601e3ff2b75201d4d17e08b2",
            "transactionIndex": 0,
            "from": "0x1821dc3f0974339db7c7146037b40f54a2e222c3",
            "to": "0x28ff6e54d5e93a2af588f1edca82144f82abfce2",
            "value": str(21000000 * 10**18),
            "gas": 21000,
            "gasPrice": "0",
            "gasUsed": 21000,
            "effectiveGasPrice": "0",
            "status": 1,
            "input": "0x",
            "nonce": 2,
            "timestamp": 1729860000
        }]
        db.save_block_and_txs(test_block, test_tx)
        print("[2/5] Block & Transaction persistence: OK")

        # Test queries
        saved_tx = db.get_tx("0xdc1ff48d2f470af79bbc277c4c17cb2d2347eeadf4191bf2564684bfb7694185")
        assert saved_tx is not None, "Failed to retrieve saved tx"
        assert saved_tx["from_addr"] == "0x1821dc3f0974339db7c7146037b40f54a2e222c3".lower()
        assert saved_tx["to_addr"] == "0x28ff6e54d5e93a2af588f1edca82144f82abfce2".lower()
        print("[3/5] Transaction resolution by hash: OK")

        pavel_txs = db.get_txs_for_address("0x28ff6e54d5e93a2af588f1edca82144f82abfce2")
        assert len(pavel_txs) == 1, "Failed to resolve address txs for Pavel"
        faucet_txs = db.get_txs_for_address("0x1821dc3f0974339db7c7146037b40f54a2e222c3")
        assert len(faucet_txs) == 1, "Failed to resolve address txs for Faucet"
        print("[4/5] Address transaction history: OK")

        # Test HTML rendering
        home_html = render_home(db)
        assert "Vestorin Staging Explorer" in home_html
        tx_html = render_tx(saved_tx["hash"], db)
        assert "21,000,000 VST" in tx_html
        assert "Success" in tx_html
        addr_html = render_address("0x28ff6e54d5e93a2af588f1edca82144f82abfce2", db)
        assert "Pavel Cherkashin" in addr_html
        print("[5/5] HTML Page generation (Home, Tx, Address): OK")

    print("=== ALL 5 SELF-TESTS PASSED ===")


# ---------------------------------------------------------
# Main Server Runner
# ---------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    if "--self-test" in sys.argv:
        run_self_test()
        sys.exit(0)

    print(f"Starting Vestorin Staging Explorer...")
    print(f"  RPC URL:   {GETH_RPC}")
    print(f"  Listen:    http://{BIND_HOST}:{BIND_PORT}")
    print(f"  Database:  {DB_PATH}")

    db = ExplorerDB(DB_PATH)

    # Start synchronizer thread
    sync_thread = Synchronizer(db, rpc_url=GETH_RPC)
    sync_thread.start()
    print("  Background synchronizer started.")

    ExplorerRequestHandler.db = db
    server = ThreadedHTTPServer((BIND_HOST, BIND_PORT), ExplorerRequestHandler)

    try:
        print(f"Explorer HTTP server listening at http://{BIND_HOST}:{BIND_PORT}")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down explorer...")
        sync_thread.running = False
        server.server_close()

if __name__ == "__main__":
    main()
