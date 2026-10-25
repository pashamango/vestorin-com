# Vestorin Staging Light Explorer (chainId 202627)

Ultra-lightweight block, transaction, and address explorer for the Vestorin Staging network. Designed to resolve MetaMask transaction and address links over Tailnet HTTPS.

## Architecture

- **Runtime**: Python 3 standard library (`http.server`, `urllib.request`, `sqlite3`, `json`, `threading`). Zero external dependencies or node modules.
- **RPC Upstream**: Local geth node at `http://127.0.0.1:8545` (Clique consensus, chainId 202627 / `0x31783`).
- **Storage**: SQLite WAL mode (`vestorin_explorer.db`). Stores block metadata and indexed transaction records with fast lookups.
- **Sync Engine**: Background thread scanning blocks via JSON-RPC batching. Syncs in real-time as blocks are sealed (~5s interval).
- **Frontend**: Clean server-rendered HTML/CSS with monospace hash formatting, copy buttons, IN/OUT address direction indicators, and live on-chain balances via `eth_getBalance`.
- **HTTPS Termination**: Served over Tailscale via Let's Encrypt / MagicDNS certificate on `https://wolfram.tail94aa6c.ts.net:8547/`. Tailnet-only; zero public exposure.

## Endpoints

- `GET /` — Explorer Overview (network stats, search bar, recent transactions, sample blocks, quick links)
- `GET /tx/<txHash>` — Transaction detail page (from, to, value, gasPrice, gasUsed, fee, block, status, input)
- `GET /address/<address>` — Address detail page (live native VST balance from geth, nonce, full indexed transaction history)
- `GET /block/<blockNumOrHash>` — Block detail page (height, hash, parentHash, timestamp, sealer, gas, tx count)
- `GET /search?q=<query>` — Universal search redirect (supports 66-char tx/block hashes, 42-char addresses, decimal block numbers)
- `GET /api/v1/stats` — JSON statistics (`chainId`, `headBlock`, `totalTransactions`)
- `GET /api/v1/tx/<txHash>` — JSON transaction record
- `GET /api/v1/address/<addr>` — JSON address transactions
- `GET /api/v1/block/<num>` — JSON block record
- `GET /healthz` — Health check endpoint

## MetaMask Integration

To wire into MetaMask via `wallet_addEthereumChain` (EIP-3085):

```javascript
await window.ethereum.request({
  method: 'wallet_addEthereumChain',
  params: [{
    chainId: '0x31783', // 202627
    chainName: 'Vestorin Staging',
    nativeCurrency: { name: 'Vestorin', symbol: 'VST', decimals: 18 },
    rpcUrls: ['http://100.77.188.3:8546'],
    blockExplorerUrls: ['https://wolfram.tail94aa6c.ts.net:8547']
  }]
});
```

When users click transaction links or view their address in MetaMask, MetaMask navigates to:
- `https://wolfram.tail94aa6c.ts.net:8547/tx/<txHash>`
- `https://wolfram.tail94aa6c.ts.net:8547/address/<address>`

## Self-Test

To verify all internal components and HTML renderers:

```bash
python3 vestorin_staging_explorer.py --self-test
```
