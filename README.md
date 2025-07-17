# Solana PumpFun / Raydium Sniper Bot

A high-speed, Python-only Solana trading bot that monitors on-chain logs in real time and automatically executes PumpFun trades (via Raydium pools) through Jito. Ideal for educational & experimental purposes.

---

## 🚀 Features

- **WebSocket logs subscription**  
  Connects to your Solana RPC's `logsSubscribe` endpoint and watches for your target program IDs.

- **Programmable filters**  
  - Skips any “exceeded slippage” failures  
  - Detects both PumpFun log markers (`buy`/`sell` strings) **and** direct Raydium swap instructions  
  - Supports both legacy CPMM and v4 Raydium program IDs

- **Buy/Sell direction detection**  
  Compares pre- and post-transaction token balances (SOL vs. target token) to decide whether to `buy` or `sell`.

- **Automated trade execution**  
  - Builds a local PumpFun payload, fetches the raw single-transaction bundle  
  - Signs it with your keypair and sends it through Jito’s RPC endpoint  
  - Logs Solscan links on success

- **Resilient connection handling**  
  Auto-reconnects on WebSocket or RPC failures, with configurable ping intervals & timeouts.

---

## 📋 Prerequisites

- Python 3.10+  
- A Solana RPC endpoint & WebSocket URL (mainnet-beta)  
- A PumpFun local-trade API URL  
- A funded Solana keypair (for signing & paying fees)  
- Jito access (public endpoint `/api/v1/transactions`)

---

## 🔧 Installation

```bash
git clone https://github.com/your-username/solana-sniper-bot.git
cd solana-sniper-bot
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
````

---

## ⚙️ Configuration

Copy & edit `config.example.json` to `config.json`:

```json
{
  "RPC_URL":      "https://api.mainnet-beta.solana.com",
  "WS_URL":       "wss://api.mainnet-beta.solana.com",
  "PUMP_API_URL": "https://pumpportal.fun/api/trade-local",
  "SOL_MINT":     "So11111111111111111111111111111111111111112",
  "BUY_SOL":      "0.02",
  "SLIPPAGE_BPS": 150,
  "TARGET_PUBS":  ["<YourTargetProgramID1>", "<YourTargetProgramID2>"]
}
```

Then set your private key in `.env`:

```bash
SOLANA_PRIVATE_KEY=<your_base58_private_key>
```

---

## ▶️ Usage

```bash
python bot.py
```

The bot will:

1. Connect & subscribe to logs for each `TARGET_PUBS`.
2. On each incoming notification:

   * Fetch the full transaction via RPC (with `maxSupportedTransactionVersion=0`).
   * Dump raw instruction JSON (for debugging/filter tuning).
   * Filter by slippage failures, buy/sell keywords, and Raydium swap types.
   * Determine `buy` vs. `sell` from balance deltas.
   * Extract the token mint.
   * Call PumpFun API & send through Jito.

---

## 🛡️ Disclaimer

> **Educational use only.**
> Automated trading on Solana carries significant financial risk. Use at your own risk, with minimal funds on test accounts first.

---

## 📄 License

MIT © \[Your Name]

```

**Key points to include in your GitHub repo:**

- A `requirements.txt` listing:
```

aiohttp
websockets
python-dotenv
solders


