#!/usr/bin/env python3
import os
import sys
import json
import asyncio
import logging
import signal
import base58
import aiohttp
import websockets
from websockets.exceptions import ConnectionClosed
from dotenv import load_dotenv
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

# ─── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scamsniper")

# ─── Raydium & Aggregator Program IDs ──────────────────────────────────────────
RAY_PROGRAM_IDS = {
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",   # legacy CPMM
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",   # V3 LP
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",   # V4 LP
    "AveaiuA1emN71q9mS2QQ9BEWNAAHmp8sHSvwLFHQjufM"    # aggregator seen in dumps
}

# ─── Load Config ───────────────────────────────────────────────────────────────
load_dotenv()
try:
    C = json.load(open("config.json"))
except FileNotFoundError:
    log.error("config.json not found")
    sys.exit(1)

RPC_URL      = C["RPC_URL"]
WS_URL       = C["WS_URL"]
PUMP_API_URL = C["PUMP_API_URL"]
SOL_MINT     = C["SOL_MINT"]
BUY_SOL      = C["BUY_SOL"]           # e.g. 0.02 SOL
SLIPPAGE_BPS = C["SLIPPAGE_BPS"]      # e.g. 150 for 1.5%
PRIORITY_FEE = 0.0007                 # 0.0007 SOL for Jito tip
POOL         = "auto"
TARGET_PUBS  = C["TARGET_PUBS"]

# ─── Wallet Setup ──────────────────────────────────────────────────────────────
pk_b58 = os.getenv("SOLANA_PRIVATE_KEY", "")
if not pk_b58:
    log.error("SOLANA_PRIVATE_KEY missing"); sys.exit(1)
try:
    keypair = Keypair.from_base58_string(pk_b58)
except Exception as e:
    log.error(f"Invalid SOLANA_PRIVATE_KEY: {e}"); sys.exit(1)
WALLET = Pubkey.from_string(str(keypair.pubkey()))
log.info(f"Using wallet {WALLET}")

# ─── RPC Helpers ───────────────────────────────────────────────────────────────
async def rpc_request(method: str, params):
    async with aiohttp.ClientSession() as sess:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        try:
            async with sess.post(RPC_URL, json=payload) as r:
                resp = await r.json()
                if r.status != 200 or "error" in resp:
                    log.error(f"RPC {method} failed: {resp.get('error','Unknown error')}")
                    return {}
                return resp
        except Exception as e:
            log.error(f"RPC {method} failed: {e}")
            return {}

async def fetch_tx(sig: str) -> dict:
    res = await rpc_request("getTransaction", [
        sig,
        {"encoding":"jsonParsed","commitment":"confirmed","maxSupportedTransactionVersion":0}
    ])
    return res.get("result", {}) or {}

# ─── Mint Extraction ───────────────────────────────────────────────────────────
def find_mint(tx: dict) -> str | None:
    # 1) top-level parsed instructions
    for instr in tx.get("transaction", {}).get("message", {}).get("instructions", []):
        m = instr.get("parsed", {}).get("info", {}).get("mint")
        if m and m != SOL_MINT:
            return m
    # 2) inner instructions
    for grp in tx.get("meta", {}).get("innerInstructions", []):
        for instr in grp.get("instructions", []):
            m = instr.get("parsed", {}).get("info", {}).get("mint")
            if m and m != SOL_MINT:
                return m
    # 3) fallback to accountKeys[3], [4], [10]
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    for idx in (3, 4, 10):
        if len(keys) > idx:
            entry = keys[idx]
            if isinstance(entry, dict):
                entry = entry.get("pubkey")
            if entry and entry != SOL_MINT:
                return entry
    return None

# ─── Trade via PumpPortal + Jito Single Transaction ─────────────────────────────
async def do_trade(mint: str, action: str, retries: int = 3) -> bool:
    async def send_single_trade(act: str, payload: dict) -> bool:
        log.info(f"→ {act.upper()} payload: {payload}")
        async with aiohttp.ClientSession() as sess:
            for attempt in range(1, retries + 1):
                try:
                    async with sess.post(PUMP_API_URL, json=[payload]) as resp:
                        if resp.status != 200:
                            txt = await resp.text()
                            log.error(f"/trade-local {act} failed {resp.status}: {txt}")
                            if attempt < retries:
                                await asyncio.sleep(1)
                                continue
                            return False
                        enc = await resp.json()
                        break
                except Exception as e:
                    log.error(f"/trade-local {act} attempt {attempt} failed: {e}")
                    if attempt < retries:
                        await asyncio.sleep(1)
                        continue
                    return False

        try:
            raw = base58.b58decode(enc[0])
            base_tx = VersionedTransaction.from_bytes(raw)
            signed_tx = VersionedTransaction(base_tx.message, [keypair])
            encoded = base58.b58encode(bytes(signed_tx)).decode()
            sig = str(signed_tx.signatures[0])

            jito_payload = {"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[encoded]}
            async with aiohttp.ClientSession() as sess:
                jito_resp = await sess.post(
                    "https://ny.mainnet.block-engine.jito.wtf/api/v1/transactions",
                    json=jito_payload
                )
                if jito_resp.status != 200:
                    txt = await jito_resp.text()
                    log.error(f"Jito {act} failed {jito_resp.status}: {txt}")
                    return False
            log.info(f"{act.upper()} → https://solscan.io/tx/{sig}")
            return True
        except Exception as e:
            log.error(f"{act.upper()} signing/Jito error: {e}")
            return False

    buy_payload = {
        "publicKey": str(WALLET), "action": "buy",  "mint": mint,
        "amount": BUY_SOL, "denominatedInSol": "true",
        "slippage": SLIPPAGE_BPS/100.0, "priorityFee": PRIORITY_FEE, "pool": POOL
    }
    sell_payload = {
        "publicKey": str(WALLET), "action": "sell", "mint": mint,
        "amount": "100%", "denominatedInSol": "false",
        "slippage": SLIPPAGE_BPS/100.0, "priorityFee": PRIORITY_FEE, "pool": POOL
    }

    if action in ("buy", "both"):
        if not await send_single_trade("buy", buy_payload):
            log.error(f"BUY failed for mint {mint}")
            return False
    if action in ("sell", "both"):
        if not await send_single_trade("sell", sell_payload):
            log.error(f"SELL failed for mint {mint}")
            return False
    return True

# ─── Raydium Swap Detector & Helpers ──────────────────────────────────────────
def is_ray_swap(tx: dict) -> bool:
    groups = [tx["transaction"]["message"]["instructions"]]
    groups += [grp["instructions"] for grp in tx["meta"].get("innerInstructions", [])]
    for instrs in groups:
        for instr in instrs:
            pid = instr.get("programId")
            if pid in RAY_PROGRAM_IDS:
                return True
            parsed = instr.get("parsed", {})
            if isinstance(parsed, dict) and "type" in parsed:
                if "swap" in parsed["type"].lower():
                    return True
    return False

def determine_action(tx: dict) -> str | None:
    pre  = {b["mint"]:b for b in tx["meta"].get("preTokenBalances", [])}
    post = {b["mint"]:b for b in tx["meta"].get("postTokenBalances", [])}
    wdiff = post.get(SOL_MINT,{}).get("uiTokenAmount",{}).get("uiAmount",0) - \
            pre.get(SOL_MINT,{}).get("uiTokenAmount",{}).get("uiAmount",0)
    for mint, bal in post.items():
        if mint == SOL_MINT: continue
        tdiff = bal["uiTokenAmount"]["uiAmount"] - pre.get(mint,{}).get("uiTokenAmount",{}).get("uiAmount",0)
        if wdiff < 0 and tdiff > 0: return "buy"
        if wdiff > 0 and tdiff < 0: return "sell"
    return None

# ─── WS Handler & Main Loop ───────────────────────────────────────────────────
async def handle_logs(msg: str):
    data = json.loads(msg)
    if data.get("method") != "logsNotification":
        return

    v    = data["params"]["result"]["value"]
    sig0 = v["signature"]
    logs = v["logs"]

    if any("exceededslippage" in L.lower() for L in logs):
        return

    tx0 = await fetch_tx(sig0)
    if not tx0:
        return

    # filter: any buy/sell log or Raydium swap
    if not (any("buy" in L.lower() or "sell" in L.lower() for L in logs)
            or is_ray_swap(tx0)):
        return

    action = determine_action(tx0)
    if not action:
        return

    mint = find_mint(tx0)
    if not mint:
        log.warning(f"No mint for {sig0}")
        return

    log.info(f"↗ ACTION {action.upper()} → sig={sig0} | mint={mint}")
    if not await do_trade(mint, action):
        log.error(f"{action.upper()} failed for mint {mint}")

async def main():
    stop = asyncio.Event()
    loop = asyncio.get_event_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop.set)

    while not stop.is_set():
        try:
            async with websockets.connect(WS_URL, ping_interval=30, ping_timeout=10) as ws:
                log.info("WS connected")
                for i, pub in enumerate(TARGET_PUBS, start=1):
                    sub = {
                        "jsonrpc": "2.0", "id": i,
                        "method": "logsSubscribe",
                        "params": [{"mentions": [pub]}, {"commitment": "confirmed"}]
                    }
                    await ws.send(json.dumps(sub))
                while not stop.is_set():
                    try:
                        msg = await ws.recv()
                        if isinstance(msg, bytes):
                            continue
                        await handle_logs(msg)
                    except ConnectionClosed as e:
                        log.error(f"WS closed: {e}; reconnecting in 5s")
                        break
                    except Exception as e:
                        log.error(f"Error processing message: {e}")
        except Exception as e:
            log.error(f"WS error: {e}; reconnecting in 5s")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())

