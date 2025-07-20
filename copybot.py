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
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scamsniper")

# ─── Program IDs ───────────────────────────────────────────────────────────────
PUMP_AMM_PROGRAM_ID = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"  # PumpSwap
RAY_PROGRAM_IDS = {
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",  # CPMM
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",  # V4 LP
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",   # V3 LP
    "AveaiuA1emN71q9mS2QQ9BEWNAAHmp8sHSvwLFHQjufM",  # Aggregator
    "LPTvU5gW4F7NjL7PhwnL5kQxx2SwYDLRV7BKB3Pumjk"   # LaunchLab
}
PHOTON_PROGRAM_ID = "BSfD6SHZigAfDWSjzD5Q41jw8LmKwtmjskPH9XW1mrRW"  # Photon Program

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
BUY_SOL      = C["BUY_SOL"]
SLIPPAGE_BPS = 500  # 5%
PRIORITY_FEE = 0.001  # 0.001 SOL
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
    global log
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
    global log
    res = await rpc_request("getTransaction", [
        sig,
        {"encoding":"jsonParsed","commitment":"confirmed","maxSupportedTransactionVersion":0}
    ])
    return res.get("result", {}) or {}

# ─── Mint Extraction ───────────────────────────────────────────────────────────
def find_mint(tx: dict, action: str, is_pump: bool, is_launchlab: bool, is_photon: bool) -> str | None:
    global log
    platform = "Pump.fun" if is_pump else "Raydium LaunchLab" if is_launchlab else "Photon" if is_photon else "Raydium"
    for instr in tx.get("transaction", {}).get("message", {}).get("instructions", []):
        parsed = instr.get("parsed", {})
        info = parsed.get("info", {})
        log.debug(f"Parsed outer instruction: {parsed}")
        if parsed.get("type") in ["transferChecked", "transfer"]:
            mint = info.get("mint") or info.get("account")
            if mint and mint != SOL_MINT:
                if action == "buy" and info.get("destination") and (info.get("source") != mint or not info.get("source")):
                    log.debug(f"{platform} buy mint: {mint}")
                    return mint
                if action == "sell" and (info.get("source") == mint or info.get("account") == mint):
                    log.debug(f"{platform} sell mint: {mint}")
                    return mint
    for grp in tx.get("meta", {}).get("innerInstructions", []):
        for instr in grp.get("instructions", []):
            parsed = instr.get("parsed", {})
            info = parsed.get("info", {})
            log.debug(f"Parsed inner instruction: {parsed}")
            if parsed.get("type") in ["transferChecked", "transfer"]:
                mint = info.get("mint") or info.get("account")
                if mint and mint != SOL_MINT:
                    if action == "buy" and info.get("destination") and (info.get("source") != mint or not info.get("source")):
                        log.debug(f"{platform} buy mint: {mint}")
                        return mint
                    if action == "sell" and (info.get("source") == mint or info.get("account") == mint):
                        log.debug(f"{platform} sell mint: {mint}")
                        return mint
    # Fallback to account keys
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    for idx in (3, 4, 10):
        if len(keys) > idx:
            entry = keys[idx]
            if isinstance(entry, dict):
                entry = entry.get("pubkey")
            if entry and entry != SOL_MINT:
                log.debug(f"Fallback mint from accountKeys[{idx}]: {entry}")
                return entry
    return None

# ─── Trade via PumpPortal + Jito Single Transaction ─────────────────────────────
async def do_trade(mint: str, action: str, retries: int = 5) -> bool:
    global log
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
                                await asyncio.sleep(2)
                                continue
                            return False
                        enc = await resp.json()
                        break
                except Exception as e:
                    log.error(f"/trade-local {act} attempt {attempt} failed: {e}")
                    if attempt < retries:
                        await asyncio.sleep(2)
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
        "publicKey": str(WALLET), "action": "buy", "mint": mint,
        "amount": BUY_SOL, "denominatedInSol": "true",
        "slippage": SLIPPAGE_BPS/100.0, "priorityFee": PRIORITY_FEE, "pool": POOL
    }
    sell_payload = {
        "publicKey": str(WALLET), "action": "sell", "mint": mint,
        "amount": "100%", "denominatedInSol": "false",
        "slippage": SLIPPAGE_BPS/100.0, "priorityFee": PRIORITY_FEE, "pool": POOL,
        "wrapAndUnwrapSol": True
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

# ─── Swap Detector & Helpers ───────────────────────────────────────────────────
def is_pump_swap(tx: dict) -> bool:
    global log
    groups = [tx["transaction"]["message"]["instructions"]]
    groups += [grp["instructions"] for grp in tx["meta"].get("innerInstructions", [])]
    for instrs in groups:
        for instr in instrs:
            if instr.get("programId") == PUMP_AMM_PROGRAM_ID:
                log.debug("Detected Pump.fun AMM program")
                return True
            parsed = instr.get("parsed", {})
            if isinstance(parsed, dict) and parsed.get("type") in ["transferChecked", "transfer", "createIdempotent", "initializeAccount3"]:
                log.debug("Pump.fun swap-related instruction detected")
                return True
    return False

def is_ray_swap(tx: dict) -> bool:
    global log
    groups = [tx["transaction"]["message"]["instructions"]]
    groups += [grp["instructions"] for grp in tx["meta"].get("innerInstructions", [])]
    for instrs in groups:
        for instr in instrs:
            if instr.get("programId") in RAY_PROGRAM_IDS and instr.get("programId") != "LPTvU5gW4F7NjL7PhwnL5kQxx2SwYDLRV7BKB3Pumjk":
                log.debug("Detected Raydium program")
                return True
            parsed = instr.get("parsed", {})
            if isinstance(parsed, dict) and parsed.get("type") in ["transferChecked", "transfer", "createIdempotent", "initializeAccount3"]:
                log.debug("Raydium swap-related instruction detected")
                return True
    return False

def is_ray_launchlab_swap(tx: dict) -> bool:
    global log
    groups = [tx["transaction"]["message"]["instructions"]]
    groups += [grp["instructions"] for grp in tx["meta"].get("innerInstructions", [])]
    for instrs in groups:
        for instr in instrs:
            if instr.get("programId") == "LPTvU5gW4F7NjL7PhwnL5kQxx2SwYDLRV7BKB3Pumjk":
                log.debug("Detected Raydium LaunchLab program")
                return True
            parsed = instr.get("parsed", {})
            if isinstance(parsed, dict) and parsed.get("type") in ["transferChecked", "transfer", "createIdempotent", "initializeAccount3"]:
                log.debug("Raydium LaunchLab swap-related instruction detected")
                return True
    return False

def is_photon_swap(tx: dict) -> bool:
    global log
    groups = [tx["transaction"]["message"]["instructions"]]
    groups += [grp["instructions"] for grp in tx["meta"].get("innerInstructions", [])]
    for instrs in groups:
        for instr in instrs:
            if instr.get("programId") == PHOTON_PROGRAM_ID:
                log.debug("Detected Photon program")
                return True
            parsed = instr.get("parsed", {})
            if isinstance(parsed, dict) and parsed.get("type") in ["transferChecked", "transfer", "createIdempotent", "initializeAccount3"]:
                log.debug("Photon swap-related instruction detected")
                return True
    return False

def determine_action(tx: dict) -> str | None:
    global log
    sig = tx.get("transaction", {}).get("signatures", [""])[0]
    log.debug(f"Parsing instructions for tx: {sig}")
    is_pump = is_pump_swap(tx)
    is_launchlab = is_ray_launchlab_swap(tx)
    is_photon = is_photon_swap(tx)
    is_ray = is_ray_swap(tx) and not is_launchlab
    platform = "Pump.fun" if is_pump else "Raydium LaunchLab" if is_launchlab else "Photon" if is_photon else "Raydium"

    # Track WSOL/SOL and token transfers
    wsol_transfer = None
    token_transfer = None
    is_swap_log = False

    # Check logs for swap indicators
    logs = tx.get("meta", {}).get("logMessages", [])
    for log_msg in logs:
        if any(s in log_msg.lower() for s in ["raydium:swap", "photon", "swap"]):
            log.debug(f"{platform} swap detected in logs: {log_msg}")
            is_swap_log = True
            break

    # Check outer instructions
    outer_instructions = tx.get("transaction", {}).get("message", {}).get("instructions", [])
    for instr in outer_instructions:
        parsed = instr.get("parsed", {})
        info = parsed.get("info", {})
        log.debug(f"Parsed outer instruction: {parsed}")
        if parsed.get("type") == "transferChecked":
            mint = info.get("mint")
            if mint == SOL_MINT and info.get("destination"):
                wsol_transfer = info
                log.debug(f"{platform} WSOL transferChecked detected: {info}")
            elif mint and mint != SOL_MINT and info.get("source") == mint:
                token_transfer = info
                log.debug(f"{platform} token transferChecked detected (sell): {info}")
            elif mint and mint != SOL_MINT and info.get("destination") and info.get("source") != mint:
                log.debug(f"{platform} action: buy (token received)")
                return "buy"
        elif parsed.get("type") in ["transfer", "createIdempotent", "initializeAccount3"]:
            if info.get("destination") == str(WALLET) or info.get("lamports") or info.get("account") == str(WALLET):
                wsol_transfer = info
                log.debug(f"{platform} WSOL/SOL transfer detected: {info}")
            elif info.get("account") and info.get("account") != SOL_MINT:
                token_transfer = info
                log.debug(f"{platform} token transfer detected (sell): {info}")
            elif info.get("mint") and info.get("mint") != SOL_MINT and info.get("destination"):
                token_transfer = info
                log.debug(f"{platform} token transfer detected (buy): {info}")

    # Check inner instructions
    inner_groups = tx.get("meta", {}).get("innerInstructions", [])
    for grp in inner_groups:
        for instr in grp.get("instructions", []):
            parsed = instr.get("parsed", {})
            info = parsed.get("info", {})
            log.debug(f"Parsed inner instruction: {parsed}")
            if parsed.get("type") == "transferChecked":
                mint = info.get("mint")
                if mint == SOL_MINT and info.get("destination"):
                    wsol_transfer = info
                    log.debug(f"{platform} WSOL transferChecked detected: {info}")
                elif mint and mint != SOL_MINT and info.get("source") == mint:
                    token_transfer = info
                    log.debug(f"{platform} token transferChecked detected (sell): {info}")
                elif mint and mint != SOL_MINT and info.get("destination") and info.get("source") != mint:
                    log.debug(f"{platform} action: buy (token received)")
                    return "buy"
            elif parsed.get("type") in ["transfer", "createIdempotent", "initializeAccount3"]:
                if info.get("destination") == str(WALLET) or info.get("lamports") or info.get("account") == str(WALLET):
                    wsol_transfer = info
                    log.debug(f"{platform} WSOL/SOL transfer detected: {info}")
                elif info.get("account") and info.get("account") != SOL_MINT:
                    token_transfer = info
                    log.debug(f"{platform} token transfer detected (sell): {info}")
                elif info.get("mint") and info.get("mint") != SOL_MINT and info.get("destination"):
                    token_transfer = info
                    log.debug(f"{platform} token transfer detected (buy): {info}")

    # Determine action based on transfers and platform
    if is_swap_log or is_photon or is_pump or is_ray or is_launchlab:
        if wsol_transfer and token_transfer:
            log.debug(f"{platform} action: sell (WSOL/SOL received, token sent)")
            return "sell"
        if token_transfer and not wsol_transfer and any(info.get(key) for key in ["destination", "account", "mint"] if key in info):
            log.debug(f"{platform} action: buy (token received)")
            return "buy"

    log.debug(f"No clear buy/sell action detected, logMessages: {logs}")
    return None

# ─── WS Handler & Main Loop ───────────────────────────────────────────────────
async def handle_logs(msg: str):
    global log
    data = json.loads(msg)
    if data.get("method") != "logsNotification":
        return

    v = data["params"]["result"]["value"]
    sig0 = v["signature"]
    logs = v["logs"]

    if any("exceededslippage" in L.lower() for L in logs):
        log.debug(f"Skipping tx {sig0} due to slippage error")
        return

    tx0 = await fetch_tx(sig0)
    if not tx0:
        log.debug(f"No transaction data for {sig0}")
        return

    # Process transactions with swap-related indicators or platform programs
    if not (any(s in L.lower() for L in logs for s in ["buy", "sell", "raydium:swap", "photon", "swap"]) or 
            is_pump_swap(tx0) or is_ray_swap(tx0) or is_ray_launchlab_swap(tx0) or is_photon_swap(tx0)):
        log.debug(f"Tx {sig0} does not match buy/sell, raydium:swap, photon, or Pump/Raydium/LaunchLab swap criteria")
        return

    action = determine_action(tx0)
    if not action:
        log.debug(f"No buy/sell action detected for sig={sig0}")
        return

    mint = find_mint(tx0, action, is_pump_swap(tx0), is_ray_launchlab_swap(tx0), is_photon_swap(tx0))
    if not mint:
        log.warning(f"No mint for {sig0}")
        return

    log.info(f"↗ ACTION {action.upper()} → sig={sig0} | mint={mint}")
    if not await do_trade(mint, action):
        log.error(f"{action.upper()} failed for mint {mint}")

async def main():
    global log
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
    # Clear cached bytecode
    import shutil
    cache_dir = os.path.join(os.path.dirname(__file__), "__pycache__")
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)
    asyncio.run(main())
