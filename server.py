import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
ENV_FILE = BASE_DIR / ".env"
RIA_FILE = BASE_DIR / "ria_holdings.json"
CAPITAL_FILE = BASE_DIR / "capital_ledger.json"

TOSS_BASE_URL = "https://openapi.tossinvest.com"

SENSITIVE_ENV_KEYS = {
    "TOSS_CLIENT_ID",
    "TOSS_CLIENT_SECRET",
    "KIS_1_CANO",
    "KIS_1_APP_KEY",
    "KIS_1_APP_SECRET",
    "KIS_2_CANO",
    "KIS_2_APP_KEY",
    "KIS_2_APP_SECRET",
    "KIS_3_CANO",
    "KIS_3_APP_KEY",
    "KIS_3_APP_SECRET",
    "KIS_4_CANO",
    "KIS_4_APP_KEY",
    "KIS_4_APP_SECRET",
}

_CRYPTO_LOCK = threading.RLock()
_UNLOCKED_MASTER_PW = None
_DECRYPTED_ENV_CACHE = {}
PBKDF2_ITERATIONS = 200_000


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    return f"PBKDF2${PBKDF2_ITERATIONS}${_b64e(salt)}${_b64e(dk)}"


def verify_password_hash(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash or not stored_hash.startswith("PBKDF2$"):
            return False
        _, iter_str, salt_b64, dk_b64 = stored_hash.split("$", 3)
        iters = int(iter_str)
        salt = _b64d(salt_b64)
        expected_dk = _b64d(dk_b64)
        actual_dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=len(expected_dk))
        return hmac.compare_digest(actual_dk, expected_dk)
    except Exception:
        return False


def _keystream_xor(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    block_idx = 0
    offset = 0
    while offset < len(data):
        counter_bytes = block_idx.to_bytes(8, "big")
        ks_block = hmac.new(enc_key, nonce + counter_bytes, hashlib.sha256).digest()
        chunk_len = min(32, len(data) - offset)
        for i in range(chunk_len):
            out[offset + i] = data[offset + i] ^ ks_block[i]
        offset += chunk_len
        block_idx += 1
    return bytes(out)


def encrypt_secret(plaintext: str, password: str) -> str:
    if plaintext is None or plaintext == "" or plaintext.startswith("ENC$v1$"):
        return plaintext
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key_mat = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64)
    enc_key, mac_key = key_mat[:32], key_mat[32:]
    pt_bytes = plaintext.encode("utf-8")
    ct_bytes = _keystream_xor(pt_bytes, enc_key, nonce)
    mac = hmac.new(mac_key, salt + nonce + ct_bytes, hashlib.sha256).digest()
    return f"ENC$v1${_b64e(salt)}${_b64e(nonce)}${_b64e(ct_bytes)}${_b64e(mac)}"


def decrypt_secret(token: str, password: str) -> str:
    if not token or not token.startswith("ENC$v1$"):
        return token
    parts = token.split("$")
    if len(parts) != 6:
        raise ValueError("잘못된 암호문 형식입니다.")
    _, _, salt_b64, nonce_b64, ct_b64, mac_b64 = parts
    salt = _b64d(salt_b64)
    nonce = _b64d(nonce_b64)
    ct_bytes = _b64d(ct_b64)
    expected_mac = _b64d(mac_b64)
    key_mat = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64)
    enc_key, mac_key = key_mat[:32], key_mat[32:]
    actual_mac = hmac.new(mac_key, salt + nonce + ct_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise ValueError("마스터 비밀번호가 일치하지 않거나 암호문이 손상되었습니다.")
    pt_bytes = _keystream_xor(ct_bytes, enc_key, nonce)
    return pt_bytes.decode("utf-8")


def _read_raw_env_lines():
    if not ENV_FILE.exists():
        return [], {}
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    raw_map = {}
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        raw_map[k.strip()] = v.strip()
    return lines, raw_map


def encrypt_env_file_with_password(password: str, old_password: str = None):
    with _CRYPTO_LOCK:
        lines, raw_map = _read_raw_env_lines()
        if not lines and not raw_map:
            return
        new_lines = []
        handled_keys = set()
        pw_hash = hash_password(password)
        user_plain = raw_map.get("DASHBOARD_USER", "")
        if user_plain.startswith("ENC$v1$") and (old_password or password):
            try:
                user_plain = decrypt_secret(user_plain, old_password or password)
            except Exception:
                pass

        for line in lines:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                new_lines.append(line)
                continue
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k in ("DASHBOARD_PASSWORD", "OLD_PASSWORD"):
                handled_keys.add(k)
                continue
            if k == "DASHBOARD_PASSWORD_HASH":
                new_lines.append(f"DASHBOARD_PASSWORD_HASH={pw_hash}")
                handled_keys.add("DASHBOARD_PASSWORD_HASH")
                continue
            if k == "DASHBOARD_USER_HASH":
                if user_plain and not user_plain.startswith("PBKDF2$"):
                    new_lines.append(f"DASHBOARD_USER_HASH={hash_password(user_plain)}")
                else:
                    new_lines.append(line)
                handled_keys.add("DASHBOARD_USER_HASH")
                continue
            if k == "DASHBOARD_USER":
                handled_keys.add("DASHBOARD_USER")
                if user_plain:
                    new_lines.append(f"DASHBOARD_USER_HASH={hash_password(user_plain)}")
                    handled_keys.add("DASHBOARD_USER_HASH")
                continue
            if k in SENSITIVE_ENV_KEYS:
                plain_val = v
                if v.startswith("ENC$v1$"):
                    plain_val = decrypt_secret(v, old_password or password)
                enc_val = encrypt_secret(plain_val, password)
                new_lines.append(f"{k}={enc_val}")
                handled_keys.add(k)
            else:
                new_lines.append(line)

        if "DASHBOARD_PASSWORD_HASH" not in handled_keys:
            new_lines.append(f"DASHBOARD_PASSWORD_HASH={pw_hash}")

        ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        _DECRYPTED_ENV_CACHE.clear()


def unlock_with_password(password: str) -> bool:
    global _UNLOCKED_MASTER_PW
    with _CRYPTO_LOCK:
        _, raw_map = _read_raw_env_lines()
        plain_pw_in_env = raw_map.get("DASHBOARD_PASSWORD")
        pw_hash = raw_map.get("DASHBOARD_PASSWORD_HASH")

        if plain_pw_in_env:
            if not hmac.compare_digest(password, plain_pw_in_env):
                return False
            encrypt_env_file_with_password(password)
            _UNLOCKED_MASTER_PW = password
            return True

        if pw_hash:
            if not verify_password_hash(password, pw_hash):
                return False
            # If any sensitive key was added in plaintext, auto-encrypt it now
            needs_enc = any(
                (k in raw_map and raw_map[k] and not raw_map[k].startswith("ENC$v1$"))
                for k in SENSITIVE_ENV_KEYS
            ) or ("DASHBOARD_USER" in raw_map)
            if needs_enc:
                encrypt_env_file_with_password(password)
            _UNLOCKED_MASTER_PW = password
            return True

        return False


def load_env():
    with _CRYPTO_LOCK:
        _, raw_map = _read_raw_env_lines()
        pw = _UNLOCKED_MASTER_PW or os.environ.get("DASHBOARD_MASTER_PW")
        if not pw and raw_map.get("DASHBOARD_PASSWORD"):
            pw = raw_map.get("DASHBOARD_PASSWORD")
            encrypt_env_file_with_password(pw)
            _, raw_map = _read_raw_env_lines()

        result = {}
        for k, v in raw_map.items():
            if v.startswith("ENC$v1$"):
                if not pw:
                    result[k] = ""
                else:
                    cache_key = (k, v, pw)
                    if cache_key in _DECRYPTED_ENV_CACHE:
                        result[k] = _DECRYPTED_ENV_CACHE[cache_key]
                    else:
                        try:
                            dec = decrypt_secret(v, pw)
                            _DECRYPTED_ENV_CACHE[cache_key] = dec
                            result[k] = dec
                        except Exception:
                            result[k] = ""
            else:
                result[k] = v
        return result


def load_ria_holdings():
    if not RIA_FILE.exists():
        return {"cashKrw": 0.0, "cashUsd": 0.0, "items": [], "sales": []}
    try:
        data = json.loads(RIA_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {"cashKrw": 0.0, "cashUsd": 0.0, "items": data, "sales": []}
        return {
            "cashKrw": float(data.get("cashKrw", 0.0)),
            "cashUsd": float(data.get("cashUsd", 0.0)),
            "items": data.get("items", []),
            "sales": data.get("sales", []),
        }
    except Exception:
        return {"cashKrw": 0.0, "cashUsd": 0.0, "items": [], "sales": []}


def build_transfer_sell_orders(sales: list) -> list:
    """토스 종합계좌 → RIA 이관 후 매도한 내역을 종합계좌 기준 가상 SELL 체결로 변환 (보유수량·원금 역산용)."""
    orders = []
    for s in sales or []:
        sym = (s.get("symbol") or "").strip().upper()
        qty = to_float(s.get("quantity"), 0.0)
        if not sym or qty <= 0:
            continue
        curr = s.get("currency") or ("KRW" if is_kr_symbol(sym) else "USD")
        if curr == "USD":
            amount = to_float(s.get("sellAmountUsd"), 0.0)
            cost_native = to_float(s.get("purchaseAmountUsd"), 0.0)
        else:
            amount = to_float(s.get("sellAmountKrw"), 0.0)
            cost_native = to_float(s.get("purchaseAmountKrw"), 0.0)
        sold_at = (s.get("soldAt") or "").strip().replace(" ", "T")
        orders.append({
            "symbol": sym,
            "side": "SELL",
            "currency": curr,
            "synthetic": True,
            "costNative": cost_native,
            "orderedAt": sold_at,
            "execution": {
                "filledQuantity": qty,
                "filledAmount": amount,
                "filledAt": sold_at,
            },
        })
    return orders


def summarize_ria_sales(sales: list) -> dict:
    sell_krw = sum(to_float(s.get("sellAmountKrw"), 0.0) for s in sales or [])
    cost_krw = sum(to_float(s.get("purchaseAmountKrw"), 0.0) for s in sales or [])
    fee_krw = sum(to_float(s.get("commissionKrw"), 0.0) + to_float(s.get("taxKrw"), 0.0) for s in sales or [])
    profit_krw = sell_krw - cost_krw - fee_krw
    return {
        "count": len(sales or []),
        "sellAmountKrw": sell_krw,
        "purchaseAmountKrw": cost_krw,
        "feeKrw": fee_krw,
        "profitKrw": profit_krw,
        "returnRatePct": (profit_krw / cost_krw * 100.0) if cost_krw > 0 else 0.0,
    }


def save_ria_holdings(data):
    RIA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_capital_ledger():
    if not CAPITAL_FILE.exists():
        return {"baseSummary": {}, "manualTransactions": []}
    try:
        return json.loads(CAPITAL_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"baseSummary": {}, "manualTransactions": []}


def save_capital_ledger(data):
    CAPITAL_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def get_capital_summary():
    ledger = load_capital_ledger()
    base_summary = ledger.get("baseSummary", {})
    manual_txs = ledger.get("manualTransactions", [])

    base_net = sum(item.get("net", 0) for item in base_summary.values())
    manual_deposits = sum(
        to_float(tx.get("amount", 0))
        for tx in manual_txs
        if tx.get("type") == "DEPOSIT"
    )
    manual_withdraws = sum(
        to_float(tx.get("amount", 0))
        for tx in manual_txs
        if tx.get("type") == "WITHDRAW"
    )
    manual_net = manual_deposits - manual_withdraws

    total_net = base_net + manual_net
    return {
        "baseNetKrw": base_net,
        "manualDepositsKrw": manual_deposits,
        "manualWithdrawsKrw": manual_withdraws,
        "manualNetKrw": manual_net,
        "totalNetCapitalKrw": total_net,
        "baseSummary": base_summary,
        "manualTransactions": manual_txs,
    }


class TossApiClient:
    def __init__(self):
        self._lock = threading.Lock()
        self._access_token = None
        self._token_expires_at = 0
        self._accounts_cache = None
        self._accounts_cached_at = 0
        self._universe_cache = None
        self._universe_lock = threading.Lock()
        self._candles_cache = {}
        self._candles_lock = threading.Lock()
        self._orders_cache = {}
        self._orders_lock = threading.Lock()

    def _get_credentials(self):
        env = load_env()
        client_id = env.get("TOSS_CLIENT_ID") or os.environ.get("TOSS_CLIENT_ID", "")
        client_secret = env.get("TOSS_CLIENT_SECRET") or os.environ.get("TOSS_CLIENT_SECRET", "")
        return client_id, client_secret

    def get_token(self, force_refresh=False):
        with self._lock:
            now = time.time()
            if not force_refresh and self._access_token and now < self._token_expires_at - 60:
                return self._access_token

            client_id, client_secret = self._get_credentials()
            if not client_id or not client_secret:
                raise RuntimeError("TOSS_CLIENT_ID 또는 TOSS_CLIENT_SECRET이 설정되지 않았습니다.")

            body = urllib.parse.urlencode({
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{TOSS_BASE_URL}/oauth2/token",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._access_token = data["access_token"]
                expires_in = int(data.get("expires_in", 86400))
                self._token_expires_at = now + expires_in
                return self._access_token

    def request(self, path, query=None, account_seq=None, retry_auth=True):
        token = self.get_token(force_refresh=False)
        url = f"{TOSS_BASE_URL}{path}"
        if query:
            clean_q = {k: v for k, v in query.items() if v is not None and v != ""}
            if clean_q:
                url += "?" + urllib.parse.urlencode(clean_q)

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if account_seq is not None:
            headers["X-Tossinvest-Account"] = str(account_seq)

        last_err = None
        for attempt in range(4):
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 401 and retry_auth:
                    self.get_token(force_refresh=True)
                    return self.request(path, query=query, account_seq=account_seq, retry_auth=False)
                err_body = e.read().decode("utf-8", errors="replace")
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    time.sleep(0.45 * (attempt + 1))
                    continue
                try:
                    err_json = json.loads(err_body)
                except Exception:
                    err_json = {"error": {"code": f"HTTP_{e.code}", "message": err_body}}
                raise RuntimeError(json.dumps(err_json, ensure_ascii=False))
            except Exception as ex:
                last_err = ex
                if attempt < 3:
                    time.sleep(0.35 * (attempt + 1))
                    continue
                raise last_err

    def get_accounts(self, force_refresh=False):
        now = time.time()
        if not force_refresh and self._accounts_cache and (now - self._accounts_cached_at < 300):
            return self._accounts_cache
        resp = self.request("/api/v1/accounts")
        self._accounts_cache = resp.get("result", [])
        self._accounts_cached_at = now
        return self._accounts_cache

    def get_daily_candles_extended(self, symbol, pages=4):
        now = time.time()
        disk_cache_file = BASE_DIR / "candles_cache.json"
        with self._candles_lock:
            if not self._candles_cache and disk_cache_file.exists():
                try:
                    loaded = json.loads(disk_cache_file.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        self._candles_cache = loaded
                except Exception:
                    pass
            cached = self._candles_cache.get(symbol)
            min_expected = 150 if pages > 1 else 20
            if (
                cached
                and (now - cached.get("ts", 0) < 21600)
                and len(cached.get("candles") or []) >= min_expected
                and cached.get("pages", 1) >= pages
            ):
                return cached["candles"]

        all_candles = []
        before = None
        for page_idx in range(pages):
            if page_idx > 0:
                time.sleep(0.08)
            q = {"symbol": symbol, "interval": "1d", "count": "200", "adjusted": "true"}
            if before:
                q["before"] = before
            try:
                res = self.request("/api/v1/candles", query=q).get("result", {})
            except Exception:
                break
            batch = res.get("candles") or []
            if not batch:
                break
            if all_candles and batch[0].get("timestamp") == all_candles[-1].get("timestamp"):
                batch = batch[1:]
            all_candles.extend(batch)
            nxt = res.get("nextBefore")
            if not nxt or len(batch) < 50:
                break
            before = nxt

        if all_candles:
            with self._candles_lock:
                self._candles_cache[symbol] = {
                    "ts": now,
                    "pages": pages,
                    "candles": all_candles,
                }
                try:
                    disk_cache_file.write_text(
                        json.dumps(self._candles_cache, ensure_ascii=False),
                        encoding="utf-8",
                    )
                except Exception:
                    pass
        return all_candles

    def ensure_universe_loaded(self):
        cache_file = BASE_DIR / "universe_cache.json"
        if self._universe_cache is not None:
            return
        if cache_file.exists():
            try:
                self._universe_cache = json.loads(cache_file.read_text(encoding="utf-8"))
                if self._universe_cache:
                    return
            except Exception:
                pass

        with self._universe_lock:
            if self._universe_cache is not None:
                return
            markets = ["KOSPI", "KOSDAQ", "NASDAQ", "NYSE", "AMEX"]
            universe = []
            for idx, mkt in enumerate(markets):
                if idx > 0:
                    time.sleep(1.05)
                try:
                    r = self.request("/api/v1/stocks/all", {"market": mkt, "status": "ACTIVE"})
                    items = r.get("result", [])
                    country = "KR" if mkt in ("KOSPI", "KOSDAQ", "KR_ETC") else "US"
                    currency = "KRW" if country == "KR" else "USD"
                    for it in items:
                        it["market"] = mkt
                        it["marketCountry"] = country
                        it["currency"] = currency
                    universe.extend(items)
                except Exception:
                    pass
            if universe:
                self._universe_cache = universe
                try:
                    cache_file.write_text(json.dumps(universe, ensure_ascii=False), encoding="utf-8")
                except Exception:
                    pass

    def search_stocks(self, query_str):
        q = (query_str or "").strip().lower()
        if not q:
            return []

        self.ensure_universe_loaded()
        universe = self._universe_cache or []

        exact_matches = []
        partial_matches = []
        for s in universe:
            sym = (s.get("symbol") or "").lower()
            name = (s.get("name") or "").lower()
            if sym == q or name == q:
                exact_matches.append(s)
            elif q in sym or q in name:
                partial_matches.append(s)
                if len(partial_matches) >= 30:
                    break
        return (exact_matches + partial_matches)[:25]

    def resolve_stock_info_map(self, symbols):
        clean_syms = list({(s or "").strip().upper() for s in symbols if s})
        if not clean_syms:
            return {}

        self.ensure_universe_loaded()
        universe = self._universe_cache or []
        uni_map = {(s.get("symbol") or "").upper(): s for s in universe}

        result_map = {}
        missing = []
        for sym in clean_syms:
            if sym in uni_map:
                result_map[sym] = uni_map[sym]
            else:
                missing.append(sym)

        if missing:
            try:
                resp = self.request("/api/v1/stocks", {"symbols": ",".join(missing[:200])})
                for s in resp.get("result", []):
                    result_map[s["symbol"].upper()] = s
            except Exception:
                pass
        return result_map

    def get_all_filled_orders(self, account_seq, force_refresh=False):
        all_closed = self.get_all_closed_orders(account_seq, force_refresh=force_refresh)
        return [
            o for o in all_closed if o.get("status") in ("FILLED", "PARTIAL_FILLED")
        ]

    def get_all_closed_orders(self, account_seq, force_refresh=False):
        now = time.time()
        with self._orders_lock:
            cached = self._orders_cache.get(account_seq)
            if not force_refresh and cached and (now - cached["ts"] < 300) and "all_closed" in cached:
                return cached["all_closed"]

        all_orders = []
        cursor = None
        for _ in range(10):
            q = {"status": "CLOSED", "limit": "100"}
            if cursor:
                q["cursor"] = cursor
            try:
                res = self.request("/api/v1/orders", query=q, account_seq=account_seq).get("result", {})
            except Exception:
                break
            batch = res.get("orders") or []
            all_orders.extend(batch)
            if not res.get("hasNext") or not res.get("nextCursor"):
                break
            cursor = res.get("nextCursor")

        filled = [
            o for o in all_orders if o.get("status") in ("FILLED", "PARTIAL_FILLED")
        ]
        with self._orders_lock:
            self._orders_cache[account_seq] = {
                "ts": now,
                "orders": filled,
                "all_closed": all_orders,
            }
        return all_orders


toss_client = TossApiClient()

KIS_BASE_URL = "https://openapi.koreainvestment.com:9443"
KIS_TOKENS_PATH = BASE_DIR / "kis_tokens.json"


class KisApiClient:
    def __init__(self):
        self._lock = threading.Lock()
        self._balance_cache = {"ts": 0.0, "data": None}
        self._orders_cache = {}
        self._inferred_dates = {}

    def get_account_configs(self):
        env = load_env()
        configs = [
            {
                "id": "KIS_1",
                "cano": env.get("KIS_1_CANO", ""),
                "prdt": env.get("KIS_1_PRDT", "22"),
                "label": env.get("KIS_1_LABEL", "한투 연금저축"),
                "short": "한투연금",
                "appkey": env.get("KIS_1_APP_KEY", ""),
                "appsecret": env.get("KIS_1_APP_SECRET", ""),
                "supportsOrders": True,
            },
            {
                "id": "KIS_2",
                "cano": env.get("KIS_2_CANO", ""),
                "prdt": env.get("KIS_2_PRDT", "01"),
                "label": env.get("KIS_2_LABEL", "한투 ISA"),
                "short": "한투ISA",
                "appkey": env.get("KIS_2_APP_KEY", ""),
                "appsecret": env.get("KIS_2_APP_SECRET", ""),
                "supportsOrders": True,
            },
            {
                "id": "KIS_3",
                "cano": env.get("KIS_3_CANO", ""),
                "prdt": env.get("KIS_3_PRDT", "29"),
                "label": env.get("KIS_3_LABEL", "한투 IRP"),
                "short": "한투IRP",
                "appkey": env.get("KIS_3_APP_KEY", ""),
                "appsecret": env.get("KIS_3_APP_SECRET", ""),
                "supportsOrders": False,
            },
            {
                "id": "KIS_4",
                "cano": env.get("KIS_4_CANO", ""),
                "prdt": env.get("KIS_4_PRDT", "01"),
                "label": env.get("KIS_4_LABEL", "한투 위탁"),
                "short": "한투위탁",
                "appkey": env.get("KIS_4_APP_KEY", ""),
                "appsecret": env.get("KIS_4_APP_SECRET", ""),
                "supportsOrders": True,
            },
        ]
        return [c for c in configs if c.get("cano") and c.get("appkey") and c.get("appsecret")]

    def _load_tokens(self):
        if KIS_TOKENS_PATH.exists():
            try:
                raw_text = KIS_TOKENS_PATH.read_text(encoding="utf-8").strip()
                pw = _UNLOCKED_MASTER_PW or os.environ.get("DASHBOARD_MASTER_PW")
                if raw_text.startswith("ENC$v1$"):
                    if not pw:
                        return {}
                    raw_text = decrypt_secret(raw_text, pw)
                data = json.loads(raw_text)
                if pw and not KIS_TOKENS_PATH.read_text(encoding="utf-8").strip().startswith("ENC$v1$"):
                    self._save_tokens(data)
                return data
            except Exception:
                pass
        return {}

    def _save_tokens(self, tokens):
        try:
            raw_json = json.dumps(tokens, ensure_ascii=False, indent=2)
            pw = _UNLOCKED_MASTER_PW or os.environ.get("DASHBOARD_MASTER_PW")
            if pw:
                KIS_TOKENS_PATH.write_text(encrypt_secret(raw_json, pw), encoding="utf-8")
            else:
                KIS_TOKENS_PATH.write_text(raw_json, encoding="utf-8")
        except Exception:
            pass

    def get_token(self, acc):
        cano = acc["cano"]
        now = time.time()
        with self._lock:
            tokens = self._load_tokens()
            if cano in tokens and tokens[cano].get("expires_at", 0) > now + 300:
                return tokens[cano]["access_token"]

            req = urllib.request.Request(
                f"{KIS_BASE_URL}/oauth2/tokenP",
                data=json.dumps({
                    "grant_type": "client_credentials",
                    "appkey": acc["appkey"],
                    "appsecret": acc["appsecret"],
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            tok = data["access_token"]
            exp = int(data.get("expires_in", 86400))
            tokens[cano] = {
                "access_token": tok,
                "expires_at": now + exp,
                "issued_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save_tokens(tokens)
            return tok

    def request_get(self, acc, path, tr_id, params):
        tok = self.get_token(acc)
        qs = urllib.parse.urlencode(params)
        url = f"{KIS_BASE_URL}{path}?{qs}"
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "authorization": f"Bearer {tok}",
            "appkey": acc["appkey"],
            "appsecret": acc["appsecret"],
            "tr_id": tr_id,
            "custtype": "P",
        }
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=15) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                # Retry if KIS returns SESSION FULL (rt_cd == "9")
                if res.get("rt_cd") == "9" and attempt < 3:
                    time.sleep(0.65 * (attempt + 1))
                    continue
                return res
            except Exception:
                if attempt < 3:
                    time.sleep(0.65 * (attempt + 1))
                else:
                    return {}
        return {}

    def fetch_all_accounts_data(self, force=False):
        now = time.time()
        if not force and self._balance_cache["data"] and (now - self._balance_cache["ts"] < 25):
            return self._balance_cache["data"]

        configs = self.get_account_configs()
        accounts_summary = []
        items_by_acc = {}
        cash_by_acc = {}

        for acc in configs:
            acc_id = acc["id"]
            items_by_acc[acc_id] = []
            cash_by_acc[acc_id] = 0.0

            res = self.request_get(
                acc,
                "/uapi/domestic-stock/v1/trading/inquire-balance",
                "TTTC8434R",
                {
                    "CANO": acc["cano"],
                    "ACNT_PRDT_CD": acc["prdt"],
                    "AFHR_FLPR_YN": "N",
                    "OFL_YN": "",
                    "INQR_DVSN": "02",
                    "UNPR_DVSN": "01",
                    "FUND_STTL_ICLD_YN": "N",
                    "FNCG_AMT_AUTO_RDPT_YN": "N",
                    "PRCS_DVSN": "00",
                    "CTX_AREA_FK100": "",
                    "CTX_AREA_NK100": "",
                },
            )
            out1 = res.get("output1") or []
            out2 = res.get("output2") or []
            if out2:
                o2 = out2[0]
                cash_by_acc[acc_id] = to_float(
                    o2.get("prvs_rcdl_excc_amt") or o2.get("dnca_tot_amt"), 0.0
                )

            for row in out1:
                qty = to_float(row.get("hldg_qty"), 0.0)
                if qty <= 0:
                    continue
                sym = (row.get("pdno") or "").strip().upper()
                name = (row.get("prdt_name") or sym).strip()
                avg_price = to_float(row.get("pchs_avg_pric"), 0.0)
                purch_amt = to_float(row.get("pchs_amt"), qty * avg_price)
                last_price = to_float(row.get("prpr"), avg_price)
                val_amt = to_float(row.get("evlu_amt"), qty * last_price)
                pl_val = to_float(row.get("evlu_pfls_amt"), val_amt - purch_amt)
                pl_rate_pct = to_float(
                    row.get("evlu_pfls_rt"),
                    (pl_val / purch_amt * 100.0) if purch_amt > 0 else 0.0,
                )
                dpl_rate_pct = to_float(row.get("fltt_rt"), 0.0)
                dpl_per_share = to_float(row.get("bfdy_cprs_icdc"), 0.0)
                dpl_val = dpl_per_share * qty

                # Commission & Tax (ETFs in KR and pension/IRP accounts have 0% transaction tax)
                comm = round(val_amt * 0.00015)
                tax = 0.0
                total_cost = comm + tax
                val_after = val_amt - total_cost
                pl_after = val_after - purch_amt
                pl_rate_after = (pl_after / purch_amt * 100.0) if purch_amt > 0 else 0.0

                cache_key = (acc_id, sym, round(avg_price))
                if cache_key not in self._inferred_dates:
                    self._inferred_dates[cache_key] = infer_ria_purchase_date(sym, avg_price)
                purch_date = self._inferred_dates[cache_key]

                items_by_acc[acc_id].append({
                    "symbol": sym,
                    "name": name,
                    "accountTag": acc_id,
                    "accountLabel": acc["label"],
                    "shortLabel": acc["short"],
                    "purchaseDate": purch_date,
                    "marketCountry": "KR",
                    "currency": "KRW",
                    "quantity": qty,
                    "lastPrice": last_price,
                    "averagePurchasePrice": avg_price,
                    "lastPriceKrw": last_price,
                    "averagePurchasePriceKrw": avg_price,
                    "purchaseAmount": purch_amt,
                    "marketValue": val_amt,
                    "marketValueAfterCost": val_after,
                    "profitLoss": pl_val,
                    "profitLossAfterCost": pl_after,
                    "returnRatePct": pl_rate_pct,
                    "returnRateAfterCostPct": pl_rate_after,
                    "dailyProfitLoss": dpl_val,
                    "dailyReturnRatePct": dpl_rate_pct,
                    "commission": comm,
                    "tax": tax,
                    "totalCost": total_cost,
                    "purchaseAmountKrw": purch_amt,
                    "marketValueKrw": val_amt,
                    "marketValueAfterCostKrw": val_after,
                    "profitLossKrw": pl_val,
                    "profitLossAfterCostKrw": pl_after,
                    "dailyProfitLossKrw": dpl_val,
                    "totalCostKrw": total_cost,
                    "weightByPurchasePct": 0.0,
                    "weightByMarketValuePct": 0.0,
                })

            accounts_summary.append({
                "id": acc_id,
                "accountNo": f"{acc['cano']}-{acc['prdt']}",
                "label": acc["label"],
                "short": acc["short"],
                "holdingCount": len(items_by_acc[acc_id]),
                "cashKrw": cash_by_acc[acc_id],
            })
            time.sleep(0.15)

        result = {
            "accounts": accounts_summary,
            "itemsByAcc": items_by_acc,
            "cashByAcc": cash_by_acc,
        }
        self._balance_cache = {"ts": now, "data": result}
        return result

    def get_account_filled_orders(self, acc_id):
        now = time.time()
        if acc_id in self._orders_cache and (now - self._orders_cache[acc_id]["ts"] < 600):
            return self._orders_cache[acc_id]["orders"]

        configs = {c["id"]: c for c in self.get_account_configs()}
        acc = configs.get(acc_id)
        if not acc or not acc.get("supportsOrders"):
            return []

        raw_rows = []
        # 1) Recent 3 months (TTTC8001R) + 2) Past 1 year (CTSC9115R) + 3) Past 2-3 years (CTSC9115R)
        for tr_id, s_dt, e_dt in [
            ("TTTC8001R", "20260727", "20261231"),
            ("CTSC9115R", "20250727", "20260726"),
            ("CTSC9115R", "20240727", "20250726"),
            ("CTSC9115R", "20230727", "20240726"),
        ]:
            res = self.request_get(
                acc,
                "/uapi/domestic-stock/v1/trading/inquire-daily-ccld",
                tr_id,
                {
                    "CANO": acc["cano"],
                    "ACNT_PRDT_CD": acc["prdt"],
                    "INQR_STRT_DT": s_dt,
                    "INQR_END_DT": e_dt,
                    "SLL_BUY_DVSN_CD": "00",
                    "INQR_DVSN": "00",
                    "PDNO": "",
                    "CCLD_DVSN": "01",
                    "ORD_GNO_BRNO": "",
                    "ODNO": "",
                    "INQR_DVSN_3": "00",
                    "INQR_DVSN_1": "",
                    "CTX_AREA_FK100": "",
                    "CTX_AREA_NK100": "",
                },
            )
            for r in res.get("output1") or []:
                fq = to_float(r.get("tot_ccld_qty"), 0.0)
                fa = to_float(r.get("tot_ccld_amt"), 0.0)
                if fq <= 0 or fa <= 0:
                    continue
                odt_raw = (r.get("ord_dt") or "").strip()
                if len(odt_raw) == 8:
                    odt = f"{odt_raw[:4]}-{odt_raw[4:6]}-{odt_raw[6:8]}"
                else:
                    odt = odt_raw
                otm_raw = (r.get("ord_tmd") or "090000").strip()
                if len(otm_raw) == 6:
                    otm = f"{otm_raw[:2]}:{otm_raw[2:4]}:{otm_raw[4:6]}"
                else:
                    otm = "09:00:00"
                side = "SELL" if r.get("sll_buy_dvsn_cd") == "01" else "BUY"
                avg_p = to_float(r.get("avg_prvs"), fa / fq)
                sym = (r.get("pdno") or "").strip().upper()
                name = (r.get("prdt_name") or sym).strip()
                raw_rows.append({
                    "symbol": sym,
                    "name": f"{name} ({acc['short']})",
                    "currency": "KRW",
                    "side": side,
                    "status": "FILLED",
                    "quantity": fq,
                    "price": avg_p,
                    "orderAmount": fa,
                    "orderedAt": f"{odt}T{otm}",
                    "accountTag": acc_id,
                    "accountLabel": acc["label"],
                    "execution": {
                        "filledQuantity": fq,
                        "averageFilledPrice": avg_p,
                        "filledAmount": fa,
                        "filledAt": f"{odt}T{otm}",
                        "commission": round(fa * 0.00015),
                        "tax": 0.0,
                    },
                })
            time.sleep(0.25)

        raw_rows.sort(key=lambda x: x["orderedAt"], reverse=True)
        self._orders_cache[acc_id] = {"ts": now, "orders": raw_rows}
        return raw_rows


kis_client = KisApiClient()


def is_kr_symbol(sym):
    s = (sym or "").strip().upper()
    return len(s) == 6 and s[0].isdigit()


def to_float(val, default=0.0):
    if val is None or val == "":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def infer_ria_purchase_date(sym, avg_price):
    if avg_price <= 0:
        return time.strftime("%Y-%m-%d")
    try:
        candles = toss_client.get_daily_candles_extended(sym, pages=4)
    except Exception:
        candles = []
    if not candles:
        return time.strftime("%Y-%m-%d")

    # 1st priority: most recent trading day where lowPrice <= avg_price <= highPrice
    for c in candles:
        low_p = to_float(c.get("lowPrice"), 0.0)
        high_p = to_float(c.get("highPrice"), 0.0)
        if low_p <= avg_price <= high_p and low_p > 0:
            return (c.get("timestamp") or "")[:10]

    # 2nd priority: trading day across all fetched candles with closest closePrice
    best_date = (candles[-1].get("timestamp") or "")[:10]
    best_diff = float("inf")
    for c in candles:
        close_p = to_float(c.get("closePrice"), 0.0)
        if close_p > 0:
            diff = abs(close_p - avg_price)
            if diff < best_diff:
                best_diff = diff
                best_date = (c.get("timestamp") or "")[:10]
    return best_date or time.strftime("%Y-%m-%d")


def build_ria_enriched_items(ria_data, usd_krw_rate):
    items = ria_data.get("items") or []
    if not items:
        return []

    symbols = list({(it.get("symbol") or "").strip().upper() for it in items if it.get("symbol")})
    price_map = {}
    stock_info_map = toss_client.resolve_stock_info_map(symbols)

    if symbols:
        sym_str = ",".join(symbols[:200])
        try:
            p_resp = toss_client.request("/api/v1/prices", {"symbols": sym_str})
            for p in p_resp.get("result", []):
                price_map[p["symbol"].upper()] = p
        except Exception:
            pass

    enriched = []
    dirty = False
    for it in items:
        sym = (it.get("symbol") or "").strip().upper()
        if not sym:
            continue
        s_info = stock_info_map.get(sym, {})
        p_info = price_map.get(sym, {})

        curr = (
            p_info.get("currency")
            or s_info.get("currency")
            or ("KRW" if is_kr_symbol(sym) else None)
            or it.get("currency")
            or "USD"
        )
        country = "KR" if curr == "KRW" else "US"
        saved_name = (it.get("name") or "").strip()
        if not saved_name or saved_name.upper() == sym:
            name = s_info.get("name") or sym
        else:
            name = saved_name

        qty = to_float(it.get("quantity"), 0.0)
        avg_price = to_float(it.get("averagePurchasePrice"), 0.0)
        purch_amt = to_float(it.get("purchaseAmount"), qty * avg_price)
        if purch_amt <= 0 and qty > 0 and avg_price > 0:
            purch_amt = qty * avg_price
        if avg_price <= 0 and qty > 0 and purch_amt > 0:
            avg_price = purch_amt / qty

        purch_date = (it.get("purchaseDate") or "").strip()
        if not purch_date:
            purch_date = infer_ria_purchase_date(sym, avg_price)
            it["purchaseDate"] = purch_date
            it["name"] = name
            it["currency"] = curr
            dirty = True

        last_price = to_float(p_info.get("lastPrice"), avg_price)
        val_amt = qty * last_price

        if curr == "KRW":
            comm = round(val_amt * 0.00015)
            tax = round(val_amt * 0.0015)
        else:
            comm = round(val_amt * 0.001, 2)
            tax = 0.0
        total_cost = comm + tax
        val_after = val_amt - total_cost

        pl_val = val_amt - purch_amt
        pl_after_val = val_after - purch_amt
        pl_rate_pct = (pl_val / purch_amt * 100.0) if purch_amt > 0 else 0.0
        pl_rate_after_pct = (pl_after_val / purch_amt * 100.0) if purch_amt > 0 else 0.0

        fx_mult = usd_krw_rate if curr == "USD" else 1.0

        enriched.append({
            "symbol": sym,
            "name": name,
            "accountTag": "RIA",
            "accountLabel": "RIA 계좌",
            "purchaseDate": purch_date,
            "marketCountry": country,
            "currency": curr,
            "quantity": qty,
            "lastPrice": last_price,
            "averagePurchasePrice": avg_price,
            "lastPriceKrw": last_price * fx_mult,
            "averagePurchasePriceKrw": avg_price * fx_mult,
            "purchaseAmount": purch_amt,
            "marketValue": val_amt,
            "marketValueAfterCost": val_after,
            "profitLoss": pl_val,
            "profitLossAfterCost": pl_after_val,
            "returnRatePct": pl_rate_pct,
            "returnRateAfterCostPct": pl_rate_after_pct,
            "dailyProfitLoss": 0.0,
            "dailyReturnRatePct": 0.0,
            "commission": comm,
            "tax": tax,
            "totalCost": total_cost,
            "purchaseAmountKrw": purch_amt * fx_mult,
            "marketValueKrw": val_amt * fx_mult,
            "marketValueAfterCostKrw": val_after * fx_mult,
            "profitLossKrw": pl_val * fx_mult,
            "profitLossAfterCostKrw": pl_after_val * fx_mult,
            "dailyProfitLossKrw": 0.0,
            "totalCostKrw": total_cost * fx_mult,
            "weightByPurchasePct": 0.0,
            "weightByMarketValuePct": 0.0,
        })

    if dirty:
        try:
            save_ria_holdings(ria_data)
        except Exception:
            pass
    return enriched


def _fmt_qty_label(q: float) -> str:
    if abs(q - round(q)) < 1e-6:
        return f"{int(round(q)):,}주"
    return f"{q:,.4f}".rstrip("0").rstrip(".") + "주"


ALL_ACCOUNT_IDS = ["BROKERAGE", "RIA", "KIS_1", "KIS_2", "KIS_3", "KIS_4"]

OVERSEAS_ETF_KEYWORDS = (
    "미국",
    "나스닥",
    "s&p",
    "다우존스",
    "필라델피아",
    "러셀",
    "글로벌",
    "선진국",
    "신흥국",
    "유럽",
    "유로",
    "일본",
    "니케이",
    "차이나",
    "중국",
    "항셍",
    "csi",
    "과창판",
    "인도",
    "니프티",
    "베트남",
    "대만",
    "브라질",
    "라틴",
    "월드",
    "msci",
    "acwi",
    "soxx",
    "qqq",
    "schd",
    "ndx",
    "spx",
    "빅테크",
    "매그니피센트",
    "테크top",
    "fang",
    "테슬라",
    "엔비디아",
    "애플",
    "마이크로소프트",
    "구글",
    "아마존",
    "버크셔",
)


def is_domestic_overseas_etf(name: str, symbol: str = "", currency: str = "KRW") -> bool:
    if (currency or "KRW").upper() != "KRW":
        return False
    nm = (name or "").lower()
    if not nm:
        return False
    return any(kw in nm for kw in OVERSEAS_ETF_KEYWORDS)


def parse_scope_set(account_scope: str) -> set:
    if not account_scope or account_scope.strip().upper() == "ALL":
        return set(ALL_ACCOUNT_IDS)
    parts = [p.strip().upper() for p in account_scope.split(",") if p.strip()]
    selected = set()
    for p in parts:
        if p == "ALL":
            selected.update(ALL_ACCOUNT_IDS)
        elif p == "KIS_ALL":
            selected.update(["KIS_1", "KIS_2", "KIS_3", "KIS_4"])
        elif p in ALL_ACCOUNT_IDS:
            selected.add(p)
    return selected if selected else set(ALL_ACCOUNT_IDS)


def _short_acct_label(item: dict) -> str:
    if item.get("shortLabel"):
        return item["shortLabel"]
    tag = item.get("accountTag", "")
    return {
        "BROKERAGE": "토스종합",
        "RIA": "토스RIA",
        "KIS_1": "한투연금",
        "KIS_2": "한투ISA",
        "KIS_3": "한투IRP",
        "KIS_4": "한투위탁",
    }.get(tag, item.get("accountLabel") or "계좌")


def merge_same_symbol_items(items_list: list) -> list:
    groups = {}
    ordered_syms = []

    for it in items_list:
        sym = (it.get("symbol") or "").upper()
        if not sym:
            continue
        if sym not in groups:
            groups[sym] = []
            ordered_syms.append(sym)
        groups[sym].append(dict(it))

    merged_result = []
    for sym in ordered_syms:
        grp = groups[sym]
        if len(grp) == 1:
            merged_result.append(grp[0])
            continue

        base = grp[0]
        tot_qty = sum(to_float(x.get("quantity"), 0.0) for x in grp)
        tot_purch = sum(to_float(x.get("purchaseAmount"), 0.0) for x in grp)
        tot_mv = sum(to_float(x.get("marketValue"), 0.0) for x in grp)
        tot_mv_after = sum(to_float(x.get("marketValueAfterCost"), 0.0) for x in grp)
        tot_pl = sum(to_float(x.get("profitLoss"), 0.0) for x in grp)
        tot_pl_after = sum(to_float(x.get("profitLossAfterCost"), 0.0) for x in grp)

        tot_purch_krw = sum(to_float(x.get("purchaseAmountKrw"), 0.0) for x in grp)
        tot_mv_krw = sum(to_float(x.get("marketValueKrw"), 0.0) for x in grp)
        tot_mv_after_krw = sum(to_float(x.get("marketValueAfterCostKrw"), 0.0) for x in grp)
        tot_pl_krw = sum(to_float(x.get("profitLossKrw"), 0.0) for x in grp)
        tot_pl_after_krw = sum(to_float(x.get("profitLossAfterCostKrw"), 0.0) for x in grp)

        avg_price = (tot_purch / tot_qty) if tot_qty > 0 else to_float(base.get("averagePurchasePrice"), 0.0)
        avg_price_krw = (tot_purch_krw / tot_qty) if tot_qty > 0 else to_float(base.get("averagePurchasePriceKrw"), 0.0)

        rate_pct = (tot_pl / tot_purch * 100.0) if tot_purch > 0 else 0.0
        rate_after_pct = (tot_pl_after / tot_purch * 100.0) if tot_purch > 0 else 0.0

        # Scale daily profit/loss if a reference item has daily P/L
        ref_dpl_item = next(
            (x for x in grp if abs(to_float(x.get("dailyProfitLoss"), 0.0)) > 0 and to_float(x.get("quantity"), 0.0) > 0),
            None,
        )
        if ref_dpl_item:
            ref_q = to_float(ref_dpl_item.get("quantity"), 1.0)
            scale_dpl = tot_qty / ref_q
            tot_dpl = to_float(ref_dpl_item.get("dailyProfitLoss"), 0.0) * scale_dpl
            tot_dpl_krw = to_float(ref_dpl_item.get("dailyProfitLossKrw"), 0.0) * scale_dpl
            dpl_rate = to_float(ref_dpl_item.get("dailyReturnRatePct"), 0.0)
        else:
            tot_dpl = sum(to_float(x.get("dailyProfitLoss"), 0.0) for x in grp)
            tot_dpl_krw = sum(to_float(x.get("dailyProfitLossKrw"), 0.0) for x in grp)
            dpl_rate = to_float(base.get("dailyReturnRatePct"), 0.0)

        comm = sum(to_float(x.get("commission"), 0.0) for x in grp)
        tax = sum(to_float(x.get("tax"), 0.0) for x in grp)
        tot_cost = sum(to_float(x.get("totalCost"), 0.0) for x in grp)
        tot_cost_krw = sum(to_float(x.get("totalCostKrw"), 0.0) for x in grp)

        short_names = [_short_acct_label(x) for x in grp]
        breakdown_str = " + ".join(
            f"{_short_acct_label(x)} {_fmt_qty_label(to_float(x.get('quantity'), 0.0))}" for x in grp
        )

        merged_result.append({
            **base,
            "accountTag": "COMBINED",
            "accountLabel": "+".join(short_names) + " 합산",
            "quantity": tot_qty,
            "quantityBreakdown": breakdown_str,
            "averagePurchasePrice": avg_price,
            "averagePurchasePriceKrw": avg_price_krw,
            "purchaseAmount": tot_purch,
            "marketValue": tot_mv,
            "marketValueAfterCost": tot_mv_after,
            "profitLoss": tot_pl,
            "profitLossAfterCost": tot_pl_after,
            "returnRatePct": rate_pct,
            "returnRateAfterCostPct": rate_after_pct,
            "dailyProfitLoss": tot_dpl,
            "dailyProfitLossKrw": tot_dpl_krw,
            "dailyReturnRatePct": dpl_rate,
            "commission": comm,
            "tax": tax,
            "totalCost": tot_cost,
            "purchaseAmountKrw": tot_purch_krw,
            "marketValueKrw": tot_mv_krw,
            "marketValueAfterCostKrw": tot_mv_after_krw,
            "profitLossKrw": tot_pl_krw,
            "profitLossAfterCostKrw": tot_pl_after_krw,
            "totalCostKrw": tot_cost_krw,
        })

    return merged_result


def build_dashboard_data(account_scope="ALL", force_accounts=False):
    accounts = toss_client.get_accounts(force_refresh=force_accounts)
    if not accounts:
        return {"accounts": [], "error": "연동된 토스증권 계좌가 없습니다."}

    selected_account = accounts[0]
    seq = selected_account["accountSeq"]

    with ThreadPoolExecutor(max_workers=5) as executor:
        f_holdings = executor.submit(toss_client.request, "/api/v1/holdings", None, seq)
        f_fx = executor.submit(
            toss_client.request,
            "/api/v1/exchange-rate",
            {"baseCurrency": "USD", "quoteCurrency": "KRW"},
        )
        f_bp_krw = executor.submit(
            toss_client.request, "/api/v1/buying-power", {"currency": "KRW"}, seq
        )
        f_bp_usd = executor.submit(
            toss_client.request, "/api/v1/buying-power", {"currency": "USD"}, seq
        )
        f_kis = executor.submit(kis_client.fetch_all_accounts_data, force_accounts)

        holdings_res = f_holdings.result().get("result", {})
        try:
            fx_res = f_fx.result().get("result", {})
        except Exception:
            fx_res = {"rate": "1350.0", "midRate": "1350.0", "rateChangeType": "EQUAL"}

        try:
            bp_krw_res = f_bp_krw.result().get("result", {})
        except Exception:
            bp_krw_res = {"cashBuyingPower": "0"}

        try:
            bp_usd_res = f_bp_usd.result().get("result", {})
        except Exception:
            bp_usd_res = {"cashBuyingPower": "0"}

        try:
            kis_data = f_kis.result()
        except Exception:
            kis_data = {"accounts": [], "itemsByAcc": {}, "cashByAcc": {}}

    usd_krw_rate = to_float(fx_res.get("rate"), 1350.0)
    brokerage_cash_krw = to_float(bp_krw_res.get("cashBuyingPower"), 0.0)
    brokerage_cash_usd = to_float(bp_usd_res.get("cashBuyingPower"), 0.0)

    raw_items = holdings_res.get("items") or []
    brokerage_items = []
    for item in raw_items:
        curr = item.get("currency", "KRW")
        fx_mult = usd_krw_rate if curr == "USD" else 1.0

        qty = to_float(item.get("quantity"))
        last_price = to_float(item.get("lastPrice"))
        avg_price = to_float(item.get("averagePurchasePrice"))

        imv = item.get("marketValue") or {}
        ipl = item.get("profitLoss") or {}
        idpl = item.get("dailyProfitLoss") or {}
        icost = item.get("cost") or {}

        purch_amt = to_float(imv.get("purchaseAmount"))
        val_amt = to_float(imv.get("amount"))
        val_after = to_float(imv.get("amountAfterCost"))

        pl_val = to_float(ipl.get("amount"))
        pl_after_val = to_float(ipl.get("amountAfterCost"))
        pl_rate_pct = to_float(ipl.get("rate")) * 100.0
        pl_rate_after_pct = to_float(ipl.get("rateAfterCost")) * 100.0

        dpl_val = to_float(idpl.get("amount"))
        dpl_rate_pct = to_float(idpl.get("rate")) * 100.0

        comm = to_float(icost.get("commission"))
        tax = to_float(icost.get("tax"))
        total_item_cost = comm + tax

        brokerage_items.append({
            "symbol": item.get("symbol"),
            "name": item.get("name"),
            "accountTag": "BROKERAGE",
            "accountLabel": "토스 종합매매",
            "shortLabel": "토스종합",
            "marketCountry": item.get("marketCountry"),
            "currency": curr,
            "quantity": qty,
            "lastPrice": last_price,
            "averagePurchasePrice": avg_price,
            "lastPriceKrw": last_price * fx_mult,
            "averagePurchasePriceKrw": avg_price * fx_mult,
            "purchaseAmount": purch_amt,
            "marketValue": val_amt,
            "marketValueAfterCost": val_after,
            "profitLoss": pl_val,
            "profitLossAfterCost": pl_after_val,
            "returnRatePct": pl_rate_pct,
            "returnRateAfterCostPct": pl_rate_after_pct,
            "dailyProfitLoss": dpl_val,
            "dailyReturnRatePct": dpl_rate_pct,
            "commission": comm,
            "tax": tax,
            "totalCost": total_item_cost,
            "purchaseAmountKrw": purch_amt * fx_mult,
            "marketValueKrw": val_amt * fx_mult,
            "marketValueAfterCostKrw": val_after * fx_mult,
            "profitLossKrw": pl_val * fx_mult,
            "profitLossAfterCostKrw": pl_after_val * fx_mult,
            "dailyProfitLossKrw": dpl_val * fx_mult,
            "totalCostKrw": total_item_cost * fx_mult,
            "weightByPurchasePct": 0.0,
            "weightByMarketValuePct": 0.0,
        })

    ria_data = load_ria_holdings()
    ria_items = build_ria_enriched_items(ria_data, usd_krw_rate)
    ria_cash_krw = to_float(ria_data.get("cashKrw"), 0.0)
    ria_cash_usd = to_float(ria_data.get("cashUsd"), 0.0)

    kis_items_by_acc = kis_data.get("itemsByAcc") or {}
    kis_cash_by_acc = kis_data.get("cashByAcc") or {}
    kis_1_items = kis_items_by_acc.get("KIS_1") or []
    kis_2_items = kis_items_by_acc.get("KIS_2") or []
    kis_3_items = kis_items_by_acc.get("KIS_3") or []
    kis_4_items = kis_items_by_acc.get("KIS_4") or []
    kis_all_raw_items = kis_1_items + kis_2_items + kis_3_items + kis_4_items
    kis_all_cash_krw = sum(to_float(v, 0.0) for v in kis_cash_by_acc.values())

    merged_all_items = merge_same_symbol_items(brokerage_items + ria_items + kis_all_raw_items)
    merged_kis_all_items = merge_same_symbol_items(kis_all_raw_items)

    selected_set = parse_scope_set(account_scope)
    raw_selected_items = []
    cash_krw = 0.0
    cash_usd = 0.0

    if "BROKERAGE" in selected_set:
        raw_selected_items.extend(brokerage_items)
        cash_krw += brokerage_cash_krw
        cash_usd += brokerage_cash_usd
    if "RIA" in selected_set:
        raw_selected_items.extend(ria_items)
        cash_krw += ria_cash_krw
        cash_usd += ria_cash_usd
    for k_id in ("KIS_1", "KIS_2", "KIS_3", "KIS_4"):
        if k_id in selected_set:
            raw_selected_items.extend(kis_items_by_acc.get(k_id) or [])
            cash_krw += to_float(kis_cash_by_acc.get(k_id), 0.0)

    if len(selected_set) > 1:
        active_items = merge_same_symbol_items(raw_selected_items)
    else:
        active_items = raw_selected_items

    krw_items = [i for i in active_items if i["currency"] == "KRW"]
    usd_items = [i for i in active_items if i["currency"] == "USD"]

    krw_purchase = sum(i["purchaseAmount"] for i in krw_items)
    krw_mv = sum(i["marketValue"] for i in krw_items)
    krw_mv_after = sum(i["marketValueAfterCost"] for i in krw_items)
    krw_pl = sum(i["profitLoss"] for i in krw_items)
    krw_pl_after = sum(i["profitLossAfterCost"] for i in krw_items)
    krw_dpl = sum(i["dailyProfitLoss"] for i in krw_items)
    krw_rate = (krw_pl / krw_purchase * 100.0) if krw_purchase > 0 else 0.0
    krw_rate_after = (krw_pl_after / krw_purchase * 100.0) if krw_purchase > 0 else 0.0

    usd_purchase = sum(i["purchaseAmount"] for i in usd_items)
    usd_mv = sum(i["marketValue"] for i in usd_items)
    usd_mv_after = sum(i["marketValueAfterCost"] for i in usd_items)
    usd_pl = sum(i["profitLoss"] for i in usd_items)
    usd_pl_after = sum(i["profitLossAfterCost"] for i in usd_items)
    usd_dpl = sum(i["dailyProfitLoss"] for i in usd_items)
    usd_rate = (usd_pl / usd_purchase * 100.0) if usd_purchase > 0 else 0.0
    usd_rate_after = (usd_pl_after / usd_purchase * 100.0) if usd_purchase > 0 else 0.0

    usd_purchase_krw = usd_purchase * usd_krw_rate
    usd_mv_krw = usd_mv * usd_krw_rate
    usd_mv_after_krw = usd_mv_after * usd_krw_rate
    usd_pl_krw = usd_pl * usd_krw_rate
    usd_pl_after_krw = usd_pl_after * usd_krw_rate
    usd_dpl_krw = usd_dpl * usd_krw_rate
    cash_usd_krw = cash_usd * usd_krw_rate

    total_purchase_krw = krw_purchase + usd_purchase_krw
    total_mv_krw = krw_mv + usd_mv_krw
    total_mv_after_krw = krw_mv_after + usd_mv_after_krw
    total_pl_krw = krw_pl + usd_pl_krw
    total_pl_after_krw = krw_pl_after + usd_pl_after_krw
    total_dpl_krw = krw_dpl + usd_dpl_krw
    total_cost_krw = (krw_mv - krw_mv_after) + (usd_mv_krw - usd_mv_after_krw)

    total_return_pct = (
        (total_pl_krw / total_purchase_krw * 100.0) if total_purchase_krw > 0 else 0.0
    )
    total_return_after_pct = (
        (total_pl_after_krw / total_purchase_krw * 100.0) if total_purchase_krw > 0 else 0.0
    )

    pl_obj = holdings_res.get("profitLoss") or {}
    dpl_obj = holdings_res.get("dailyProfitLoss") or {}
    raw_brok_sdk_rate = to_float(pl_obj.get("rate"))
    raw_brok_sdk_rate_after = to_float(pl_obj.get("rateAfterCost"))

    brok_mv_krw = sum(i["marketValueKrw"] for i in brokerage_items)
    brok_mv_after_krw = sum(i["marketValueAfterCostKrw"] for i in brokerage_items)
    brok_purchase_krw = sum(i["purchaseAmountKrw"] for i in brokerage_items)

    # Derive brokerage internal KRW cost basis implied by Toss official SDK rate (reflecting historical FX)
    if brok_mv_krw > 0 and (1.0 + raw_brok_sdk_rate) > 0:
        brok_sdk_purchase_krw = brok_mv_krw / (1.0 + raw_brok_sdk_rate)
    else:
        brok_sdk_purchase_krw = brok_purchase_krw

    if brok_mv_after_krw > 0 and (1.0 + raw_brok_sdk_rate_after) > 0:
        brok_sdk_purchase_after_krw = brok_mv_after_krw / (1.0 + raw_brok_sdk_rate_after)
    else:
        brok_sdk_purchase_after_krw = brok_purchase_krw

    ria_purchase_krw = sum(i["purchaseAmountKrw"] for i in ria_items)
    ria_mv_krw = sum(i["marketValueKrw"] for i in ria_items)
    ria_mv_after_krw = sum(i["marketValueAfterCostKrw"] for i in ria_items)

    kis_purchase_krw = sum(i["purchaseAmountKrw"] for i in kis_all_raw_items)
    kis_mv_krw = sum(i["marketValueKrw"] for i in kis_all_raw_items)
    kis_mv_after_krw = sum(i["marketValueAfterCostKrw"] for i in kis_all_raw_items)

    if selected_set == {"BROKERAGE"}:
        sdk_rate_pct = raw_brok_sdk_rate * 100.0
        sdk_rate_after_pct = raw_brok_sdk_rate_after * 100.0
    elif "BROKERAGE" not in selected_set:
        sdk_rate_pct = total_return_pct
        sdk_rate_after_pct = total_return_after_pct
    else:
        # Combine Toss official brokerage basis + any other selected accounts (RIA / KIS)
        other_purch_krw = (ria_purchase_krw if "RIA" in selected_set else 0.0) + sum(
            sum(i["purchaseAmountKrw"] for i in (kis_items_by_acc.get(k) or []))
            for k in ("KIS_1", "KIS_2", "KIS_3", "KIS_4")
            if k in selected_set
        )
        other_mv_krw = (ria_mv_krw if "RIA" in selected_set else 0.0) + sum(
            sum(i["marketValueKrw"] for i in (kis_items_by_acc.get(k) or []))
            for k in ("KIS_1", "KIS_2", "KIS_3", "KIS_4")
            if k in selected_set
        )
        other_mv_after_krw = (ria_mv_after_krw if "RIA" in selected_set else 0.0) + sum(
            sum(i["marketValueAfterCostKrw"] for i in (kis_items_by_acc.get(k) or []))
            for k in ("KIS_1", "KIS_2", "KIS_3", "KIS_4")
            if k in selected_set
        )
        comb_sdk_purch = brok_sdk_purchase_krw + other_purch_krw
        comb_sdk_purch_after = brok_sdk_purchase_after_krw + other_purch_krw
        comb_mv = brok_mv_krw + other_mv_krw
        comb_mv_after = brok_mv_after_krw + other_mv_after_krw
        sdk_rate_pct = (
            ((comb_mv - comb_sdk_purch) / comb_sdk_purch * 100.0) if comb_sdk_purch > 0 else 0.0
        )
        sdk_rate_after_pct = (
            ((comb_mv_after - comb_sdk_purch_after) / comb_sdk_purch_after * 100.0)
            if comb_sdk_purch_after > 0
            else 0.0
        )

    sdk_daily_rate_pct = (
        (total_dpl_krw / (total_mv_krw - total_dpl_krw) * 100.0)
        if (total_mv_krw - total_dpl_krw) > 0
        else (to_float(dpl_obj.get("rate")) * 100.0 if account_scope == "BROKERAGE" else 0.0)
    )

    total_cash_krw = cash_krw + cash_usd_krw
    total_asset_krw = total_mv_krw + total_cash_krw

    for it in active_items:
        it["isOverseasEtf"] = is_domestic_overseas_etf(
            it.get("name", ""), it.get("symbol", ""), it.get("currency", "KRW")
        )
        it["weightByPurchasePct"] = (
            (it["purchaseAmountKrw"] / total_purchase_krw * 100.0) if total_purchase_krw > 0 else 0.0
        )
        it["weightByMarketValuePct"] = (
            (it["marketValueKrw"] / total_mv_krw * 100.0) if total_mv_krw > 0 else 0.0
        )

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "accountScope": account_scope,
        "capitalSummary": get_capital_summary(),
        "accounts": accounts,
        "selectedAccount": selected_account,
        "kisAccounts": kis_data.get("accounts") or [],
        "kisItemsByAcc": kis_items_by_acc,
        "counts": {
            "all": len(merged_all_items),
            "brokerage": len(brokerage_items),
            "ria": len(ria_items),
            "kisAll": len(merged_kis_all_items),
            "kis1": len(kis_1_items),
            "kis2": len(kis_2_items),
            "kis3": len(kis_3_items),
            "kis4": len(kis_4_items),
        },
        "brokerageItems": brokerage_items,
        "riaConfig": {
            "cashKrw": ria_cash_krw,
            "cashUsd": ria_cash_usd,
            "items": ria_items,
            "sales": ria_data.get("sales") or [],
            "salesSummary": summarize_ria_sales(ria_data.get("sales") or []),
        },
        "exchangeRate": {
            "baseCurrency": fx_res.get("baseCurrency", "USD"),
            "quoteCurrency": fx_res.get("quoteCurrency", "KRW"),
            "rate": usd_krw_rate,
            "midRate": to_float(fx_res.get("midRate"), usd_krw_rate),
            "rateChangeType": fx_res.get("rateChangeType", "EQUAL"),
            "validFrom": fx_res.get("validFrom"),
            "validUntil": fx_res.get("validUntil"),
        },
        "totalKrw": {
            "purchaseAmount": total_purchase_krw,
            "marketValue": total_mv_krw,
            "marketValueAfterCost": total_mv_after_krw,
            "profitLoss": total_pl_krw,
            "profitLossAfterCost": total_pl_after_krw,
            "totalCost": total_cost_krw,
            "returnRatePct": total_return_pct,
            "returnRateAfterCostPct": total_return_after_pct,
            "sdkReturnRatePct": sdk_rate_pct,
            "sdkReturnRateAfterCostPct": sdk_rate_after_pct,
            "dailyProfitLoss": total_dpl_krw,
            "dailyReturnRatePct": sdk_daily_rate_pct,
            "cashBuyingPower": total_cash_krw,
            "totalAsset": total_asset_krw,
        },
        "krwMarket": {
            "purchaseAmount": krw_purchase,
            "marketValue": krw_mv,
            "marketValueAfterCost": krw_mv_after,
            "profitLoss": krw_pl,
            "profitLossAfterCost": krw_pl_after,
            "totalCost": krw_mv - krw_mv_after,
            "returnRatePct": krw_rate,
            "returnRateAfterCostPct": krw_rate_after,
            "dailyProfitLoss": krw_dpl,
            "cashBuyingPower": cash_krw,
        },
        "usdMarket": {
            "purchaseAmount": usd_purchase,
            "marketValue": usd_mv,
            "marketValueAfterCost": usd_mv_after,
            "profitLoss": usd_pl,
            "profitLossAfterCost": usd_pl_after,
            "totalCost": usd_mv - usd_mv_after,
            "returnRatePct": usd_rate,
            "returnRateAfterCostPct": usd_rate_after,
            "dailyProfitLoss": usd_dpl,
            "cashBuyingPower": cash_usd,
            "purchaseAmountKrw": usd_purchase_krw,
            "marketValueKrw": usd_mv_krw,
            "marketValueAfterCostKrw": usd_mv_after_krw,
            "profitLossKrw": usd_pl_krw,
            "profitLossAfterCostKrw": usd_pl_after_krw,
            "dailyProfitLossKrw": usd_dpl_krw,
            "cashBuyingPowerKrw": cash_usd_krw,
        },
        "items": active_items,
    }


def _prepare_order_reconstructed_account(held_items: list, filled_orders_desc: list):
    orders_asc = list(reversed(filled_orders_desc))
    held_map = {it["symbol"]: it for it in held_items}
    sym_orders = {}
    sym_currency = {}
    for it in held_items:
        sym_currency[it["symbol"]] = it["currency"]

    for o in orders_asc:
        sym = (o.get("symbol") or "").upper()
        if not sym:
            continue
        sym_currency[sym] = o.get("currency") or ("KRW" if is_kr_symbol(sym) else "USD")
        sym_orders.setdefault(sym, []).append(o)

    init_qty = {}
    init_cost = {}
    qty_scale = {}
    cost_scale = {}
    active_symbols = set()

    candidate_syms = set(held_map.keys()) | set(sym_orders.keys())
    for sym in candidate_syms:
        olist = sym_orders.get(sym, [])
        b_q = sum(to_float((o.get("execution") or {}).get("filledQuantity")) for o in olist if o.get("side") == "BUY")
        b_amt = sum(to_float((o.get("execution") or {}).get("filledAmount")) for o in olist if o.get("side") == "BUY")
        s_q = sum(to_float((o.get("execution") or {}).get("filledQuantity")) for o in olist if o.get("side") == "SELL")
        cur_it = held_map.get(sym)
        cur_q = cur_it["quantity"] if cur_it else 0.0
        cur_cost = cur_it["purchaseAmount"] if cur_it else 0.0

        if cur_q <= 1e-6 and s_q <= 1e-6:
            continue

        active_symbols.add(sym)
        scale = 1.0
        c_scale = 1.0
        net_q = b_q - s_q
        if cur_q > 0 and net_q > cur_q and s_q == 0 and b_q > 0:
            scale = cur_q / b_q
            if b_amt > 0 and cur_cost > 0:
                c_scale = cur_cost / b_amt
            iq = 0.0
        else:
            iq = max(0.0, cur_q - net_q)

        qty_scale[sym] = scale
        cost_scale[sym] = c_scale
        init_qty[sym] = iq

        if cur_q > 0 and iq > 0:
            q = iq
            c_coeff = 1.0
            c_const = 0.0
            for o in olist:
                ex = o.get("execution") or {}
                fq = to_float(ex.get("filledQuantity")) * scale
                fa = to_float(ex.get("filledAmount")) * c_scale
                if o.get("side") == "BUY":
                    q += fq
                    c_const += fa
                else:
                    if q > 0:
                        ratio = max(0.0, (q - fq) / q)
                        c_coeff *= ratio
                        c_const *= ratio
                        q = max(0.0, q - fq)
            ic = (cur_cost - c_const) / c_coeff if c_coeff > 1e-6 else (iq * cur_it["averagePurchasePrice"])
            if ic <= 0:
                ic = iq * cur_it["averagePurchasePrice"]
            init_cost[sym] = ic
        else:
            init_cost[sym] = 0.0
            if iq > 0:
                synth = [o for o in olist if o.get("synthetic") and o.get("side") == "SELL"]
                synth_q = sum(to_float((o.get("execution") or {}).get("filledQuantity")) for o in synth)
                synth_c = sum(to_float(o.get("costNative")) for o in synth)
                if synth_q > 0 and synth_c > 0:
                    init_cost[sym] = iq * (synth_c / synth_q)

    return {
        "held_map": held_map,
        "sym_orders": sym_orders,
        "sym_currency": sym_currency,
        "init_qty": init_qty,
        "init_cost": init_cost,
        "qty_scale": qty_scale,
        "cost_scale": cost_scale,
        "active_symbols": active_symbols,
    }


def build_returns_history(account_scope="ALL", pages=4, force_refresh=False):
    dash = build_dashboard_data(account_scope="ALL", force_accounts=force_refresh)
    brok_held_items = dash.get("brokerageItems") or []
    ria_held_items = (dash.get("riaConfig") or {}).get("items") or []
    kis_items_by_acc = dash.get("kisItemsByAcc") or {}
    usd_krw_rate = to_float(dash.get("exchangeRate", {}).get("rate"), 1350.0)
    seq = (dash.get("selectedAccount") or {}).get("accountSeq", 1)

    selected_set = parse_scope_set(account_scope)
    include_brok = "BROKERAGE" in selected_set
    include_ria = "RIA" in selected_set
    include_kis_1 = "KIS_1" in selected_set
    include_kis_2 = "KIS_2" in selected_set
    include_kis_3 = "KIS_3" in selected_set
    include_kis_4 = "KIS_4" in selected_set

    # Accounts reconstructed via order execution history (Toss Brokerage, KIS_1, KIS_2, KIS_4)
    order_reconstructed_accounts = []
    if include_brok and brok_held_items:
        brok_orders = list(toss_client.get_all_filled_orders(seq))
        brok_orders.extend(build_transfer_sell_orders(load_ria_holdings().get("sales") or []))
        brok_orders.sort(
            key=lambda x: ((x.get("execution") or {}).get("filledAt") or x.get("orderedAt") or "")[:10],
            reverse=True,
        )
        order_reconstructed_accounts.append(
            _prepare_order_reconstructed_account(brok_held_items, brok_orders)
        )
    if include_kis_1:
        k1_items = kis_items_by_acc.get("KIS_1") or []
        k1_orders = kis_client.get_account_filled_orders("KIS_1")
        if k1_items or k1_orders:
            order_reconstructed_accounts.append(
                _prepare_order_reconstructed_account(k1_items, k1_orders)
            )
    if include_kis_2:
        k2_items = kis_items_by_acc.get("KIS_2") or []
        k2_orders = kis_client.get_account_filled_orders("KIS_2")
        if k2_items or k2_orders:
            order_reconstructed_accounts.append(
                _prepare_order_reconstructed_account(k2_items, k2_orders)
            )
    if include_kis_4:
        k4_items = kis_items_by_acc.get("KIS_4") or []
        k4_orders = kis_client.get_account_filled_orders("KIS_4")
        if k4_items or k4_orders:
            order_reconstructed_accounts.append(
                _prepare_order_reconstructed_account(k4_items, k4_orders)
            )

    # Accounts reconstructed via purchaseDate activation (Toss RIA, KIS_3 IRP)
    date_activated_items = []
    if include_ria:
        date_activated_items.extend(ria_held_items)
    if include_kis_3:
        date_activated_items.extend(kis_items_by_acc.get("KIS_3") or [])

    all_needed_symbols = set()
    sym_currency = {}
    for acc_state in order_reconstructed_accounts:
        all_needed_symbols.update(acc_state["active_symbols"])
        sym_currency.update(acc_state["sym_currency"])
    for dit in date_activated_items:
        if dit.get("symbol"):
            all_needed_symbols.add(dit["symbol"])
            sym_currency[dit["symbol"]] = dit.get("currency", "KRW")

    all_needed_symbols = list(all_needed_symbols)
    if not all_needed_symbols:
        return {"daily": [], "monthly": [], "yearly": [], "totalPurchaseKrw": 0}

    symbol_date_price = {}
    all_dates_set = set()

    def fetch_sym_candles(sym):
        c_list = toss_client.get_daily_candles_extended(sym, pages=pages)
        date_map = {}
        for c in c_list:
            ts = c.get("timestamp") or ""
            d_str = ts[:10]
            if d_str:
                date_map[d_str] = to_float(c.get("closePrice"), 0.0)
        return sym, date_map

    with ThreadPoolExecutor(max_workers=2) as ex:
        for sym, d_map in ex.map(fetch_sym_candles, all_needed_symbols):
            symbol_date_price[sym] = d_map
            all_dates_set.update(d_map.keys())

    sorted_dates = sorted(all_dates_set)
    if not sorted_dates:
        return {"daily": [], "monthly": [], "yearly": [], "totalPurchaseKrw": 0}

    earliest_chart_date = sorted_dates[0]
    latest_chart_date = sorted_dates[-1]

    # Live price map from currently held items for final-date exact alignment
    live_price_map = {}
    for acc_state in order_reconstructed_accounts:
        for sym, it in acc_state["held_map"].items():
            if to_float(it.get("lastPrice"), 0.0) > 0:
                live_price_map[sym] = to_float(it.get("lastPrice"), 0.0)
    for dit in date_activated_items:
        if dit.get("symbol") and to_float(dit.get("lastPrice"), 0.0) > 0:
            live_price_map[dit["symbol"]] = to_float(dit.get("lastPrice"), 0.0)

    # Initialize state per order-reconstructed account
    for acc_state in order_reconstructed_accounts:
        cur_qty = {sym: acc_state["init_qty"].get(sym, 0.0) for sym in acc_state["active_symbols"]}
        cur_cost = {sym: acc_state["init_cost"].get(sym, 0.0) for sym in acc_state["active_symbols"]}
        orders_by_date = {}
        for sym in acc_state["active_symbols"]:
            scale = acc_state["qty_scale"].get(sym, 1.0)
            c_scale = acc_state.get("cost_scale", {}).get(sym, 1.0)
            for o in acc_state["sym_orders"].get(sym, []):
                ex = o.get("execution") or {}
                odt = (ex.get("filledAt") or o.get("orderedAt") or "")[:10]
                if not odt:
                    continue
                if odt < earliest_chart_date:
                    fq = to_float(ex.get("filledQuantity")) * scale
                    fa = to_float(ex.get("filledAmount")) * c_scale
                    if o.get("side") == "BUY":
                        cur_qty[sym] += fq
                        cur_cost[sym] += fa
                    else:
                        q_prev = cur_qty[sym]
                        if q_prev > 0:
                            ratio = max(0.0, (q_prev - fq) / q_prev)
                            cur_cost[sym] *= ratio
                            cur_qty[sym] = max(0.0, q_prev - fq)
                else:
                    orders_by_date.setdefault(odt, []).append((sym, o, scale, c_scale))
        acc_state["cur_qty"] = cur_qty
        acc_state["cur_cost"] = cur_cost
        acc_state["orders_by_date"] = orders_by_date

    # Track last known price per symbol
    last_known_price = {}
    for sym in all_needed_symbols:
        d_map = symbol_date_price.get(sym, {})
        if d_map:
            earliest_sym_date = min(d_map.keys())
            last_known_price[sym] = d_map[earliest_sym_date]
        else:
            last_known_price[sym] = 0.0

    daily_series = []
    prev_pl = None
    prev_rate = None
    prev_mv = None

    for d_str in sorted_dates:
        # Apply orders on d_str for each order-reconstructed account
        for acc_state in order_reconstructed_accounts:
            cur_qty = acc_state["cur_qty"]
            cur_cost = acc_state["cur_cost"]
            for sym, o, scale, c_scale in acc_state["orders_by_date"].get(d_str, []):
                ex = o.get("execution") or {}
                fq = to_float(ex.get("filledQuantity")) * scale
                fa = to_float(ex.get("filledAmount")) * c_scale
                if o.get("side") == "BUY":
                    cur_qty[sym] = cur_qty.get(sym, 0.0) + fq
                    cur_cost[sym] = cur_cost.get(sym, 0.0) + fa
                else:
                    q_prev = cur_qty.get(sym, 0.0)
                    if q_prev > 0:
                        ratio = max(0.0, (q_prev - fq) / q_prev)
                        cur_cost[sym] = cur_cost.get(sym, 0.0) * ratio
                        cur_qty[sym] = max(0.0, q_prev - fq)

        # Update prices for d_str
        for sym in all_needed_symbols:
            d_map = symbol_date_price.get(sym, {})
            if d_str in d_map and d_map[d_str] > 0:
                last_known_price[sym] = d_map[d_str]
            if d_str == latest_chart_date and sym in live_price_map:
                last_known_price[sym] = live_price_map[sym]

        day_purchase_krw = 0.0
        day_mv_krw = 0.0
        day_krw_mv = 0.0
        day_usd_mv_krw = 0.0

        # Sum active positions across order-reconstructed accounts
        for acc_state in order_reconstructed_accounts:
            cur_qty = acc_state["cur_qty"]
            cur_cost = acc_state["cur_cost"]
            for sym in acc_state["active_symbols"]:
                q = cur_qty.get(sym, 0.0)
                c = cur_cost.get(sym, 0.0)
                if q <= 1e-5 or c <= 1e-2:
                    continue
                curr = acc_state["sym_currency"].get(sym, "KRW")
                fx_mult = usd_krw_rate if curr == "USD" else 1.0
                price = last_known_price.get(sym, 0.0)
                if price <= 0 and c > 0:
                    price = c / q
                p_krw = c * fx_mult
                v_krw = q * price * fx_mult
                day_purchase_krw += p_krw
                day_mv_krw += v_krw
                if curr == "USD":
                    day_usd_mv_krw += v_krw
                else:
                    day_krw_mv += v_krw

        # Sum active date-activated positions (RIA & KIS_3 IRP) whose purchaseDate <= d_str
        for dit in date_activated_items:
            p_date = dit.get("purchaseDate") or earliest_chart_date
            if d_str < p_date:
                continue
            sym = dit["symbol"]
            curr = dit["currency"]
            fx_mult = usd_krw_rate if curr == "USD" else 1.0
            price = last_known_price.get(sym, dit["lastPrice"])
            if price <= 0:
                price = dit["averagePurchasePrice"]
            p_krw = dit["purchaseAmount"] * fx_mult
            v_krw = dit["quantity"] * price * fx_mult
            day_purchase_krw += p_krw
            day_mv_krw += v_krw
            if curr == "USD":
                day_usd_mv_krw += v_krw
            else:
                day_krw_mv += v_krw

        if day_purchase_krw <= 0:
            continue

        pl_krw = day_mv_krw - day_purchase_krw
        rate_pct = (pl_krw / day_purchase_krw * 100.0) if day_purchase_krw > 0 else 0.0
        # Pure investment profit change excluding newly added/withdrawn principal (first period uses 0원 principal baseline)
        period_pl = (pl_krw - prev_pl) if prev_pl is not None else pl_krw
        period_rate_diff = (rate_pct - prev_rate) if prev_rate is not None else rate_pct
        # 구간 등락률(%): 직전 구간 평가금액(prev_mv) 대비 당기 순수 손익 증감률 (첫 구간은 원금 대비 수익률)
        period_change_pct = (
            (period_pl / prev_mv * 100.0) if (prev_mv is not None and prev_mv > 0) else rate_pct
        )

        daily_series.append({
            "period": d_str,
            "purchaseAmountKrw": round(day_purchase_krw),
            "marketValueKrw": round(day_mv_krw),
            "krwMarketValue": round(day_krw_mv),
            "usdMarketValueKrw": round(day_usd_mv_krw),
            "profitLossKrw": round(pl_krw),
            "returnRatePct": round(rate_pct, 2),
            "periodProfitChangeKrw": round(period_pl),
            "periodRateDiffPct": round(period_rate_diff, 2),
            "periodReturnPct": round(period_change_pct, 2),
        })
        prev_pl = pl_krw
        prev_rate = rate_pct
        prev_mv = day_mv_krw

    # Aggregate into monthly (last trading day of each YYYY-MM)
    monthly_map = {}
    for row in daily_series:
        ym = row["period"][:7]
        monthly_map[ym] = row

    monthly_series = []
    prev_m_pl = None
    prev_m_rate = None
    prev_m_mv = None
    for ym in sorted(monthly_map.keys()):
        snap = dict(monthly_map[ym])
        snap["period"] = ym
        pl_krw = snap["profitLossKrw"]
        mv_krw = snap["marketValueKrw"]
        rate_pct = snap["returnRatePct"]
        m_pl_diff = round(pl_krw - prev_m_pl) if prev_m_pl is not None else round(pl_krw)
        snap["periodProfitChangeKrw"] = m_pl_diff
        snap["periodRateDiffPct"] = round(rate_pct - prev_m_rate, 2) if prev_m_rate is not None else round(rate_pct, 2)
        snap["periodReturnPct"] = (
            round(m_pl_diff / prev_m_mv * 100.0, 2)
            if (prev_m_mv is not None and prev_m_mv > 0)
            else round(rate_pct, 2)
        )
        monthly_series.append(snap)
        prev_m_pl = pl_krw
        prev_m_rate = rate_pct
        prev_m_mv = mv_krw

    # Aggregate into yearly (last trading day of each YYYY)
    yearly_map = {}
    for row in daily_series:
        yr = row["period"][:4]
        yearly_map[yr] = row

    yearly_series = []
    prev_y_pl = None
    prev_y_rate = None
    prev_y_mv = None
    for yr in sorted(yearly_map.keys()):
        snap = dict(yearly_map[yr])
        snap["period"] = f"{yr}년"
        pl_krw = snap["profitLossKrw"]
        mv_krw = snap["marketValueKrw"]
        rate_pct = snap["returnRatePct"]
        y_pl_diff = round(pl_krw - prev_y_pl) if prev_y_pl is not None else round(pl_krw)
        snap["periodProfitChangeKrw"] = y_pl_diff
        snap["periodRateDiffPct"] = round(rate_pct - prev_y_rate, 2) if prev_y_rate is not None else round(rate_pct, 2)
        snap["periodReturnPct"] = (
            round(y_pl_diff / prev_y_mv * 100.0, 2)
            if (prev_y_mv is not None and prev_y_mv > 0)
            else round(rate_pct, 2)
        )
        yearly_series.append(snap)
        prev_y_pl = pl_krw
        prev_y_rate = rate_pct
        prev_y_mv = mv_krw

    return {
        "totalPurchaseKrw": daily_series[-1]["purchaseAmountKrw"] if daily_series else 0,
        "daily": daily_series,
        "monthly": monthly_series,
        "yearly": yearly_series,
    }


ALLOWED_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/mobile": ("mobile.html", "text/html; charset=utf-8"),
    "/m": ("mobile.html", "text/html; charset=utf-8"),
    "/mobile.html": ("mobile.html", "text/html; charset=utf-8"),
    "/manifest.json": ("manifest.json", "application/manifest+json; charset=utf-8"),
    "/sw.js": ("sw.js", "application/javascript; charset=utf-8"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/icon-maskable-192.png": ("icon-maskable-192.png", "image/png"),
    "/icon-maskable-512.png": ("icon-maskable-512.png", "image/png"),
    "/apple-touch-icon.png": ("icon-192.png", "image/png"),
    "/favicon.ico": ("icon-192.png", "image/png"),
}

PUBLIC_PWA_FILES = {
    "/manifest.json",
    "/sw.js",
    "/icon-192.png",
    "/icon-512.png",
    "/icon-maskable-192.png",
    "/icon-maskable-512.png",
    "/apple-touch-icon.png",
    "/favicon.ico",
}

_RATE_LIMIT_LOCK = threading.Lock()
_IP_REQUEST_LOG = {}
_LAST_FORCE_REFRESH_TS = {"dashboard": 0.0, "history": 0.0}
RATE_LIMIT_WINDOW_SEC = 10.0
RATE_LIMIT_MAX_REQ = 60
FORCE_REFRESH_COOLDOWN_SEC = 2.5
MAX_POST_BODY_BYTES = 64 * 1024


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format, *args):
        pass

    def list_directory(self, path):
        self._send_json({"error": "디렉터리 조회가 금지되어 있습니다."}, status=403)
        return None

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-XSS-Protection", "1; mode=block")
        super().end_headers()

    def _check_security(self) -> bool:
        client_ip = (self.client_address[0] if self.client_address else "") or ""
        now = time.time()

        # 1. IP별 Rate Limit 검사 (DoS / 무차별 대입 방어)
        with _RATE_LIMIT_LOCK:
            history = _IP_REQUEST_LOG.get(client_ip, [])
            history = [t for t in history if now - t < RATE_LIMIT_WINDOW_SEC]
            if len(history) >= RATE_LIMIT_MAX_REQ:
                _IP_REQUEST_LOG[client_ip] = history
                self._send_json(
                    {"error": "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."},
                    status=429,
                )
                return False
            history.append(now)
            _IP_REQUEST_LOG[client_ip] = history

        # 2. 비밀번호 인증 및 마스터키 복호화 검사
        _, raw_map = _read_raw_env_lines()
        has_pw_config = bool(
            raw_map.get("DASHBOARD_PASSWORD_HASH") or raw_map.get("DASHBOARD_PASSWORD")
        )
        is_local = client_ip in ("127.0.0.1", "::1", "localhost")

        if has_pw_config or not is_local:
            if not has_pw_config:
                self._send_json(
                    {"error": "외부 접속이 차단되었습니다."},
                    status=403,
                )
                return False
            auth_header = self.headers.get("Authorization") or ""
            authorized = False
            if auth_header.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
                    user_in, pw_in = decoded.split(":", 1)
                    user_hash = raw_map.get("DASHBOARD_USER_HASH")
                    user_plain = raw_map.get("DASHBOARD_USER")
                    user_ok = True
                    if user_hash:
                        user_ok = verify_password_hash(user_in, user_hash)
                    elif user_plain:
                        user_ok = hmac.compare_digest(user_in, user_plain)
                    if user_ok and unlock_with_password(pw_in):
                        authorized = True
                except Exception:
                    authorized = False
            if not authorized:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Integrated Stock Portfolio"')
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write("인증이 필요합니다.".encode("utf-8"))
                return False

        return True

    def _allow_force_refresh(self, key: str, requested_force: bool) -> bool:
        if not requested_force:
            return False
        now = time.time()
        with _RATE_LIMIT_LOCK:
            last_ts = _LAST_FORCE_REFRESH_TS.get(key, 0.0)
            if now - last_ts < FORCE_REFRESH_COOLDOWN_SEC:
                return False
            _LAST_FORCE_REFRESH_TS[key] = now
            return True

    def _serve_whitelisted_static(self, path: str):
        if path not in ALLOWED_STATIC_FILES:
            self._send_json({"error": "접근이 허용되지 않은 경로입니다."}, status=403)
            return
        filename, content_type = ALLOWED_STATIC_FILES[path]
        target_path = (STATIC_DIR / filename).resolve()
        if not str(target_path).startswith(str(STATIC_DIR.resolve())) or not target_path.is_file():
            self._send_json({"error": "파일을 찾을 수 없습니다."}, status=404)
            return
        raw = target_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if filename == "sw.js":
            self.send_header("Service-Worker-Allowed", "/")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        elif filename == "manifest.json":
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        elif filename.endswith(".png"):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_json(self, data, status=200):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # Public PWA metadata/icons: serve without Basic Auth for Chrome / Google WebAPK service
        if path in PUBLIC_PWA_FILES:
            self._serve_whitelisted_static(path)
            return

        if not self._check_security():
            return

        def qval(key, default=None):
            vals = qs.get(key)
            return vals[0] if vals else default

        try:
            if path == "/api/dashboard":
                scope = qval("scope", "ALL")
                force = self._allow_force_refresh("dashboard", qval("refresh") == "1")
                data = build_dashboard_data(account_scope=scope, force_accounts=force)
                self._send_json(data)
                return

            if path == "/api/returns-history":
                scope = qval("scope", "ALL")
                pages = min(max(int(qval("pages", "4")), 1), 10)
                force = self._allow_force_refresh("history", qval("refresh") == "1")
                data = build_returns_history(account_scope=scope, pages=pages, force_refresh=force)
                self._send_json(data)
                return

            if path == "/api/stock-search":
                q = qval("q", "")
                results = toss_client.search_stocks(q)
                self._send_json({"results": results})
                return

            if path == "/api/ria-holdings":
                self._send_json(load_ria_holdings())
                return

            if path == "/api/capital":
                self._send_json(get_capital_summary())
                return

            if path == "/api/orders":
                accounts = toss_client.get_accounts()
                seq = qval("accountSeq") or (accounts[0]["accountSeq"] if accounts else 1)
                status = qval("status", "CLOSED")
                symbol = qval("symbol")
                from_date = qval("from")
                to_date = qval("to")
                cursor = qval("cursor")
                limit = qval("limit", "100")

                if status == "CLOSED" and not cursor and not from_date and not to_date:
                    raw_toss_orders = toss_client.get_all_closed_orders(seq)
                    orders_list = [dict(o) for o in raw_toss_orders]
                    order_res = {"orders": orders_list, "hasNext": False, "nextCursor": None}
                else:
                    resp = toss_client.request(
                        "/api/v1/orders",
                        query={
                            "status": status,
                            "from": from_date,
                            "to": to_date,
                            "cursor": cursor,
                            "limit": limit,
                        },
                        account_seq=seq,
                    )
                    order_res = resp.get("result", {})
                    orders_list = [dict(o) for o in (order_res.get("orders") or [])]

                if orders_list:
                    order_syms = [o.get("symbol") for o in orders_list if o.get("symbol")]
                    info_map = toss_client.resolve_stock_info_map(order_syms)
                    for o in orders_list:
                        osym = (o.get("symbol") or "").upper()
                        o["name"] = info_map.get(osym, {}).get("name") or o.get("name") or osym

                if status == "CLOSED":
                    kis_orders = [
                        dict(ko)
                        for ko in (
                            kis_client.get_account_filled_orders("KIS_1")
                            + kis_client.get_account_filled_orders("KIS_2")
                            + kis_client.get_account_filled_orders("KIS_4")
                        )
                    ]
                    orders_list = orders_list + kis_orders

                if symbol:
                    q_low = symbol.strip().lower()
                    exact_sym = qval("exactSymbol") == "1"
                    if exact_sym:
                        orders_list = [
                            o
                            for o in orders_list
                            if (o.get("symbol") or "").lower() == q_low
                        ]
                    else:
                        orders_list = [
                            o
                            for o in orders_list
                            if q_low in (o.get("symbol") or "").lower()
                            or q_low in (o.get("name") or "").lower()
                        ]

                orders_list.sort(
                    key=lambda x: ((x.get("execution") or {}).get("filledAt") or x.get("orderedAt") or ""),
                    reverse=True,
                )
                order_res["orders"] = orders_list

                self._send_json(order_res)
                return

            if path == "/api/candles":
                symbol = qval("symbol")
                interval = qval("interval", "1d")
                count = qval("count", "90")
                if not symbol:
                    self._send_json({"error": "symbol 파라미터가 필요합니다."}, status=400)
                    return
                resp = toss_client.request(
                    "/api/v1/candles",
                    query={
                        "symbol": symbol,
                        "interval": interval,
                        "count": count,
                        "adjusted": "true",
                    },
                )
                self._send_json(resp.get("result", {}))
                return

            self._serve_whitelisted_static(path or "/")
            return

        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def do_POST(self):
        if not self._check_security():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_POST_BODY_BYTES:
                self._send_json({"error": "요청 본문이 너무 큽니다."}, status=413)
                return
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

            if path == "/api/ria-holdings":
                ria = load_ria_holdings()
                action = body.get("action", "upsert_item")

                if action == "upsert_item":
                    sym = (body.get("symbol") or "").strip().upper()
                    raw_name = (body.get("name") or "").strip()
                    s_info = toss_client.resolve_stock_info_map([sym]).get(sym, {}) if sym else {}
                    if not raw_name or raw_name.upper() == sym:
                        name = s_info.get("name") or sym
                    else:
                        name = raw_name
                    curr = (
                        s_info.get("currency")
                        or ("KRW" if is_kr_symbol(sym) else None)
                        or body.get("currency")
                        or "USD"
                    )
                    qty = to_float(body.get("quantity"), 0.0)
                    avg_price = to_float(body.get("averagePurchasePrice"), 0.0)
                    purch_amt = to_float(body.get("purchaseAmount"), 0.0)
                    purch_date = (body.get("purchaseDate") or "").strip()

                    if not sym or qty <= 0:
                        self._send_json({"error": "종목코드와 보유수량(0보다 큰 값)을 입력해 주세요."}, status=400)
                        return

                    if purch_amt > 0 and avg_price <= 0:
                        avg_price = purch_amt / qty
                    elif avg_price > 0 and purch_amt <= 0:
                        purch_amt = qty * avg_price

                    if not purch_date:
                        existing = next((i for i in ria["items"] if i.get("symbol", "").upper() == sym), None)
                        if existing and existing.get("purchaseDate") and abs(to_float(existing.get("averagePurchasePrice")) - avg_price) < 0.01:
                            purch_date = existing.get("purchaseDate")
                        else:
                            purch_date = infer_ria_purchase_date(sym, avg_price)

                    items = [i for i in ria["items"] if i.get("symbol", "").upper() != sym]
                    items.append({
                        "symbol": sym,
                        "name": name,
                        "currency": curr,
                        "quantity": qty,
                        "averagePurchasePrice": avg_price,
                        "purchaseAmount": purch_amt,
                        "purchaseDate": purch_date,
                    })
                    ria["items"] = items
                    save_ria_holdings(ria)
                    self._send_json({"ok": True, "ria": ria})
                    return

                if action == "delete_item":
                    sym = (body.get("symbol") or "").strip().upper()
                    ria["items"] = [i for i in ria["items"] if i.get("symbol", "").upper() != sym]
                    save_ria_holdings(ria)
                    self._send_json({"ok": True, "ria": ria})
                    return

                if action == "upsert_sale":
                    sym = (body.get("symbol") or "").strip().upper()
                    qty = to_float(body.get("quantity"), 0.0)
                    if not sym or qty <= 0:
                        self._send_json({"error": "종목코드와 매도수량(0보다 큰 값)을 입력해 주세요."}, status=400)
                        return
                    s_info = toss_client.resolve_stock_info_map([sym]).get(sym, {})
                    curr = (body.get("currency") or s_info.get("currency") or ("KRW" if is_kr_symbol(sym) else "USD")).upper()
                    name = (body.get("name") or "").strip() or s_info.get("name") or sym
                    sell_krw = to_float(body.get("sellAmountKrw"), 0.0)
                    buy_krw = to_float(body.get("purchaseAmountKrw"), 0.0)
                    comm = to_float(body.get("commissionKrw"), 0.0)
                    tax = to_float(body.get("taxKrw"), 0.0)
                    sell_usd = to_float(body.get("sellAmountUsd"), 0.0)
                    buy_usd = to_float(body.get("purchaseAmountUsd"), 0.0)
                    sale_id = (body.get("id") or "").strip() or f"ria_sale_{sym.lower()}_{int(time.time() * 1000)}"
                    sale = {
                        "id": sale_id,
                        "symbol": sym,
                        "name": name,
                        "currency": curr,
                        "soldAt": (body.get("soldAt") or "").strip(),
                        "quantity": qty,
                        "sellPriceUsd": (sell_usd / qty) if sell_usd > 0 else 0.0,
                        "sellPriceKrw": sell_krw / qty,
                        "buyPriceKrw": buy_krw / qty,
                        "sellAmountUsd": sell_usd,
                        "sellAmountKrw": sell_krw,
                        "purchaseAmountKrw": buy_krw,
                        "purchaseAmountUsd": buy_usd,
                        "commissionKrw": comm,
                        "taxKrw": tax,
                        "grossProfitKrw": sell_krw - buy_krw,
                        "finalProfitKrw": sell_krw - buy_krw - comm - tax,
                    }
                    sales = [x for x in (ria.get("sales") or []) if x.get("id") != sale_id]
                    sales.append(sale)
                    sales.sort(key=lambda x: x.get("soldAt") or "")
                    ria["sales"] = sales
                    save_ria_holdings(ria)
                    self._send_json({"ok": True, "ria": ria})
                    return

                if action == "delete_sale":
                    sale_id = (body.get("id") or "").strip()
                    ria["sales"] = [x for x in (ria.get("sales") or []) if x.get("id") != sale_id]
                    save_ria_holdings(ria)
                    self._send_json({"ok": True, "ria": ria})
                    return

                if action == "update_cash":
                    ria["cashKrw"] = to_float(body.get("cashKrw"), 0.0)
                    ria["cashUsd"] = to_float(body.get("cashUsd"), 0.0)
                    save_ria_holdings(ria)
                    self._send_json({"ok": True, "ria": ria})
                    return

            if path == "/api/capital":
                ledger = load_capital_ledger()
                action = body.get("action", "add_transaction")
                if action == "add_transaction":
                    tx = {
                        "id": "tx_" + str(int(time.time() * 1000)),
                        "date": (body.get("date") or time.strftime("%Y-%m-%d")).strip(),
                        "type": (body.get("type") or "DEPOSIT").strip().upper(),
                        "account": (body.get("account") or "기타").strip(),
                        "amount": to_float(body.get("amount"), 0.0),
                        "memo": (body.get("memo") or "").strip(),
                        "createdAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    if tx["amount"] <= 0:
                        self._send_json({"error": "금액은 0보다 커야 합니다."}, status=400)
                        return
                    ledger.setdefault("manualTransactions", []).insert(0, tx)
                    save_capital_ledger(ledger)
                    self._send_json({"ok": True, "transaction": tx, "summary": get_capital_summary()})
                    return
                elif action == "delete_transaction":
                    tx_id = (body.get("id") or "").strip()
                    ledger["manualTransactions"] = [
                        t for t in ledger.get("manualTransactions", []) if t.get("id") != tx_id
                    ]
                    save_capital_ledger(ledger)
                    self._send_json({"ok": True, "summary": get_capital_summary()})
                    return
                elif action == "update_base":
                    base_key = body.get("key")
                    if base_key and "baseSummary" in ledger and base_key in ledger["baseSummary"]:
                        item = ledger["baseSummary"][base_key]
                        if "net" in body:
                            item["net"] = to_float(body["net"])
                        if "deposit" in body:
                            item["deposit"] = to_float(body["deposit"])
                        if "withdraw" in body:
                            item["withdraw"] = to_float(body["withdraw"])
                        if "note" in body:
                            item["note"] = str(body["note"])
                        save_capital_ledger(ledger)
                    self._send_json({"ok": True, "summary": get_capital_summary()})
                    return

            self._send_json({"error": "Not found"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)


def main():
    env = load_env()
    port = int(env.get("PORT", os.environ.get("PORT", 8080)))
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=toss_client.ensure_universe_loaded, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", port), AppHandler)
    print(f"Toss Invest Portfolio Server running at http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
