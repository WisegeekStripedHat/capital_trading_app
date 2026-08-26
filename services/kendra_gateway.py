"""Secret-holding Hazel merchant gateway for Kendra Service Pay.

Deploy this module on a server. It must never be bundled into the desktop app.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from services.hazel_config import get_config
from services.kendra_contract import (
    DEFAULT_DAILY_SERVICE_CODE,
    DEFAULT_PACKAGE_CODE,
    DEFAULT_PACKAGE_CURRENCY,
    HAZEL_MINIMUM_PURCHASE_TOKENS,
    HAZEL_MINIMUM_PURCHASE_USD,
    KENDRA_PRODUCTION_BASE_URL,
    converted_kes_amount,
    kendra_api_base_url_error,
)


app = FastAPI(title="Hazel Kendra Merchant Gateway", docs_url=None, redoc_url=None)
logger = logging.getLogger(__name__)


def _config_float(name: str, default: str) -> float:
    try:
        return float(get_config(name, default) or 0)
    except (TypeError, ValueError):
        return -1.0


KENDRA_BASE_URL = get_config("KENDRA_BASE_URL", KENDRA_PRODUCTION_BASE_URL).rstrip("/")
KENDRA_MERCHANT_API_KEY = os.getenv("KENDRA_MERCHANT_API_KEY", "").strip()
KENDRA_PACKAGE_CODE = get_config("KENDRA_PACKAGE_CODE", DEFAULT_PACKAGE_CODE).strip()
KENDRA_PAYMENT_PROVIDER = get_config("KENDRA_PAYMENT_PROVIDER", "HOSTED").strip().upper()
KENDRA_PACKAGE_CURRENCY = get_config(
    "KENDRA_PACKAGE_CURRENCY",
    DEFAULT_PACKAGE_CURRENCY,
).strip().upper()
KENDRA_PACKAGE_PRICE_USD = _config_float(
    "KENDRA_PACKAGE_PRICE_USD",
    str(HAZEL_MINIMUM_PURCHASE_USD),
)
KENDRA_USD_TO_KES_RATE = _config_float("KENDRA_USD_TO_KES_RATE", "0")
KENDRA_PACKAGE_PRICE_AMOUNT = _config_float(
    "KENDRA_PACKAGE_PRICE_AMOUNT",
    str(
        converted_kes_amount(KENDRA_PACKAGE_PRICE_USD, KENDRA_USD_TO_KES_RATE)
        if KENDRA_PACKAGE_CURRENCY == "KES"
        else KENDRA_PACKAGE_PRICE_USD
    ),
)
KENDRA_DAILY_SERVICE_CODE = get_config(
    "KENDRA_DAILY_SERVICE_CODE",
    DEFAULT_DAILY_SERVICE_CODE,
).strip()
DEVICE_PEPPER = os.getenv("HAZEL_GATEWAY_DEVICE_PEPPER", "").strip()
DB_PATH = Path(os.getenv("HAZEL_GATEWAY_DB", "data/hazel_kendra_gateway.sqlite3"))
CONTRACT_CACHE_SECONDS = 300
_contract_cache = {"checked_at": 0.0, "result": None}
RETRYABLE_LEDGER_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class CheckoutRequest(BaseModel):
    device_id: str
    device_secret: str
    email: str
    package_code: str | None = None


class DeviceRequest(BaseModel):
    device_id: str
    device_secret: str


class CheckoutStatusRequest(DeviceRequest):
    request_id: str


def _require_server_config() -> None:
    missing = []
    if not KENDRA_MERCHANT_API_KEY.startswith("tpp_live_"):
        missing.append("KENDRA_MERCHANT_API_KEY")
    if len(DEVICE_PEPPER) < 32:
        missing.append("HAZEL_GATEWAY_DEVICE_PEPPER (at least 32 characters)")
    if not KENDRA_PACKAGE_CODE:
        missing.append("KENDRA_PACKAGE_CODE")
    if KENDRA_PAYMENT_PROVIDER not in {"HOSTED", "MPESA"}:
        missing.append("KENDRA_PAYMENT_PROVIDER (HOSTED or MPESA)")
    if KENDRA_PACKAGE_CURRENCY not in {"USD", "KES"}:
        missing.append("KENDRA_PACKAGE_CURRENCY (USD or KES)")
    if KENDRA_PACKAGE_PRICE_USD != HAZEL_MINIMUM_PURCHASE_USD:
        missing.append("KENDRA_PACKAGE_PRICE_USD (exactly 30)")
    if KENDRA_PACKAGE_PRICE_AMOUNT <= 0:
        missing.append("KENDRA_PACKAGE_PRICE_AMOUNT (positive)")
    if KENDRA_PACKAGE_CURRENCY == "KES":
        converted_amount = converted_kes_amount(
            KENDRA_PACKAGE_PRICE_USD,
            KENDRA_USD_TO_KES_RATE,
        )
        if KENDRA_USD_TO_KES_RATE <= 0:
            missing.append("KENDRA_USD_TO_KES_RATE (positive for KES)")
        if not KENDRA_PACKAGE_PRICE_AMOUNT.is_integer():
            missing.append("KENDRA_PACKAGE_PRICE_AMOUNT (whole KES)")
        if converted_amount and KENDRA_PACKAGE_PRICE_AMOUNT != converted_amount:
            missing.append(
                "KENDRA_PACKAGE_PRICE_AMOUNT "
                f"({converted_amount} KES at the configured conversion rate)"
            )
    if KENDRA_PAYMENT_PROVIDER == "MPESA" and KENDRA_PACKAGE_CURRENCY != "KES":
        missing.append("KENDRA_PACKAGE_CURRENCY=KES for M-Pesa")
    if not KENDRA_DAILY_SERVICE_CODE:
        missing.append("KENDRA_DAILY_SERVICE_CODE")
    base_url_error = kendra_api_base_url_error(
        KENDRA_BASE_URL,
        allow_insecure_local=os.getenv("KENDRA_ALLOW_INSECURE_LOCAL", "0") == "1",
    )
    if base_url_error:
        missing.append(base_url_error)
    if missing:
        raise RuntimeError("Missing or invalid server configuration: " + ", ".join(missing))


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_hash TEXT PRIMARY KEY,
            secret_hash TEXT NOT NULL,
            external_user_id TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            access_start_date TEXT,
            last_consumed_date TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS checkout_requests (
            request_id TEXT PRIMARY KEY,
            device_hash TEXT NOT NULL,
            starting_balance INTEGER NOT NULL,
            checkout_expires_at TEXT,
            credited_at INTEGER,
            verified_balance INTEGER,
            verification_mode TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(device_hash) REFERENCES devices(device_hash)
        );
        """
    )
    device_columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    checkout_columns = {row[1] for row in conn.execute("PRAGMA table_info(checkout_requests)")}
    if "access_start_date" not in device_columns:
        conn.execute("ALTER TABLE devices ADD COLUMN access_start_date TEXT")
    if "last_consumed_date" not in device_columns:
        conn.execute("ALTER TABLE devices ADD COLUMN last_consumed_date TEXT")
    if "credited_at" not in checkout_columns:
        conn.execute("ALTER TABLE checkout_requests ADD COLUMN credited_at INTEGER")
    if "verified_balance" not in checkout_columns:
        conn.execute("ALTER TABLE checkout_requests ADD COLUMN verified_balance INTEGER")
    if "verification_mode" not in checkout_columns:
        conn.execute("ALTER TABLE checkout_requests ADD COLUMN verification_mode TEXT")
    return conn


def _digest(value: str) -> str:
    return hmac.new(DEVICE_PEPPER.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _device_values(device_id: str, device_secret: str) -> tuple[str, str, str]:
    device_id = str(device_id or "").strip()
    device_secret = str(device_secret or "").strip()
    if len(device_id) < 32 or len(device_secret) < 32:
        raise HTTPException(status_code=400, detail="Invalid Hazel installation credential.")
    device_hash = _digest(f"device:{device_id}")
    secret_hash = _digest(f"secret:{device_secret}")
    external_user_id = f"hazel-{device_hash[:40]}"
    return device_hash, secret_hash, external_user_id


def _normalize_email(value: str) -> str:
    email = str(value or "").strip().lower()
    if len(email) > 254 or email.count("@") != 1 or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid billing email address.")
    return email


def _authenticate_device(request: DeviceRequest, *, register_email: str = "") -> sqlite3.Row:
    device_hash, secret_hash, external_user_id = _device_values(
        request.device_id,
        request.device_secret,
    )
    now = int(time.time())
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_hash = ?",
            (device_hash,),
        ).fetchone()
        if row:
            if not hmac.compare_digest(str(row["secret_hash"]), secret_hash):
                raise HTTPException(status_code=403, detail="This installation is not authorized for the wallet.")
            if register_email:
                conn.execute(
                    "UPDATE devices SET email = ?, updated_at = ? WHERE device_hash = ?",
                    (_normalize_email(register_email), now, device_hash),
                )
                row = conn.execute(
                    "SELECT * FROM devices WHERE device_hash = ?",
                    (device_hash,),
                ).fetchone()
            return row
        if not register_email:
            raise HTTPException(status_code=404, detail="Open Kendra Pay checkout to register this installation.")
        conn.execute(
            """
            INSERT INTO devices (
                device_hash, secret_hash, external_user_id, email, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                device_hash,
                secret_hash,
                external_user_id,
                _normalize_email(register_email),
                now,
                now,
            ),
        )
        return conn.execute(
            "SELECT * FROM devices WHERE device_hash = ?",
            (device_hash,),
        ).fetchone()


def _kendra_error_detail(status_code: int, body: str, path: str) -> str:
    detail = None
    try:
        payload = json.loads(body or "{}")
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("message") or payload.get("error")
    except (TypeError, ValueError):
        pass
    if isinstance(detail, list):
        messages = []
        for item in detail:
            if isinstance(item, dict):
                messages.append(str(item.get("msg") or item.get("message") or item))
            else:
                messages.append(str(item))
        detail = "; ".join(messages)
    elif isinstance(detail, dict):
        detail = str(detail.get("message") or detail.get("reason") or detail)

    prefix = {
        400: "Kendra rejected the package or checkout data",
        401: "Kendra rejected the merchant API key; configure an active tpp_live_* key on the gateway",
        403: "Kendra denied this merchant operation",
        404: "Kendra could not find the requested route or resource",
        409: "Kendra reported a payment or wallet conflict",
        422: "Kendra could not validate the merchant request",
        429: "Kendra rate-limited the merchant gateway",
        503: "Kendra is temporarily unavailable",
    }.get(status_code, "Kendra rejected the merchant request")
    safe_detail = str(detail or "").strip()
    return f"{prefix}: {safe_detail}" if safe_detail else f"{prefix} (HTTP {status_code}, {path})."


def _kendra_request(method: str, path: str, payload: dict | None = None) -> object:
    _require_server_config()
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    retryable = method == "GET" or path == "/v1/wallets/spend"
    attempts = 3 if retryable else 1
    for attempt in range(attempts):
        request = urllib.request.Request(
            f"{KENDRA_BASE_URL}{path}",
            data=data,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {KENDRA_MERCHANT_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "Hazel-Kendra-Gateway/1",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")
            if retryable and err.code in {429, 500, 502, 503} and attempt + 1 < attempts:
                time.sleep(0.5 * (2 ** attempt))
                continue
            status = err.code if err.code in {400, 401, 403, 404, 409, 422, 429, 503} else 502
            detail = _kendra_error_detail(err.code, body, path)
            logger.warning("Kendra API request failed: method=%s path=%s status=%s", method, path, err.code)
            raise HTTPException(status_code=status, detail=detail) from err
        except (urllib.error.URLError, TimeoutError, ValueError) as err:
            if retryable and attempt + 1 < attempts:
                time.sleep(0.5 * (2 ** attempt))
                continue
            raise HTTPException(status_code=503, detail=f"Kendra is temporarily unavailable: {err}") from err
    raise HTTPException(status_code=503, detail="Kendra is temporarily unavailable.")


def _wallet_balance(external_user_id: str) -> int:
    query = urllib.parse.urlencode({"external_user_id": external_user_id})
    response = _kendra_request("GET", f"/v1/wallets/balance?{query}")
    return int((response or {}).get("balance") or 0)


def _transactions(external_user_id: str) -> list[dict]:
    query = urllib.parse.urlencode({"external_user_id": external_user_id})
    response = _kendra_request("GET", f"/v1/wallets/transactions?{query}")
    return list((response or {}).get("transactions") or [])


def _parse_timestamp(value: object) -> int:
    try:
        text = str(value or "").replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.astimezone(timezone.utc).timestamp())
    except (TypeError, ValueError):
        return 0


def _qualifying_purchase(transactions: list[dict], created_at: int) -> dict | None:
    return next(
        (
            item
            for item in transactions
            if str(item.get("type") or "").upper() == "PURCHASE"
            and int(item.get("token_amount") or 0) >= HAZEL_MINIMUM_PURCHASE_TOKENS
            and _parse_timestamp(item.get("created_at")) >= int(created_at)
        ),
        None,
    )


def _verify_checkout_credit(
    external_user_id: str,
    *,
    starting_balance: int,
    created_at: int,
) -> dict:
    """Verify new wallet credit, using the ledger as audit evidence when available."""
    current_balance = _wallet_balance(external_user_id)
    required_balance = int(starting_balance) + HAZEL_MINIMUM_PURCHASE_TOKENS
    result = {
        "credited": False,
        "current_balance": current_balance,
        "required_balance": required_balance,
        "verification_mode": "wallet-balance-pending",
        "verification_warning": "",
    }
    if current_balance < required_balance:
        return result

    try:
        purchase = _qualifying_purchase(_transactions(external_user_id), created_at)
    except HTTPException as err:
        if err.status_code not in RETRYABLE_LEDGER_STATUS_CODES:
            raise
        logger.warning(
            "Kendra transaction ledger unavailable after wallet credit for %s; "
            "accepting authoritative wallet balance delta: %s",
            external_user_id,
            err.detail,
        )
        result.update(
            {
                "credited": True,
                "verification_mode": "wallet-balance-fallback",
                "verification_warning": "Transaction audit is temporarily unavailable; wallet credit was verified.",
            }
        )
        return result

    if purchase:
        result.update(
            {
                "credited": True,
                "verification_mode": "transaction-ledger",
                "transaction_id": str(purchase.get("id") or ""),
            }
        )
        return result

    # The wallet balance is Kendra-owned and was sampled immediately before checkout.
    # Its 30-token increase is sufficient entitlement evidence while the ledger catches up.
    logger.warning(
        "Kendra wallet credit is visible for %s but its purchase transaction is not yet listed; "
        "accepting authoritative wallet balance delta.",
        external_user_id,
    )
    result.update(
        {
            "credited": True,
            "verification_mode": "wallet-balance",
            "verification_warning": "Wallet credit was verified; the transaction audit is still synchronizing.",
        }
    )
    return result


def validate_kendra_contract(force: bool = False) -> dict:
    now = time.time()
    cached = _contract_cache.get("result")
    if cached and not force and now - float(_contract_cache.get("checked_at") or 0) < CONTRACT_CACHE_SECONDS:
        return cached
    packages = _kendra_request("GET", "/v1/pricing/packages")
    services = _kendra_request("GET", "/v1/pricing/services")
    package = next(
        (item for item in packages if item.get("code") == KENDRA_PACKAGE_CODE and item.get("is_active")),
        None,
    )
    service = next(
        (
            item
            for item in services
            if item.get("service_code") == KENDRA_DAILY_SERVICE_CODE and item.get("is_active")
        ),
        None,
    )
    errors = []
    if not package:
        errors.append(f"Active package {KENDRA_PACKAGE_CODE!r} was not found")
    else:
        if int(package.get("token_amount") or 0) != HAZEL_MINIMUM_PURCHASE_TOKENS:
            errors.append("Hazel package must contain exactly 30 tokens")
        if int(package.get("bonus_tokens") or 0) != 0:
            errors.append("Hazel package bonus_tokens must be zero")
        if str(package.get("currency") or "").upper() != KENDRA_PACKAGE_CURRENCY:
            errors.append(
                "Hazel package currency must be "
                f"{KENDRA_PACKAGE_CURRENCY} (configured package {KENDRA_PACKAGE_CODE})"
            )
        if abs(float(package.get("price_amount") or 0) - KENDRA_PACKAGE_PRICE_AMOUNT) > 1e-9:
            errors.append(
                "Hazel package price must be exactly "
                f"{KENDRA_PACKAGE_CURRENCY} {KENDRA_PACKAGE_PRICE_AMOUNT:g}"
            )
    if not service:
        errors.append(f"Active service {KENDRA_DAILY_SERVICE_CODE!r} was not found")
    elif int(service.get("token_cost") or 0) != 1:
        errors.append("Hazel daily-access service must cost exactly one token")
    result = {
        "valid": not errors,
        "errors": errors,
        "package_code": KENDRA_PACKAGE_CODE,
        "payment_provider": KENDRA_PAYMENT_PROVIDER,
        "service_code": KENDRA_DAILY_SERVICE_CODE,
        "tokens": HAZEL_MINIMUM_PURCHASE_TOKENS,
        "currency": KENDRA_PACKAGE_CURRENCY,
        "price_amount": KENDRA_PACKAGE_PRICE_AMOUNT,
        "price_usd_reference": KENDRA_PACKAGE_PRICE_USD,
        "usd_to_kes_rate": KENDRA_USD_TO_KES_RATE if KENDRA_PACKAGE_CURRENCY == "KES" else None,
        "daily_token_cost": 1,
    }
    _contract_cache.update({"checked_at": now, "result": result})
    return result


def _require_contract() -> dict:
    result = validate_kendra_contract()
    if not result["valid"]:
        raise HTTPException(status_code=503, detail="Kendra pricing contract is invalid: " + "; ".join(result["errors"]))
    return result


@app.get("/health")
def health() -> dict:
    try:
        _require_server_config()
        return {"status": "ok", "service": "hazel-kendra-gateway"}
    except RuntimeError as err:
        raise HTTPException(status_code=503, detail=str(err)) from err


@app.get("/ready")
def ready() -> dict:
    return {"status": "ready", **_require_contract()}


@app.post("/v1/hazel/checkout-session")
def create_checkout_session(request: CheckoutRequest) -> dict:
    _require_contract()
    if request.package_code and request.package_code != KENDRA_PACKAGE_CODE:
        raise HTTPException(status_code=400, detail="Hazel checkout package does not match the server contract.")
    device = _authenticate_device(request, register_email=request.email)
    starting_balance = _wallet_balance(device["external_user_id"])
    response = _kendra_request(
        "POST",
        "/v1/checkout/sessions",
        {
            "external_user_id": device["external_user_id"],
            "email": device["email"],
            # Kendra owns currency and amount through this pre-approved package.
            "package_code": KENDRA_PACKAGE_CODE,
        },
    )
    checkout_url = str((response or {}).get("checkout_url") or "")
    parsed_checkout = urllib.parse.urlparse(checkout_url)
    parsed_base = urllib.parse.urlparse(KENDRA_BASE_URL)
    valid_checkout_url = (
        parsed_checkout.scheme == parsed_base.scheme
        and parsed_checkout.hostname == parsed_base.hostname
        and parsed_checkout.port == parsed_base.port
        and parsed_checkout.path.rstrip("/") == "/checkout"
        and parsed_checkout.fragment.startswith("token=")
        and not parsed_checkout.username
        and not parsed_checkout.password
    )
    if not valid_checkout_url:
        raise HTTPException(status_code=502, detail="Kendra returned an invalid checkout URL.")
    expires_at = str((response or {}).get("expires_at") or "")
    if _parse_timestamp(expires_at) <= int(time.time()):
        raise HTTPException(status_code=502, detail="Kendra returned an invalid checkout expiry.")
    request_id = secrets.token_urlsafe(24)
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO checkout_requests (
                request_id, device_hash, starting_balance, checkout_expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                request_id,
                device["device_hash"],
                starting_balance,
                expires_at,
                int(time.time()),
            ),
        )
    return {
        "request_id": request_id,
        "checkout_url": checkout_url,
        "expires_at": expires_at,
        "tokens": HAZEL_MINIMUM_PURCHASE_TOKENS,
        "amount": KENDRA_PACKAGE_PRICE_AMOUNT,
        "currency": KENDRA_PACKAGE_CURRENCY,
        "amount_usd_reference": KENDRA_PACKAGE_PRICE_USD,
        "amount_usd": KENDRA_PACKAGE_PRICE_USD,
        "daily_token_cost": 1,
    }


@app.post("/v1/hazel/checkout-status")
def checkout_status(request: CheckoutStatusRequest) -> dict:
    device = _authenticate_device(request)
    with _connect() as conn:
        checkout = conn.execute(
            "SELECT * FROM checkout_requests WHERE request_id = ? AND device_hash = ?",
            (request.request_id, device["device_hash"]),
        ).fetchone()
    if not checkout:
        raise HTTPException(status_code=404, detail="Checkout request was not found for this installation.")
    if checkout["credited_at"]:
        return {
            "ready": True,
            "status": "approved",
            "request_id": request.request_id,
            "tokens_balance": (
                checkout["verified_balance"]
                if checkout["verified_balance"] is not None
                else int(checkout["starting_balance"]) + HAZEL_MINIMUM_PURCHASE_TOKENS
            ),
            "verification_mode": checkout["verification_mode"] or "cached",
            "message": "Payment verification is complete and cached for this installation.",
        }

    evidence = _verify_checkout_credit(
        device["external_user_id"],
        starting_balance=int(checkout["starting_balance"]),
        created_at=int(checkout["created_at"]),
    )
    credited = bool(evidence["credited"])
    if credited:
        today = datetime.now(timezone.utc).date()
        with _connect() as conn:
            conn.execute(
                """
                UPDATE checkout_requests
                SET credited_at = ?, verified_balance = ?, verification_mode = ?
                WHERE request_id = ?
                """,
                (
                    int(time.time()),
                    int(evidence["current_balance"]),
                    evidence["verification_mode"],
                    request.request_id,
                ),
            )
            if int(checkout["starting_balance"]) <= 0:
                conn.execute(
                    """
                    UPDATE devices
                    SET access_start_date = ?, last_consumed_date = ?, updated_at = ?
                    WHERE device_hash = ?
                    """,
                    (
                        today.isoformat(),
                        (today - timedelta(days=1)).isoformat(),
                        int(time.time()),
                        device["device_hash"],
                    ),
                )
    return {
        "ready": credited,
        "status": "approved" if credited else "pending",
        "request_id": request.request_id,
        "tokens_balance": evidence["current_balance"],
        "verification_mode": evidence["verification_mode"],
        "verification_warning": evidence["verification_warning"],
        "retry_after_seconds": 4,
        "message": (
            "Payment verified and wallet credited."
            if credited
            else "Waiting for Kendra to verify the payment and credit 30 tokens."
        ),
    }


@app.post("/v1/hazel/wallet-status")
def wallet_status(request: DeviceRequest) -> dict:
    device = _authenticate_device(request)
    return {
        "tokens_balance": _wallet_balance(device["external_user_id"]),
        "daily_token_cost": 1,
    }


@app.post("/v1/hazel/consume-daily")
def consume_daily(request: DeviceRequest) -> dict:
    _require_contract()
    device = _authenticate_device(request)
    today = datetime.now(timezone.utc).date()
    try:
        last_consumed = date.fromisoformat(str(device["last_consumed_date"] or ""))
    except ValueError:
        last_consumed = today - timedelta(days=1)
    try:
        access_start = date.fromisoformat(str(device["access_start_date"] or ""))
    except ValueError:
        access_start = today
    next_date = max(access_start, last_consumed + timedelta(days=1))
    response = {}
    approved = True
    consumed_dates = []
    while next_date <= today:
        usage_date = next_date.isoformat()
        reference_id = f"hazel-access:{device['device_hash'][:24]}:{usage_date}"
        response = _kendra_request(
            "POST",
            "/v1/wallets/spend",
            {
                "external_user_id": device["external_user_id"],
                "email": device["email"],
                "service_code": KENDRA_DAILY_SERVICE_CODE,
                "reference_id": reference_id,
                "idempotency_key": f"spend:{KENDRA_DAILY_SERVICE_CODE}:{reference_id}",
                "metadata": {"source": "hazel-kendra-gateway", "usage_date_utc": usage_date},
            },
        )
        approved = (response or {}).get("approved") is True
        if not approved:
            break
        consumed_dates.append(usage_date)
        with _connect() as conn:
            conn.execute(
                "UPDATE devices SET last_consumed_date = ?, updated_at = ? WHERE device_hash = ?",
                (usage_date, int(time.time()), device["device_hash"]),
            )
        next_date += timedelta(days=1)
    remaining_balance = int(
        (response or {}).get("remaining_balance")
        if (response or {}).get("remaining_balance") is not None
        else _wallet_balance(device["external_user_id"])
    )
    return {
        "approved": approved,
        "activated": approved,
        "valid": approved,
        "usage_date": today.isoformat(),
        "consumed_today": approved and today.isoformat() in consumed_dates,
        "reconciled_dates": consumed_dates,
        "tokens_spent": len(consumed_dates),
        "tokens_balance": remaining_balance,
        "reason": "" if approved else str((response or {}).get("reason") or "Kendra did not approve daily access."),
        "transaction_id": (response or {}).get("transaction_id"),
    }
