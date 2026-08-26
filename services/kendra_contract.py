"""Public Hazel/Kendra commercial contract shared by desktop and gateway."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from urllib.parse import urlparse

from services.hazel_config import get_config


KENDRA_PRODUCTION_BASE_URL = "https://pay.atsfriendlyresume.pro"
HAZEL_TOKEN_VALUE_USD = 1
HAZEL_MINIMUM_PURCHASE_TOKENS = 30
HAZEL_MINIMUM_PURCHASE_USD = 30
DEFAULT_PACKAGE_CODE = "hazel_30_usd"
DEFAULT_PACKAGE_CURRENCY = "USD"
DEFAULT_DAILY_SERVICE_CODE = "HAZEL_DAILY_ACCESS"


def _decimal(value: object, default: str = "0") -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(default)


def converted_kes_amount(price_usd: object, usd_to_kes_rate: object) -> int:
    """Return the configured USD list price as a whole-KES package amount."""
    price = _decimal(price_usd)
    rate = _decimal(usd_to_kes_rate)
    if price <= 0 or rate <= 0:
        return 0
    return int((price * rate).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _config_float(name: str, default: str) -> float:
    try:
        return float(get_config(name, default) or 0)
    except (TypeError, ValueError):
        return 0.0


def kendra_api_base_url_error(base_url: str, *, allow_insecure_local: bool = False) -> str:
    """Return a configuration error before a merchant key can leave the gateway."""
    value = str(base_url or "").strip().rstrip("/")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return "KENDRA_BASE_URL is malformed"

    production = urlparse(KENDRA_PRODUCTION_BASE_URL)
    is_production = (
        parsed.scheme == "https"
        and parsed.hostname == production.hostname
        and port in (None, 443)
        and parsed.path in ("", "/")
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )
    is_local_test = (
        allow_insecure_local
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
    )
    if is_production or is_local_test:
        return ""
    return f"KENDRA_BASE_URL must be exactly {KENDRA_PRODUCTION_BASE_URL} in production"


def desktop_payment_config() -> dict:
    currency = get_config("KENDRA_PACKAGE_CURRENCY", DEFAULT_PACKAGE_CURRENCY).upper()
    price_usd = _config_float(
        "KENDRA_PACKAGE_PRICE_USD",
        str(HAZEL_MINIMUM_PURCHASE_USD),
    )
    usd_to_kes_rate = _config_float("KENDRA_USD_TO_KES_RATE", "0")
    configured_amount = get_config("KENDRA_PACKAGE_PRICE_AMOUNT", "")
    if configured_amount:
        price_amount = _config_float("KENDRA_PACKAGE_PRICE_AMOUNT", "0")
    elif currency == "KES":
        price_amount = float(converted_kes_amount(price_usd, usd_to_kes_rate))
    else:
        price_amount = price_usd
    return {
        "gateway_url": get_config("KENDRA_GATEWAY_URL", "").rstrip("/"),
        "payment_provider": get_config("KENDRA_PAYMENT_PROVIDER", "HOSTED").upper(),
        "package_code": get_config("KENDRA_PACKAGE_CODE", DEFAULT_PACKAGE_CODE),
        "daily_service_code": get_config(
            "KENDRA_DAILY_SERVICE_CODE",
            DEFAULT_DAILY_SERVICE_CODE,
        ),
        "tokens": int(get_config(
            "KENDRA_PACKAGE_TOKENS",
            str(HAZEL_MINIMUM_PURCHASE_TOKENS),
        )),
        "price_usd": price_usd,
        "currency": currency,
        "price_amount": price_amount,
        "usd_to_kes_rate": usd_to_kes_rate,
    }


def validate_desktop_payment_config(config: dict, require_production: bool = False) -> list[str]:
    """Validate public settings and reject merchant secrets in desktop assets."""
    errors = []
    for key, value in (config or {}).items():
        upper_key = str(key).upper()
        text = str(value or "").strip()
        if upper_key in {"KENDRA_MERCHANT_API_KEY", "KENDRA_API_KEY"}:
            errors.append(f"{key} is a server secret and cannot be packaged")
        if text.startswith("tpp_live_"):
            errors.append(f"{key} contains a Kendra merchant secret")

    gateway_url = str(config.get("KENDRA_GATEWAY_URL") or "").strip().rstrip("/")
    parsed = urlparse(gateway_url)
    kendra_api_host = urlparse(KENDRA_PRODUCTION_BASE_URL).hostname
    if parsed.hostname == kendra_api_host:
        errors.append(
            "KENDRA_GATEWAY_URL must identify the secret-holding Hazel gateway, "
            "not the Kendra merchant API"
        )
    if require_production:
        if not gateway_url or "your-" in gateway_url or ".example" in gateway_url:
            errors.append("KENDRA_GATEWAY_URL must identify the deployed Hazel merchant gateway")
        elif parsed.scheme != "https" or not parsed.netloc:
            errors.append("KENDRA_GATEWAY_URL must be an HTTPS URL")

    package_code = str(config.get("KENDRA_PACKAGE_CODE") or "").strip()
    service_code = str(config.get("KENDRA_DAILY_SERVICE_CODE") or "").strip()
    payment_provider = str(config.get("KENDRA_PAYMENT_PROVIDER") or "HOSTED").strip().upper()
    if require_production and not package_code:
        errors.append("KENDRA_PACKAGE_CODE is required")
    if require_production and not service_code:
        errors.append("KENDRA_DAILY_SERVICE_CODE is required")
    try:
        tokens = int(config.get("KENDRA_PACKAGE_TOKENS"))
    except (TypeError, ValueError):
        tokens = 0
    try:
        price_usd = float(config.get("KENDRA_PACKAGE_PRICE_USD"))
    except (TypeError, ValueError):
        price_usd = 0.0
    currency = str(config.get("KENDRA_PACKAGE_CURRENCY") or DEFAULT_PACKAGE_CURRENCY).upper()
    try:
        price_amount = float(
            config.get("KENDRA_PACKAGE_PRICE_AMOUNT")
            if config.get("KENDRA_PACKAGE_PRICE_AMOUNT") is not None
            else price_usd
        )
    except (TypeError, ValueError):
        price_amount = 0.0
    try:
        usd_to_kes_rate = float(config.get("KENDRA_USD_TO_KES_RATE") or 0)
    except (TypeError, ValueError):
        usd_to_kes_rate = 0.0
    if tokens != HAZEL_MINIMUM_PURCHASE_TOKENS:
        errors.append("Hazel production package must contain exactly 30 tokens")
    if abs(price_usd - HAZEL_MINIMUM_PURCHASE_USD) > 1e-9:
        errors.append("Hazel commercial package price must be exactly USD 30")
    if currency not in {"USD", "KES"}:
        errors.append("KENDRA_PACKAGE_CURRENCY must be USD or KES")
    elif currency == "USD":
        if abs(price_amount - HAZEL_MINIMUM_PURCHASE_USD) > 1e-9:
            errors.append("The USD Kendra package price must be exactly USD 30")
    else:
        expected_kes = converted_kes_amount(price_usd, usd_to_kes_rate)
        if usd_to_kes_rate <= 0:
            errors.append("KENDRA_USD_TO_KES_RATE must be positive for an M-Pesa KES package")
        if price_amount <= 0 or not float(price_amount).is_integer():
            errors.append("The M-Pesa Kendra package must use a positive whole-KES price")
        if expected_kes and abs(price_amount - expected_kes) > 1e-9:
            errors.append(
                "KENDRA_PACKAGE_PRICE_AMOUNT must equal the rounded USD 30 conversion "
                f"({expected_kes} KES at rate {usd_to_kes_rate:g})"
            )
    if payment_provider not in {"HOSTED", "MPESA"}:
        errors.append("KENDRA_PAYMENT_PROVIDER must be HOSTED or MPESA")
    if payment_provider == "MPESA" and currency != "KES":
        errors.append("M-Pesa payments require KENDRA_PACKAGE_CURRENCY=KES")
    return errors
