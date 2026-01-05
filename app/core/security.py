import secrets

from fastapi import Header, HTTPException, Request

from app.core.config import PACT_API_KEY


def is_api_key_required() -> bool:
    return bool(PACT_API_KEY)


def is_valid_api_key(provided: str | None) -> bool:
    if not PACT_API_KEY:
        return True
    if not provided:
        return False
    return secrets.compare_digest(provided, PACT_API_KEY)


def get_request_api_key(request: Request, x_api_key: str | None) -> str | None:
    """
    Extract API key from common locations:
    - Header: X-API-Key
    - Header: Authorization: Bearer <key>
    - Query param: api_key (or key)
    - Cookie: pact_api_key
    """
    if x_api_key:
        return x_api_key

    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None

    qp = request.query_params.get("api_key") or request.query_params.get("key")
    if qp:
        return qp

    ck = request.cookies.get("pact_api_key")
    if ck:
        return ck

    return None


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """
    Optional API-key auth.

    If `PACT_API_KEY` env var is set, require header:
        X-API-Key: <PACT_API_KEY>
    Otherwise, allow requests (local-dev friendly).
    """
    if not PACT_API_KEY:
        return

    provided = get_request_api_key(request, x_api_key)
    if not is_valid_api_key(provided):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


