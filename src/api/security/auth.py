"""
API key authentication and role-based authorization.

Unauthenticated request  -> 401
Authenticated, wrong role -> 403
"""
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from src.api.security.config import get_admin_api_key, get_api_key

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class Role:
    ANALYST = "analyst"
    ADMIN = "admin"


def authenticate(api_key: str | None = Security(api_key_header)) -> str:
    """Validate X-API-Key and return the caller's role."""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    admin_key = get_admin_api_key()
    analyst_key = get_api_key()

    if api_key == admin_key:
        return Role.ADMIN
    if api_key == analyst_key:
        return Role.ANALYST

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_authenticated(role: str = Depends(authenticate)) -> str:
    """Any valid API key (analyst or admin)."""
    return role


def require_admin(role: str = Depends(authenticate)) -> str:
    """Admin key required for state-changing operations."""
    if role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return role


def require_api_key(api_key: str | None = Security(api_key_header)) -> str:
    """Backward-compatible alias for authenticate()."""
    return authenticate(api_key)
