"""
Simple in-memory rate limiter middleware.
Rejects requests exceeding max_requests per window_seconds per client IP.
"""
import time
from collections import defaultdict

from fastapi import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.api.security.config import is_rate_limit_disabled


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding-window rate limiter."""

    def __init__(
        self,
        app,
        max_requests: int = 100,
        window_seconds: int = 60,
        enabled: bool = True,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.enabled = enabled
        self._requests: dict = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        if not self.enabled or is_rate_limit_disabled():
            return await call_next(request)

        client_ip = request.client.host if request.client else "0.0.0.0"
        now = time.time()
        window_start = now - self.window_seconds

        self._requests[client_ip] = [
            stamp for stamp in self._requests[client_ip] if stamp > window_start
        ]

        if len(self._requests[client_ip]) >= self.max_requests:
            return Response(
                content='{"detail": "Rate limit exceeded. Try again later."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(self.window_seconds)},
            )

        self._requests[client_ip].append(now)
        return await call_next(request)
