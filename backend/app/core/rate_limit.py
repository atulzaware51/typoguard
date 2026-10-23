"""Small per-process fixed-window rate limiter for the public scan route."""

from math import ceil
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request


SCAN_REQUESTS_PER_WINDOW = 30
SCAN_RATE_WINDOW_SECONDS = 60


class FixedWindowRateLimiter:
    """Track request windows by client address with bounded in-memory state."""

    def __init__(
        self,
        limit: int = SCAN_REQUESTS_PER_WINDOW,
        window_seconds: int = SCAN_RATE_WINDOW_SECONDS,
        max_clients: int = 10_000,
    ) -> None:
        if limit < 1 or window_seconds < 1 or max_clients < 1:
            raise ValueError("Rate-limit settings must be positive.")
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = Lock()

    def retry_after(self, client_key: str, now: float | None = None) -> int | None:
        """Consume one request or return whole seconds until the window resets."""
        current = monotonic() if now is None else now
        with self._lock:
            state = self._windows.get(client_key)
            if state is None or current - state[0] >= self.window_seconds:
                self._windows[client_key] = (current, 1)
                self._prune(current)
                return None

            start, count = state
            if count >= self.limit:
                return max(1, ceil(self.window_seconds - (current - start)))

            self._windows[client_key] = (start, count + 1)
            return None

    def _prune(self, now: float) -> None:
        if len(self._windows) <= self.max_clients:
            return
        oldest_valid = now - self.window_seconds
        self._windows = {
            key: state
            for key, state in self._windows.items()
            if state[0] > oldest_valid
        }
        if len(self._windows) > self.max_clients:
            oldest = sorted(self._windows, key=lambda key: self._windows[key][0])
            for key in oldest[: len(self._windows) - self.max_clients]:
                del self._windows[key]


scan_rate_limiter = FixedWindowRateLimiter()


def enforce_scan_rate_limit(request: Request) -> None:
    client_key = request.client.host if request.client else "unknown"
    retry_after = scan_rate_limiter.retry_after(client_key)
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Scan request limit exceeded. Try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )
