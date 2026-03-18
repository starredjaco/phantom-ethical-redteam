"""Token-bucket rate limiter for HTTP calls."""

import time
import threading


class RateLimiter:
    def __init__(self, requests_per_second: float = 5.0):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.max_tokens = requests_per_second
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def wait(self):
        """Block until a token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.05)


limiter = RateLimiter()
