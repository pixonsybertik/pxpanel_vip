# speed_limit.py — soft elastic rate limit (Railway-safe)
# Never freezes the tunnel long enough for edge/client timeout (= false "ban").
#
# Design:
#  • Large burst so page loads / pings stay fast
#  • Per-wait capped (≤40ms) — connection stays alive
#  • Elastic overflow after ~200ms wait on one chunk — prefer speed over hard cap
#  • Grace for first bytes of a flow (handshake / DNS / TLS feel)
#  • No limit when speed_limit_bytes == 0

from __future__ import annotations

import asyncio
import time
from main import LINKS

_buckets: dict[str, "_Bucket"] = {}

# Floor only when user actually set a limit (avoid accidental crawl)
MIN_RATE = 32 * 1024          # 32 KB/s minimum enforced rate
MIN_BURST = 256 * 1024        # 256 KB burst
MAX_SLEEP = 0.04              # 40ms max sleep per step
MAX_WAIT_PER_CHUNK = 0.20     # after 200ms waiting, allow rest (elastic)
GRACE_BYTES = 512 * 1024      # first 512KB per uuid window lightly shaped


class _Bucket:
    __slots__ = ("rate", "capacity", "tokens", "last", "grace_left")

    def __init__(self, rate_bytes_per_sec: float):
        self.rate = max(float(rate_bytes_per_sec), float(MIN_RATE))
        # ~2.5s burst window — interactive traffic won't feel capped
        self.capacity = max(self.rate * 2.5, float(MIN_BURST))
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.grace_left = GRACE_BYTES

    def reconfigure(self, rate_bytes_per_sec: float) -> None:
        new_rate = max(float(rate_bytes_per_sec), float(MIN_RATE))
        if abs(new_rate - self.rate) < 1:
            return
        ratio = new_rate / self.rate if self.rate > 0 else 1.0
        self.rate = new_rate
        self.capacity = max(self.rate * 2.5, float(MIN_BURST))
        self.tokens = min(self.capacity, max(0.0, self.tokens * ratio))

    def _refill(self) -> None:
        now = time.monotonic()
        dt = now - self.last
        if dt <= 0:
            return
        self.last = now
        self.tokens = min(self.capacity, self.tokens + dt * self.rate)

    async def consume(self, n: int) -> None:
        if n <= 0:
            return

        # Grace: only charge 25% of tokens for early traffic (handshake soft)
        charge = n
        if self.grace_left > 0:
            g = min(self.grace_left, n)
            self.grace_left -= g
            # remaining part fully charged
            charge = (n - g) + int(g * 0.25)
            if charge <= 0:
                return

        waited = 0.0
        left = charge
        while left > 0:
            self._refill()
            take = min(left, self.tokens)
            if take > 0:
                self.tokens -= take
                left -= take
                if left <= 0:
                    return

            # Not enough tokens — short sleep, never long block
            if waited >= MAX_WAIT_PER_CHUNK:
                # Elastic: release remaining to protect tunnel stability
                return

            need = left - self.tokens
            wait = min(MAX_SLEEP, max(need / self.rate, 0.004))
            await asyncio.sleep(wait)
            waited += wait


def _rate_for(uuid: str) -> int:
    link = LINKS.get(uuid)
    if not link:
        return 0
    return int(link.get("speed_limit_bytes") or 0)


def _get_bucket(uuid: str, rate: int) -> _Bucket:
    b = _buckets.get(uuid)
    if b is None:
        b = _Bucket(rate)
        _buckets[uuid] = b
    else:
        b.reconfigure(rate)
    return b


async def throttle(uuid: str, nbytes: int) -> None:
    """Apply soft speed limit. No-op when unlimited."""
    if nbytes <= 0:
        return
    rate = _rate_for(uuid)
    if rate <= 0:
        return
    await _get_bucket(uuid, rate).consume(nbytes)


def reset_bucket(uuid: str) -> None:
    _buckets.pop(uuid, None)
