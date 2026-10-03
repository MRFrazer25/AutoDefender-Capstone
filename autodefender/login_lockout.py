"""Sign-in lockout helpers (per-client hard lock, global backoff)."""

from datetime import datetime
from typing import Iterable, List

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
# Across all clients: slow guessing down, but never refuse the real password
GLOBAL_BACKOFF_AFTER = 20
GLOBAL_MAX_BACKOFF = 8.0


def lockout_remaining(failure_times: list, now: float) -> float:
    """Seconds left in a lockout, given failed sign-in times since the last success.

    Sliding window: at most MAX_ATTEMPTS failures per LOCKOUT_SECONDS.
    """
    recent = sorted(t for t in failure_times if now - t < LOCKOUT_SECONDS)
    if len(recent) < MAX_ATTEMPTS:
        return 0.0
    return max(0.0, recent[-MAX_ATTEMPTS] + LOCKOUT_SECONDS - now)


def global_backoff(failure_times: list, now: float) -> float:
    """Extra delay when many clients are failing at once. Not a hard lock."""
    recent = [t for t in failure_times if now - t < LOCKOUT_SECONDS]
    extra = len(recent) - GLOBAL_BACKOFF_AFTER
    if extra <= 0:
        return 0.0
    return min(GLOBAL_MAX_BACKOFF, 0.25 * (2 ** min(extra, 5)))


def failures_for_client(entries: Iterable[dict], client_key: str) -> List[float]:
    """Collect failed-attempt timestamps for one client from audit entries.

    A successful sign-in for that client clears the window. Entries for other
    clients are ignored, so one source cannot lock out another.
    """
    failures: List[float] = []
    for entry in entries:
        details = entry.get("details") or {}
        if details.get("client") != client_key:
            continue
        if entry["action"] == "sign_in":
            failures = []
        elif entry["action"] == "sign_in_failed":
            stamp = entry["timestamp"]
            if isinstance(stamp, datetime):
                failures.append(stamp.timestamp())
            else:
                failures.append(float(stamp))
    return failures
