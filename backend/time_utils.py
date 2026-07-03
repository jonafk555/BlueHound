"""Unified timestamp parsing for BlueHound.

Log sources ship timestamps in many formats — ISO 8601, Kibana Discover
(``Apr 4, 2025 @ 22:00:00.000``), epoch seconds/millis, auditd, syslog. The
review found several call sites that compared/sorted timestamps as raw strings,
which silently reorders mixed-format data. The rule is now:

  * At ingest, ``LogIngester._normalize`` stamps every event with a monotonic
    epoch seconds value in the ``_ts`` field (``None`` if unparseable).
  * All downstream sort/compare/min-max on time uses ``_ts`` — never the raw
    ``timestamp`` string.

This module owns the parser so hunt_ir, threat_rules, triage, and future
consumers share one lenient implementation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

# Formats tried after ``datetime.fromisoformat`` fails. Ordered by observed
# frequency in the sample data.
_FALLBACK_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%b %d, %Y %H:%M:%S.%f",
    "%b %d, %Y %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",     # Apache/nginx access log
    "%Y/%m/%d %H:%M:%S",
)


def parse_ts(value: Any) -> Optional[float]:
    """Lenient timestamp → epoch seconds. Returns ``None`` if unparseable.

    Accepts numeric (epoch seconds/millis), ISO 8601 with or without ``Z``,
    Kibana ``Apr 4, 2025 @ 22:00:00``, and the fallback formats above.
    """
    if value is None or value == "":
        return None

    # Fast path: already numeric.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        # Heuristic: values > 10^12 are almost certainly milliseconds.
        return v / 1000.0 if v > 1e12 else v

    s = str(value).strip()
    if not s:
        return None

    # Numeric string?
    try:
        v = float(s)
        return v / 1000.0 if v > 1e12 else v
    except ValueError:
        pass

    # Kibana Discover exports use " @ " between date and time.
    s = s.replace(" @ ", " ")
    # Normalize trailing Z to explicit offset for fromisoformat.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    # Try fromisoformat first — handles the vast majority of ISO variants.
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass

    for fmt in _FALLBACK_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def event_ts(ev: dict) -> Optional[float]:
    """Return the cached ``_ts`` (set by ingest) or fall back to parsing."""
    if not isinstance(ev, dict):
        return None
    cached = ev.get("_ts")
    if cached is not None:
        try:
            return float(cached)
        except (TypeError, ValueError):
            return None
    return parse_ts(ev.get("timestamp"))
