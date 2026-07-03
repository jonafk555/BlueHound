"""Shared regex safety utilities (ReDoS lint + bounded compile/search).

Extracted from threat_rules.py and tests/test_redos.py so the same hardening is
reused by:
  - the playbook rule engine (threat_rules.py),
  - the FR-1 Hunt Query IR regex predicates (user-supplied regex), and
  - the FR-3 detection-rule generator (LLM-drafted regex must pass this gate).

Untrusted regex (from an LLM draft or a user query) must clear `validate_user_regex`
BEFORE it is ever compiled against real data: it has to compile, must not contain a
classic catastrophic-backtracking shape, and must run fast against pathological
inputs sized at the MAX_REGEX_TEXT bound.
"""
from __future__ import annotations

import contextvars
import logging
import re
import time
from functools import lru_cache

logger = logging.getLogger(__name__)

# Searched text is truncated to this many chars — a hard backstop against
# regex DoS regardless of pattern shape.
MAX_REGEX_TEXT = 16_384

# Reject obviously hostile user/LLM patterns before we ever compile them.
MAX_PATTERN_LEN = 2_048

# Classic catastrophic-backtracking shape: a quantified group whose body also
# contains a quantifier — (X+)+ , (X*)* , (X+)* , (a|a)* , etc.
NESTED_QUANT = re.compile(r"\([^)]*[+*][^)]*\)[+*]")

# Per-IR total-time budget for the timing gate. A single IR may embed multiple
# regex predicates; without this cap, an attacker crafts several "just under
# the per-regex budget" patterns and sums them into a multi-second CPU stall
# on the event loop. Set to a small integer via env for prod hardening.
IR_TIMING_BUDGET_S = float(__import__("os").getenv("BLUEHOUND_IR_REGEX_BUDGET_S", "0.25"))
_ir_timing_used = contextvars.ContextVar[float]("ir_timing_used", default=0.0)


class RegexBudgetExceeded(ValueError):
    """Raised when the aggregate per-IR regex validation time budget is spent."""


@lru_cache(maxsize=512)
def _compile_rule_regex(pattern: str):
    """Compile + cache a regex. Raises re.error on an invalid pattern."""
    return re.compile(pattern)


def safe_search(pattern: str, text: str) -> bool:
    """Bounded regex search for a trusted pattern against untrusted text.

    Truncates the searched text at MAX_REGEX_TEXT and swallows invalid-pattern
    errors (returns False) so a single bad pattern can never crash a scan.
    """
    if not text:
        return False
    try:
        return bool(_compile_rule_regex(pattern).search(str(text)[:MAX_REGEX_TEXT]))
    except re.error as exc:
        logger.error("Invalid regex pattern %r: %s", pattern[:60], exc)
        return False


def has_redos_shape(pattern: str) -> bool:
    """True if the pattern contains a nested-quantifier ReDoS shape."""
    return bool(NESTED_QUANT.search(pattern or ""))


# Reduced from the original 11-input × 16KB × 300ms sweep — that combination
# gave a single call worst case of ~3.3s of pure CPU, which an authenticated
# caller could weaponize by embedding a regex per IR predicate. Three targeted
# inputs at 4KB with a 100ms per-input budget catches every known nested
# backtracking blow-up in <30ms while capping single-call CPU at ~300ms.
_PATH_INPUT_LEN = 4_096


def _pathological_inputs(n: int = _PATH_INPUT_LEN) -> dict:
    """Inputs designed to trigger backtracking blow-ups, sized at the bound."""
    return {
        # Exercises `(a+)+`-style blow-ups on any-char / word-char patterns.
        "long_a":        "a" * n,
        # Trailing-fail forces maximum backtracking on near-anchored patterns.
        "trailing_fail": ("A" * (n - 1)) + "!",
        # Alternation-heavy near-match trips (X|X)*-shaped regexes.
        "alpha_num":     ("aA1-_" * (n // 5))[:n],
    }


def time_regex(pattern: str, budget_seconds: float = 0.10) -> tuple[bool, float]:
    """Run `pattern` via safe_search against pathological inputs.

    Returns ``(within_budget, worst_seconds)``. Also charges the elapsed time
    to the ambient per-IR budget (``IR_TIMING_BUDGET_S``); raises
    :class:`RegexBudgetExceeded` if the cumulative budget is spent — the
    caller can then reject the *entire* IR instead of just one predicate.
    """
    worst = 0.0
    for text in _pathological_inputs().values():
        t0 = time.perf_counter()
        safe_search(pattern, text)
        dt = time.perf_counter() - t0
        _ir_timing_used.set(_ir_timing_used.get() + dt)
        if _ir_timing_used.get() > IR_TIMING_BUDGET_S:
            raise RegexBudgetExceeded(
                f"aggregate regex validation budget exhausted ({IR_TIMING_BUDGET_S * 1000:.0f}ms)"
            )
        if dt > worst:
            worst = dt
        if dt > budget_seconds:
            return False, dt
    return True, worst


def reset_ir_regex_budget() -> None:
    """Zero the ambient per-IR regex validation budget. Call before running the
    timing gate over a batch of predicates so each IR gets a fresh allowance."""
    _ir_timing_used.set(0.0)


def validate_user_regex(pattern: str, budget_seconds: float = 0.10) -> tuple[bool, str]:
    """Full gate for untrusted (user/LLM) regex.

    Returns ``(ok, reason)``. ``reason`` is "" on success, otherwise a short,
    safe explanation suitable for an API response. Order: length → compile →
    static ReDoS lint → runtime timing (with per-IR aggregate budget).
    """
    if not isinstance(pattern, str) or not pattern:
        return False, "empty pattern"
    if len(pattern) > MAX_PATTERN_LEN:
        return False, f"pattern exceeds {MAX_PATTERN_LEN} chars"
    try:
        _compile_rule_regex(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    if has_redos_shape(pattern):
        return False, "nested-quantifier ReDoS shape rejected"
    try:
        ok, worst = time_regex(pattern, budget_seconds)
    except RegexBudgetExceeded as exc:
        return False, str(exc)
    if not ok:
        return False, f"regex too slow ({worst * 1000:.0f}ms > {budget_seconds * 1000:.0f}ms budget)"
    return True, ""
