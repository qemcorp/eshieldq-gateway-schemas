"""A validation error, reported without the secret that was refused.

The REST 422 body, the rest-app log and the console CLI all report through
this module: ``loc``, ``type`` and ``msg`` only (an allow-list: pydantic's
``input`` and ``ctx`` carry the raw value), and no secret quoted in ``msg``.
A secret is a value at a secret-named field; other values (an address) stay so
the message says what to fix. A secret whose field name does not say so (the
PPK's ``data``) is kept out of messages by its own validator.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from typing import Any

from pydantic import BaseModel

REDACTED = "[redacted]"
# The message for a body (or a secret) too large or deep to search.
WITHHELD = "Invalid value"

# Field names whose value is a secret; broad, as over-hiding only costs detail.
SECRET_FIELD = re.compile(
    r"password|passphrase|secret|otp|pin\b|_key$|(^|_)code$|token|credential|psk|ppk",
    re.IGNORECASE,
)

# A shorter secret is replaced only where it stands alone as a token.
_MIN_REDACT_LEN = 4
# Far beyond any real body; past these the message is withheld. Values and
# work are counted across all of one report's errors: a "missing" error
# carries the whole body, once per absent field.
_MAX_VALUES = 20_000
_MAX_DEPTH = 32
# A real secret is a scalar or a small model; a larger value is withheld.
_MAX_SECRET_VALUES = 1000
# Characters of names searched, secrets formatted and the message scanned or
# rewritten, across the report; then withheld.
_MAX_WORK = 100_000
# Longer than any field name: taken as a secret's, not searched.
_MAX_NAME_LEN = 128


class _Incomplete(Exception):
    """The submitted value was too large or deep to search."""


_SEQUENCES = (list, tuple, set, frozenset)


def _pairs(item: Any) -> Iterator[tuple[Any, Any]] | None:
    """A mapping's or model's (key, value) pairs, lazily: a copy costs all."""
    if isinstance(item, BaseModel):
        return iter(item)
    if isinstance(item, Mapping):
        return iter(item.items())
    return None


class _Budget:
    """What one report may spend, across all its errors."""

    def __init__(self) -> None:
        self.visited = 0
        self.work = 0

    @property
    def spent(self) -> bool:
        return self.visited > _MAX_VALUES or self.work > _MAX_WORK

    def charge(self, chars: int) -> None:
        self.work += chars
        if self.work > _MAX_WORK:
            raise _Incomplete


class _Search:
    def __init__(self, msg_len: int, budget: _Budget) -> None:
        self.msg_len = msg_len
        self.budget = budget
        self.taken = 0
        self.secrets: set[str] = set()

    def _texts(self, item: Any) -> list[str]:
        """The scalar ``item`` as text, charged before it costs its length."""
        if isinstance(item, bool) or item is None:
            return []
        if isinstance(item, str):
            return [item]
        if isinstance(item, bytes):
            self.budget.charge(len(item))
            return [item.decode("utf-8", errors="replace"), repr(item)[2:-1]]
        if isinstance(item, int):
            # More digits than the message has characters: not converted, as
            # str() of a long int is quadratic.
            digits = (item.bit_length() - 1) * 0.301
            if digits > self.msg_len:
                return []
            self.budget.charge(int(digits) + 2)
            return [str(item)]
        if isinstance(item, float):
            return [repr(item)]
        # Another object (an uploaded file): its text is unbounded.
        raise _Incomplete

    def _add(self, item: Any) -> None:
        """How a message can quote ``item``: as is or stripped, each escaped by
        ``repr()``/JSON (a value in a quoted list, an ``{x!r}``)."""
        for text in self._texts(item):
            bases = [text]
            if text[:1].isspace() or text[-1:].isspace():
                self.budget.charge(len(text))  # strip() copies it
                bases.append(text.strip())
            for base in bases:
                # No form is shorter than its base: a longer one is not in msg.
                if base and len(base) <= self.msg_len:
                    self.budget.charge(len(base))
                    self.secrets.update((base, repr(base)[1:-1], json.dumps(base)[1:-1]))

    def secret_name(self, name: str) -> bool:
        if len(name) > _MAX_NAME_LEN:
            return True
        self.budget.charge(len(name))
        return bool(SECRET_FIELD.search(name))

    def _step(self, depth: int) -> None:
        self.budget.visited += 1
        if self.budget.visited > _MAX_VALUES or depth > _MAX_DEPTH:
            raise _Incomplete

    def take(self, item: Any, depth: int) -> None:
        """Every form of every scalar in ``item``, a mapping's keys included.
        A container is walked, never formatted: str() of one costs all of it."""
        self._step(depth)
        self.taken += 1
        if self.taken > _MAX_SECRET_VALUES:
            raise _Incomplete
        pairs = _pairs(item)
        if pairs is not None:
            for key, value in pairs:
                self.take(key, depth + 1)
                self.take(value, depth + 1)
        elif isinstance(item, _SEQUENCES):
            for child in item:
                self.take(child, depth + 1)
        else:
            self._add(item)

    def find(self, item: Any, depth: int) -> None:
        """The values under secret-named keys anywhere in ``item``."""
        self._step(depth)
        pairs = _pairs(item)
        if pairs is not None:
            for key, value in pairs:
                if isinstance(key, str) and self.secret_name(key):
                    self.take(value, depth + 1)
                else:
                    self.find(value, depth + 1)
        elif isinstance(item, _SEQUENCES):
            for child in item:
                self.find(child, depth + 1)


def _secrets_in(error: Mapping[str, Any], msg_len: int, budget: _Budget) -> list[str]:
    """Every form, up to ``msg_len`` long, of every secret in the error's
    ``input``, longest first. Raises ``_Incomplete`` past a limit."""
    search = _Search(msg_len, budget)
    names = [part for part in error.get("loc", ()) if isinstance(part, str)]
    if any(search.secret_name(name) for name in names):
        # The refused value is itself a secret, or inside one.
        search.take(error["input"], 0)
    else:
        search.find(error["input"], 0)
    return sorted(search.secrets, key=len, reverse=True)


def _message(error: Mapping[str, Any], budget: _Budget) -> str:
    msg = str(error.get("msg", ""))
    if "input" not in error:
        return msg
    if budget.spent:
        return WITHHELD
    try:
        for secret in _secrets_in(error, len(msg), budget):
            # Each scan, and each rewrite, costs the message's current length.
            budget.charge(len(msg))
            if secret not in msg:
                continue
            budget.charge(len(msg))
            if len(secret) >= _MIN_REDACT_LEN:
                msg = msg.replace(secret, REDACTED)
            else:
                # Standalone only ('abc', ": abc"), not inside a word.
                msg = re.sub(
                    rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])", REDACTED, msg
                )
    except _Incomplete:
        return WITHHELD
    return msg


def validation_error_details(errors: Any) -> list[dict[str, Any]]:
    """Each error as ``{"loc", "type", "msg"}``, with no submitted secret in it.

    ``errors`` is a pydantic ``ValidationError``, FastAPI's
    ``RequestValidationError`` (anything with ``.errors()``), or their list of
    error dicts. Safe to apply twice.
    """
    items = errors.errors() if hasattr(errors, "errors") else errors
    budget = _Budget()
    return [
        {
            "loc": list(error.get("loc", ())),
            "type": str(error.get("type", "")),
            "msg": _message(error, budget),
        }
        for error in items
    ]


def format_validation_errors(errors: Any) -> str:
    """One console line: ``field.path: message; other: message``.

    Built from :func:`validation_error_details`, so it carries no submitted
    secret. A leading ``body`` and pydantic's ``Value error, `` prefix are
    dropped, as the Web UI does.
    """
    parts = []
    for detail in validation_error_details(errors):
        loc = [str(part) for part in detail["loc"]]
        if loc and loc[0] == "body":
            loc = loc[1:]
        msg = detail["msg"].removeprefix("Value error, ")
        parts.append(f"{'.'.join(loc)}: {msg}" if loc else msg)
    return "; ".join(parts)
