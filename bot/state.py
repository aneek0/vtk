"""Bot callback state: conversions waiting for a protocol choice.

When a batch contains several protocols the bot asks which one to convert and
attaches an inline keyboard. Answering used to re-run the whole pipeline from
the original text — refetching the subscription for a choice already parsed.
The picker now pops the parsed nodes and only re-renders them.

Entries are keyed by ``(chat_id, message_id)`` of the message carrying the
keyboard, so a callback finds its own state without hashing the input text.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from core.converters import Format
    from core.logic import Node

Key = tuple[int, int]


@dataclass
class PendingConversion:
    """Already-parsed nodes awaiting a protocol pick."""

    nodes: list[Node]
    protocols: dict[str, int]   # protocol -> node count, for the keyboard labels
    fmt: Format                 # format chosen for the initial conversion
    tag_prefix: str = ""
    group_by_country: bool = False
    sub_name: str = ""          # for output filenames
    created: float = field(default_factory=time.monotonic)


class PendingStore:
    """TTL-bounded store of :class:`PendingConversion` entries."""

    def __init__(self, ttl: float = 900.0, max_entries: int = 256):
        self.ttl = ttl
        self.max_entries = max_entries
        self._items: dict[Key, PendingConversion] = {}

    def store(self, key: Key, pending: PendingConversion) -> None:
        self._expire()
        if len(self._items) >= self.max_entries:
            oldest = min(self._items, key=lambda k: self._items[k].created)
            del self._items[oldest]
        self._items[key] = pending

    def take(self, key: Key) -> PendingConversion | None:
        """Pop ``key``; an expired entry is dropped and reported as missing."""
        self._expire()
        return self._items.pop(key, None)

    def __len__(self) -> int:
        return len(self._items)

    def _expire(self) -> None:
        cutoff = time.monotonic() - self.ttl
        for key in [k for k, v in self._items.items() if v.created < cutoff]:
            del self._items[key]
