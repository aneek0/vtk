"""Input classification: what the user sent, and the default format for it.

``classify`` answers "is this a single set of links, a subscription URL, or a
config file?"; ``default_format`` maps that answer plus the caller's node count
onto the user's settings. Front-ends (bot/web/CLI) must not re-derive either:
they used to keep their own copies of both rules and drifted.

Module-level imports here stay dependency-free on purpose — ``core.logic``
imports this module at import time, so a runtime import of ``core.converters``
or ``core.settings`` would create a cycle.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from core.converters import Format
    from core.settings import Settings


class InputKind(str, Enum):
    """Shape of the user's input, decided before any parsing happens."""

    LINK = "link"
    SUB = "sub"
    CONFIG = "config"


def classify(text: str) -> InputKind:
    """Classify (already decrypted) user input."""
    text = text.strip()
    if text.startswith(("http://", "https://")):
        return InputKind.SUB
    if text.startswith("{") or "proxies:" in text or text.startswith("- name:"):
        return InputKind.CONFIG
    return InputKind.LINK


# Settings field holding the default output format for each input kind. A link
# batch (more than one parsed node) uses ``txt_format`` instead of
# ``link_format``.
_SETTINGS_KEYS = {
    InputKind.SUB: "sub_format",
    InputKind.LINK: "link_format",
    InputKind.CONFIG: "config_format",
}
_BATCH_SETTINGS_KEY = "txt_format"


def settings_key(kind: InputKind, batch: bool = False) -> str:
    """Name of the ``Settings`` field that defaults ``kind``."""
    if kind is InputKind.LINK and batch:
        return _BATCH_SETTINGS_KEY
    return _SETTINGS_KEYS[kind]


def default_format(kind: InputKind, settings: Settings, node_count: int) -> Format:
    """Default output format for ``kind``.

    A link input with more than one parsed node is a batch and uses
    ``txt_format``; a single link uses ``link_format``. ``node_count`` is the
    parsed node count, so every supported scheme counts — earlier heuristics
    matched a hardcoded prefix list and misrouted e.g. hysteria2 batches.
    """
    return getattr(settings, settings_key(kind, batch=node_count > 1))
