"""Output format registry: labels, extensions and settings sections.

Every surface (bot keyboards, CLI menus, web ``<select>``, error messages)
used to carry its own copy of "which formats exist", "what is this format
called", "which extension does it download as" and "which formats may be a
default for which input kind". Those copies drifted; this module is now the
only one.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.converters import Format
from core.input import InputKind


@dataclass(frozen=True)
class FormatSpec:
    """One selectable output format."""

    fmt: Format
    label: str                              # human label for menus and <option>
    extension: str                          # download extension, no dot
    default_for: tuple[InputKind, ...] = ()  # kinds this format may be default for


# UI order: config formats first, plain text last.
FORMATS: tuple[FormatSpec, ...] = (
    FormatSpec(Format.SINGBOX, "sing-box JSON", "json",
               (InputKind.SUB, InputKind.LINK, InputKind.CONFIG)),
    FormatSpec(Format.MIHOMO, "mihomo YAML", "yaml",
               (InputKind.SUB, InputKind.LINK)),
    FormatSpec(Format.FLCLASH, "FlClash YAML", "yaml",
               (InputKind.SUB, InputKind.LINK)),
    FormatSpec(Format.XRAY, "X-Ray JSON", "json"),
    FormatSpec(Format.TXT, "Plain text", "txt",
               (InputKind.SUB, InputKind.LINK, InputKind.CONFIG)),
)

_BY_FORMAT = {spec.fmt: spec for spec in FORMATS}


@dataclass(frozen=True)
class Section:
    """One per-input-kind settings section (``Settings.<key>``)."""

    key: str          # Settings attribute holding the default format
    label: str        # human label
    kind: InputKind


SECTIONS: tuple[Section, ...] = (
    Section("sub_format", "Subscriptions", InputKind.SUB),
    Section("link_format", "Links", InputKind.LINK),
    Section("config_format", "Configs", InputKind.CONFIG),
    Section("txt_format", "TXT files", InputKind.LINK),
)

_SECTIONS_BY_KEY = {section.key: section for section in SECTIONS}


def spec(fmt: Format) -> FormatSpec:
    """Registry entry for ``fmt`` (``KeyError`` if the format is unknown)."""
    return _BY_FORMAT[fmt]


def extension(fmt: Format) -> str:
    return _BY_FORMAT[fmt].extension


def names() -> list[str]:
    """Accepted ``--format`` values, in UI order."""
    return [spec.fmt.value for spec in FORMATS]


def formats_for(kind: InputKind) -> list[Format]:
    """Formats that may serve as the default output for ``kind``."""
    return [spec.fmt for spec in FORMATS if kind in spec.default_for]


def section(key: str) -> Section | None:
    return _SECTIONS_BY_KEY.get(key)
