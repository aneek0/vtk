"""Tests for the input classifier and output-format registry.

Both modules exist to stop per-front-end copies from drifting, so the tests
pin the mapping they own: input shape → settings key → default format, and
format → label/extension/valid-defaults.
"""

import pytest

from core.converters import Format
from core.formats import (
    SECTIONS,
    extension,
    formats_for,
    names,
    section,
    spec,
)
from core.input import InputKind, classify, default_format, settings_key
from core.settings import Settings


@pytest.mark.parametrize(("text", "kind"), [
    ("https://sub.example.com/abc", InputKind.SUB),
    ("  http://sub.example.com/abc  ", InputKind.SUB),
    ('{"outbounds": []}', InputKind.CONFIG),
    ("proxies:\n  - name: x", InputKind.CONFIG),
    ("- name: x\n  type: vless", InputKind.CONFIG),
    ("vless://u@h:443#n", InputKind.LINK),
    ("vless://u@h:443#n\nhysteria2://p@h:443#m", InputKind.LINK),
    ("", InputKind.LINK),
])
def test_classify(text, kind):
    assert classify(text) is kind


def test_default_format_counts_nodes_not_lines():
    """A batch is decided by parsed node count, whatever the protocols are."""
    s = Settings(
        sub_format=Format.MIHOMO,
        link_format=Format.SINGBOX,
        config_format=Format.TXT,
        txt_format=Format.FLCLASH,
    )
    assert default_format(InputKind.LINK, s, node_count=1) is Format.SINGBOX
    assert default_format(InputKind.LINK, s, node_count=2) is Format.FLCLASH
    assert default_format(InputKind.SUB, s, node_count=1) is Format.MIHOMO
    assert default_format(InputKind.CONFIG, s, node_count=7) is Format.TXT


def test_settings_key():
    assert settings_key(InputKind.SUB) == "sub_format"
    assert settings_key(InputKind.CONFIG) == "config_format"
    assert settings_key(InputKind.LINK) == "link_format"
    assert settings_key(InputKind.LINK, batch=True) == "txt_format"


def test_formats_registry_covers_every_format():
    assert set(names()) == {fmt.value for fmt in Format}


def test_format_spec_fields():
    assert extension(Format.SINGBOX) == "json"
    assert extension(Format.MIHOMO) == "yaml"
    assert extension(Format.TXT) == "txt"
    assert spec(Format.XRAY).label == "X-Ray JSON"


def test_defaults_offered_per_input_kind():
    assert Format.XRAY not in formats_for(InputKind.LINK)
    assert Format.FLCLASH not in formats_for(InputKind.CONFIG)
    assert Format.TXT in formats_for(InputKind.CONFIG)
    assert set(formats_for(InputKind.SUB)) >= {Format.SINGBOX, Format.MIHOMO}


def test_sections_match_settings_fields():
    for entry in SECTIONS:
        assert hasattr(Settings(), entry.key), entry.key
        assert section(entry.key) is entry
    assert section("nope") is None
    assert [entry.key for entry in SECTIONS] == [
        "sub_format", "link_format", "config_format", "txt_format"]
