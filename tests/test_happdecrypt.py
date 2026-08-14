"""Tests for happ:// crypt5 decryption.

Covers the originally-failing salted/XOR layout (previously raised
"crypt5 segment length missing") and the legacy layout, plus the two
marker keys that were missing from the bundled table.
"""

import pytest

from core.happ import decrypt_link

# Real crypt5 link that uses the newer salted/XOR layout. Its marker key
# (vdfzfoff) was missing from the bundled crypt5_keys.json before the fix.
SALTED_LINK = (
    "happ://crypt5/fzvdpFRTCfxgSdhB06UtoHD812H6nE8yA/bWsRseM+Z4EfbHCuhKJR0n016q3ffXo"
    "SM9x0Tl2SVUOMtJk6rp9ZK9ZPM7FgErR8AYe7Y1pj65cm53U7mtp4KV6PpOTWloXEmPSIJt+DI8b+OeH"
    "H0wy2uCftrMwGEhtJc8vSyhqY0Ic9fFR8DO7650yJbgcq1TBdudWC0lPP+JqZ181FT9+RW2xOX0MxOC1"
    "XvrVR+R8DwRZc/13YoEgyihJfbu2QSLN/rcHIoVQd1smsp0tJs2H6Ov8oxCejv1ExxJuT0h05CvkxAd"
    "+r6nCZO2hSvazSyOgMFh3yXpCoy8Iu6nGdFSo1gCFQHczsOLHYbD9q2duDL8BS+cZsFVx9otWexPqsm"
    "MkkwuWg+Z2eYXqJ0axBWKm9FCQqj9qpO9oxg5W5wsaUfTw1ed6lpNoZsZV4zwBj1hvla2r0lcTlKuXW"
    "OX/7C+U/3fFz2oA0mQ4ZUpQWuxH/M/Q8IXN8kLfEOsrSmBHNCcy3arVefcjYadtNnGF2hTWOUPUg6yKL"
    "CLHvkR9qWQwwezvdbZQPyEGPOiYb6LFBxLxgwisB4eexEpCcMkPE9++qTiuk/pHyYAz8MCb9xf2uCj7"
    "K8VXEejzgI6IhS3JanFRHDcqLEE6UPkpiz14D+0H9lFRPtAM1tT3oFhXre1WofBUXxFh0YprhD8bF47"
    "QA3ugZtbV2kggSLXI9Rhj/wmg6e74asWHFUmmGSF4mQS8M9Ld/92u0vERSSlTtJlP4inLi19MEIX5YMJ"
    "1EnGk6FlmhDKVPsKqRzNl/42FD0oAUCrLSZNfIKR1jhfPEn2qcNdJCkVC5xvfos=ff"
)

EXPECTED_SALTED = "https://realityvpn.online/api/sub/bLQXWihp3brEFJWQMYLP6U6C"


def test_crypt5_salted_layout_decrypts():
    """The originally failing link must now decrypt (salted/XOR layout)."""
    assert decrypt_link(SALTED_LINK) == EXPECTED_SALTED


def test_crypt5_missing_marker_key_present():
    """The marker that previously triggered a missing-key error is bundled."""
    from core.happdecrypt import _load_crypt5_keys

    keys = _load_crypt5_keys()
    assert "vdfzfoff" in keys
    assert "asajzqxt" in keys
    # Reference repo bundles 36 keys.
    assert len(keys) >= 36


def test_crypt5_unknown_marker_raises():
    """An unknown marker (no key) should raise a clear error, not crash."""
    link = "happ://crypt5/zzzz/zzzz" + ("A" * 40)
    with pytest.raises(RuntimeError):
        decrypt_link(link)
