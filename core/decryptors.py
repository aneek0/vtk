"""Offline decryptor registry for proprietary deep-link schemes.

Two schemes ship with bundled keys: ``happ://crypt*`` (RSA) and
``incy://crypt1`` (AES-256-GCM). Both are offline, both are "decrypt this
link / decrypt every such link in this text / is this one of mine?", so they
share one interface here instead of each surface re-implementing the trio.

Per-scheme failures are :class:`~core.errors.DecryptError`; ``decrypt_input``
swallows those so an undecryptable link can never fail a batch. Any other
exception is a bug and propagates.
"""

from __future__ import annotations

import contextlib

from core.errors import DecryptError


class Decryptor:
    """One proprietary scheme backed by a bundled offline decryptor."""

    scheme: str = ""           # bare scheme, e.g. "happ"
    versions: tuple[str, ...] = ()  # advertised link-version labels

    def is_(self, text: str) -> bool:
        """True when ``text`` contains at least one link of this scheme."""
        raise NotImplementedError

    def decrypt_link(self, url: str) -> str:
        """Decrypt a single link; raises ``DecryptError`` when undecryptable."""
        raise NotImplementedError

    def decrypt_text(self, text: str) -> str:
        """Replace every link of this scheme in ``text``; idempotent."""
        raise NotImplementedError

    def supported(self) -> dict:  # pragma: no cover - overridden in subclasses
        """Version/key facts reported by ``GET /api/<scheme>/supported``."""
        return {"versions": list(self.versions)}

    @property
    def check_key(self) -> str:
        """Response key naming the check flag (``is_happ`` / ``is_incy``)."""
        return f"is_{self.scheme}"


class HappDecryptor(Decryptor):
    scheme = "happ"
    versions = ("crypt", "crypt2", "crypt3", "crypt4", "crypt5")

    def is_(self, text: str) -> bool:
        from core.happ import is_happ

        return is_happ(text)

    def decrypt_link(self, url: str) -> str:
        from core.happ import decrypt_link

        return decrypt_link(url)

    def decrypt_text(self, text: str) -> str:
        from core.happ import decrypt_text

        return decrypt_text(text)

    def supported(self) -> dict:
        from core.happdecrypt import _PKCS1_KEYS_B64, _load_crypt5_keys

        return {
            "versions": list(self.versions),
            "crypt1_4_keys": len(_PKCS1_KEYS_B64),
            "crypt5_keys": len(_load_crypt5_keys()),
        }


class IncyDecryptor(Decryptor):
    scheme = "incy"
    versions = ("crypt1",)

    def is_(self, text: str) -> bool:
        from core.incy import is_incy

        return is_incy(text)

    def decrypt_link(self, url: str) -> str:
        from core.incy import decrypt_link

        return decrypt_link(url)

    def decrypt_text(self, text: str) -> str:
        from core.incy import decrypt_text

        return decrypt_text(text)

    def supported(self) -> dict:
        from core.incy import KEY_FINGERPRINT, SCHEME_VERSION, VERSION

        return {
            "scheme": SCHEME_VERSION,
            "versions": list(self.versions),
            "keyFingerprint": KEY_FINGERPRINT,
            "version": VERSION,
        }


DECRYPTORS: tuple[Decryptor, ...] = (HappDecryptor(), IncyDecryptor())
BY_SCHEME: dict[str, Decryptor] = {d.scheme: d for d in DECRYPTORS}


def get_decryptor(scheme: str) -> Decryptor | None:
    return BY_SCHEME.get(scheme)


def decrypt_input(raw: str) -> str:
    """Decrypt every supported encrypted link in ``raw`` (idempotent).

    Already-plain text passes through unchanged. Per-link decode failures are
    contained inside each decryptor; this wrapper suppresses ``DecryptError``
    so one bad link never aborts the pass.
    """
    text = raw
    for decryptor in DECRYPTORS:
        with contextlib.suppress(DecryptError):
            text = decryptor.decrypt_text(text)
    return text
