"""
Happ deep-link decryptor — pure Python, client-side equivalent.

Supports:  happ://crypt/…   happ://crypt2/…  happ://crypt3/…
           happ://crypt4/…  happ://crypt5/…

Dependencies:
  pycryptodome  → RSA PKCS1v15 decrypt
  cryptography  → ChaCha20-Poly1305 decrypt

Runtime data (bundled with the package):
  data/crypt5_keys.json       – { "marker": "base64-PKCS8-key", … }
"""

from __future__ import annotations

import base64
import json
import logging
import re
from pathlib import Path
from typing import Final

from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA as CryptoRSA
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# String / byte helpers
# ---------------------------------------------------------------------------

def _swap_pairs(s: str) -> str:
    """Swap adjacent character pairs: ABCD → BADC."""
    arr = list(s)
    for i in range(0, len(arr) - 1, 2):
        arr[i], arr[i + 1] = arr[i + 1], arr[i]
    return "".join(arr)


def _b64_decode_urlsafe(s: str) -> bytes:
    """URL-safe base64 → bytes, with padding restoration."""
    s = s.replace("-", "+").replace("_", "/")
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Crypt1–4: hard-coded PKCS#1 RSA keys (RSA-1024 / RSA-4096)
# ---------------------------------------------------------------------------

_PKCS1_KEYS_B64: Final[tuple[str, ...]] = (
    # key[0] — happ://crypt/  (RSA-1024)
    "MIICXwIBAAKBgQCxsS7PUq1biQlVD92rf6eXKr9oG1/SrYx3qWahZP+Jq35m4Wb/Z+mB6eBWrPzJ/zZpZLWLQorcvOKt+sLaCHyH1HLNkti4jlaEQX6x97XgBm8GK08+lLLWquFDhWRNxsrfzJyNdpVopzBRmCJKTc8ObYyPbrv9T35a8Kd5WqjnUwIDAQABAoGBAJoqe85skPPF5U7jwRM2YhUJhZ+xgGWtJR3834pPslWjcLuZ/F7DrRiF7ZnF5FztDCxMsCXuycPSLWl9EulQS5mrL/fnwpK2jVE8O1Em9RsBOOrWwzuZnAuooRIb/8zC0fvH2oGkk60zSKycMe69uvYUDjhvULX2Spjmf9CS9/HhAkEA3I797En/DrpAZz6NM4GqZ1mkH0kEX/kAHLP1lBgYL1kVK455EG/ecJkMJmtK7A+fWw0N0IcxrpYAbbOAo19vjwJBAM4+0MAZ8TIZUk6Rs2gYUo04A6mYUy5MWtRa9pyFIgD71oHDR+1jrnPLqQyCj0tfbZBc1iVgsisJBpocC8sKaf0CQQDRNd3Mxb/nY2p1xJLBmaxezlvsxSEePB4MG/PFXzmJqBF5uHJD0imIWtR4mOt/ka4R+wbwl1zcAzMy28MYtQ0nAkEAuUILWML0uL+uAw01TeerH1aVU52T+h5z6BPdOTMNHD0arWywCzhi13i03JvaAyYw0F/Tq7dz0txEpeFTZopwMQJBANnHbzB87/xTjDQA4/L8sSU8m0vM1nRWmJIaAC94pcM+KDGLnbBhWrvZGy8Zg8vQwNvdvCLvylk0jVTTFqW3ibM=",
    # key[1] — happ://crypt2/  (RSA-4096)
    "MIIJKQIBAAKCAgEA5cL2yu9dZGnNbs4jt222NugIqiuZdXKdTh4IgXZmOX0vdpW+rYWrPd1EObQ3Urt+YBTK5Di98EBjYCPr8tusaVRAn3Vaq41CDisEdX35u1N8jSHQ0zDOtPdrvJtlqShib4UI6Vybk/QSmoZVbpRb67TNsiFqBmK1kxT+mbtHkhdT2u+hzNLQr0FtJR1+gC+ELKZ48zZY/d3YSSRSb+dxUnd4FH31Kz68VKqlajISSzIrGQWc/zqSlihIvfnTPNX3pCyJpwAuYXieWSRDAogrwGwoiN++y14OLYHrNlqzoJ44WM3Tbm7x1Dj/8QI3tzwixli/0JmqQ19ssETDbVQ90asoPc4QFhyc4c+PH62AdK1S+ysXt5uqEujRBk3rC53l65IOVXSTZgsLwzS7EFY9lZszJXUJJh5GB9heO8c7PNCTOxno3l4684iHFJuxnkS0DLbdzCXfovwfIP8q3lj7UJswPKVHkCLNSUutNke+xex1J3YEdvebJzv7Dk78PqLRmLWaEsAhQanXs93aTxEkd/p7hgFV30QozVQ/oNAvmQSVIBd6zCGM3of3R3tmDkDNGQGrY4MBTX+cTJGYstdhQXxj1oFZEG16F/0GGXG+sia67gYM3OC7RWyBOzULsEmupIiM8Vdx1iErw7yvJSC4IsIsWZD8JAmZtLBqEQ/TvfcCAwEAAQKCAgATc0nJLDJPydUmSDUl1hfS1hnFriMzmhxO/KPjsc49l6do9oxJzEMO3ahk6ii0zEKKh7gVUehialD/Vosm6AnUcNl3pkuisjahVGrwN1Xo0cx9dhtjhYI6N6fbM5yLkWuj3TM/7iMNh1/7zNt2nQCbF5dCOSnsmHaemOxkv0Hz0B29LwQXftFDxNokhjarS1p5HS6oCDXIZ/tjVbvU1Vb2kD6OHYufuZPf5wJR1yNNUlXrrFn6EU9PfuGJk5iaUdLBBzQv+wfyIG/nQ/aYREbP51gXHjncpX21xIXQ+CS0uDA09FetxZ6bRKgGExX8YQ7gk6rJUfjj8zQUR/3zR2pkKHRywANzu32VnSvFFtEL7+EuM0XA03MZStGuRb3/QjO+I2JOV+Ec+VVc9OYangwu8+mQC1NnCWe49LZX04hc/xlRqW4kaWcpbT7xGTIeSrWhR7cBjUvgc7NNDnKla8mXSW5/6iSi2Vl83CBm78/ao+Pwbtk/D6n3fM4c3FNiBDyWHJ27C8HLicDhSiQqZUuO203zBZrstUNN7tkmMvaHlavrvL0ajBIJD27Vo/uZ61OVYEPDybNJlRFsaRNirIYCHk2DBte6nqbZ7Hvm+3iIk928vz1dyQdZ4bLPO5onxTFAcfny8pruXnnS/aTXvaHlzTc84z5mBPR94VRqOEKrAQKCAQEA9VUEaz2XWdQuafQo6CIx2YGcBKcmQfpbBtfHb+V4BBko9BzU3ao6AGSXS54LMktnAmKjqbXkjjaMKKEHj85BbchlDoXqaSU9Xnq7wO20xn18OxNCkPdxHzzN4/HT78nRbCOxteBv4V56HsZit2a2eaBokqUuirQTZBqNpLgkPOR/wrV/Tk9RvOG4IVYxvl1TIZdp2VXqpxHceu+aE0JgQ2kj8N70w6YUOgjxRFLirr4tsPvJFs6XflogEXwsMtJGsN7Esy4uNlBGSd6JjLFuUtALXCZbx5wgKauqyJctmtqd1dllnpqAfe1eZL/aVyd2tyRg0MzqacZVs28lcuEIYQKCAQEA78CegneDbIdPyTW2+YDVVYUMQcIkxF82CnEql1GS2nIewhlKOYsAXrWln4NLdHltKX6POhfmWO5WA5ERD7v0NmNw9Q/+3je6BXx1RasExXYOqwcz7UAni95p6ZZBTP/j0fFZQYLzUC7Yg5eBDP8rKFR0MV5FnWW7fYxC5+bJY5dZH8A7Jqkt9lrNo4gmfAgbHhFoOFY6X3E7r3UTpx0XtQNQeCZ8sDF9RULSHep6EA0Kg8JtUdjbpBiTv",
    # key[2] — happ://crypt3/  (RSA-4096)
    "MIIJJwIBAAKCAgEAlBetA0wjbaj+h7oJ/d/hpNrXvAcuhOdFGEFcfCxSWyLzWk4SAQ05gtaEGZyetTax2uqagi9HT6lapUSUe2S8nMLJf5K+LEs9TYrhhBdx/B0BGahA+lPJa7nUwp7WfUmSF4hir+xka5ApHjzkAQn6cdG6FKtSPgq1rYRPd1jRf2maEHwiP/e/jqdXLPP0SFBjWTMt/joUDgE7v/IGGB0LQ7mGPAlgmxwUHVqP4bJnZ//5sNLxWMjtYHOYjaV+lixNSfhFM3MdBndjpkmgSfmgD5uYQYDL29TDk6Eu+xetUEqry8ySPjUbNWdDXCglQWMxDGjaqYXMWgxBA1UKjUBWwbgr5yKTJ7mTqhlYEC9D5V/LOnKd6pTSvaMxkHXwk8hBWvUNWAxzAf5JZ7EVE3jt0j682+/hnmL/hymUE44yMG1gCcWvSpB3BTlKoMnl4yrTakmdkbASeFRkN3iMRewaIenvMhzJh1fq7xwX94otdd5eLB2vRFavrnhOcN2JJAkKTnx9dwQwFpGEkg+8U613+Tfm/f82l56fFeoFN98dD2mUFLFZoeJ5CG81ZeXrH83niI0joX7rtoAZIPWzq3Y1Zb/Zq+kK2hSIhphY172Uvs8X2Qp2ac9UoTPM71tURsA9IvPNvUwSIo/aKlX5KE3IVE0tje7twWXL5Gb1sfcXRzsCAwEAAQKCAgAK3VHMFCHlQaiqvHNPNMWRGp0JJl27Ulw3U1Q9p+LC3OWNknyvpxC5EJPQbTUXhlO2A9AiDOXmaj5EMavTAaj0tzWhLlrVVQ/CSJYS4sVyAY67GyTpOIxmYtPBE3YY6vTU1SSoU2dqnMDnfwAbM2g0QXatXYRDGPYLLNHHp7R27IBpBTJeDwb2qEA1BBC/3WXsfVy6cfhWrrB7fH4F9tuEtG+sp+N2fbDcFnDH1hbQAm+HEXKzWMpRcSmX+rQ2wDlLW/N3utI+TzP4Vx5zTuT3QCsDYzeRgSJ4CjMwKKSGZ3QDF5cDCVJdsJ24fRl+mpBWoLqqBS7gzFVYsTx88GNs5jl9D7ZndIEOKYhtA00NgF+0N1Vs7IbgfoBfwABSFoiukBcre2NvJ4jVxApy09IiN6E/HBZ/qhH3q+1k9nLFgzH9VsBXuucgjlSFXzVLLQilfsd7LEaX8ytGDAiAC3RLbIhDRX3ruv0ufRSwhUoGd4ps+cgHrKGUGqz4pdjOzWFNTzpTTYuxkoMbklI+HIFQcstNLW0mryBcWhldqLhYNGH5w4fX+J/wkxbH1Yh9slPWT+WX69/l9myysscXxSlev9Ycty4rNWt9kohNHvBd5ZxlePD5ngTmCZ2PjisUS1Kvmy9rjzRjP2qNoxmXmTbp3QJymuF1RjtRHxlqHGVlgQKCAQEA0S/SnC+BUlUxxCVQ+qNE8FAe5EWdNgSlz1ep5NGcOBUgpFStHJBGdzSc1Ht6MuBd+2Gqfzi46CR5BbyaC9i3P0X4347wKjrzPQ39l1kGideRKEKMAbmj2SdaU7kYWFhddurGssp4xzojNG0BYkR/0kEnHeCu/RJ6HVwv5K5vyhYsAwKeWeTS3T06KElgy4uNNRRAqI9ZJamrU7ZfIQ7YBHsCWlgFwx7Hu7rQS8dOPmd4TW0Xs32yEDfDymw98e4kxNME01Z9Q55uShLwXo4g+wp/6SYL363OyR/MqSAW66IthPqz6WnJ37hmk2SZsUip9tBHPdJyvACHeNR9SP4VMwKCAQEAtTvMeW0QvNWK7+VM2cnm2viFPpqGWDaccI6Zct/Qb6cO05xdRtarm/QjM3vXjjN4ALj4gPkz014oPEcHJe5Y6ma1tGmy01cltvYoUsfxYHX2jUiaI9EmmOIR/9gSiAZn+P9RjNx9Q/hHT9ul+H5FnitC9wV0TZ7egu3ROKuZ7t5EhdogO5lC8qUn6GrVIdj9eDAGkHWdO6v3cqYuP6cV6yiBOK2CikW+MnLC8yXGwvWX7iW4/2f0xBP+N",
    # key[3] — happ://crypt4/  (RSA-4096)
    "MIIJKQIBAAKCAgEA3UZ0M3L4K+WjM3vkbQnzozHg/cRbEXvQ6i4A8RVN4OM3rK9kU01FdjyoIgywve8OEKsFnVwERZAQZ1Trv60BhmaM76QQEE+EUlIOL9EpwKWGtTL5lYC1sT9XJMNP3/CI0gP5wwQI88cY/xedpOEBW72EmOOShHUm/b/3m+HPmqwc4ugKj5zWV5SyiT829aFA5DxSjmIIFBAms7DafmSqLFTYIQL5cShDY2u+/sqyAw9yZIOoqW2TFIgIHhLPWek/ocDU7zyOrlu1E0SmcQQbLFqHq02fsnH6IcqTv3N5Adb/CkZDDQ6HvQVBmqbKZKf7ZdXkqsc/Zw27xhG7OfXCtUmWsiL7zA+KoTd3avyOh93Q9ju4UQsHthL3Gs4vECYOCS9dsXXSHEY/1ngU/hjOWFF8QEE/rYV6nA4PTyUvo5RsctSQL/9DJX7XNh3zngvif8LsCN2MPvx6X+zLouBXzgBkQ9DFfZAGLWf9TR7KVjZC/3NsuUCDoAOcpmN8pENBbeB0puiKMMWSvll36+2MYR1Xs0MgT8Y9TwhE2+TnnTJOhzmHi/BxiUlY/w2E0s4ax9GHAmX0wyF4zeV7kDkcvHuEdc0d7vDmdw0oqCqWj0Xwq86HfORu6tm1A8uRATjb4SzjTKclKuoElVAVa5Jooh/uZMozC65SmDw+N5p6Su8CAwEAAQKCAgBLlgyNoqFZxWjZZmHiSXr7bUdxCEkfkM8Nn8dcky12O8fB6mv39LZcrF22u+UIDIgec31Igq1G4e5ojd62LDAQLCnKlp2SJMeLo1ILTYTYtPJuJUqSolPuhzeKbFl1ouHp88e2sUMpmwJT6UpFj0L6hqOr4lkjfC1kktXPXvSe3lpDvIYXBrlFU5slPP3WLE5RaLW+w4gE6nt9+FS6xkJHQHhP1odE+z8B0EV/HdhvKTCnWz4bGj4azlkPhNdl3EKLS6axTlti/hq9yT6d7owlu4sKnkqGF18deei8hoJ4eWvHo7a12BfQHuKJJJ6Qgb1jzQv+tm9XEZ7qCxaMtwHabrjnIDM57xvJAO4fKX5L3/hN+Zx8q4dFsHhOOnJ1As18YChkYJXF9zcUGEztoiDBUQJAIrMJHWFJOtxj78fP18LYOjbhUL1H3IdKLLr1duX9aGM9lAgJV66l/rWlyePh+pBMriTbOAnXEsQFVvjzzzyBZznBZYCJow/KmZO3WciFbSETqq3FqoE3HwvxsjlaC4gpHWqa40lGtjFvPnIHS6MbH7LwVcAldDrjuqNJMd5lWhPAnYVj7JYER230X2HQ3BBrrAZ7Zae1lrJfdQs0zjYiyHdOAmTEtWnkuSadknecHrL4RYoZtdTriZT42N+tcbJAb5GLr3FOVwV6IhEEWQKCAQEA/AZ7xHIZmI6KcWWoYQVP2Ibmjv+DZYGAtyoYd+hnV9KiGAddJWknbZycCZU4qyG63+wEEFEoPJ3KfEqUwGHVK5jaexLP/BbgR9nwt3UF1IhDs3D8UrS79YFihuvcz+hlGDsrcTj8DZkoVAsMom0I4lsTNqauH+o0I6UYLrRswcIlbKG6yJN1B08Nbz88l8qCLLhRMXJ2yxfSch20T28UggS2bZnpEws5DY5I1C6irGRIyaLNVEi076Dp9OZ8RCnXn7KfXnZntl0AvQVUaOvTt2fh9X4Qnk5XADfUoZ2it1HIinNQOLpnhoNa2/cpGoG3tPnXaY8NNC3dt/dyCahTJQKCAQEA4MPSOuD98dv3V3GY/ODyDphzQOHxp+dHiDcY1TzLcJs3XVuPgMSL0GGBrhn5yiKKjir2mNdsdDtS2qwZVp2fZI2oUunMMZ2tila+Wa+AMUZyvUP6OFRs/qu24mVsNizV5Ad7/d/mEmfoMnRQk0Eg0dx1GNelhcdd0GvyaKAu1/uvKt97BaKLHhfC41keO1GNGXeASSSfIa5jlXQngVSPzh5C+rhtgv+z9KkyGHXUxiflisQlgKmDAXBSw",
)

# ---------------------------------------------------------------------------
# Crypt5: marker → PKCS#8 RSA-4096 private key (lazy-loaded)
# ---------------------------------------------------------------------------

_crypt5_keys: dict[str, bytes] | None = None


def _load_crypt5_keys() -> dict[str, bytes]:
    """Load crypt5 RSA keys from bundled JSON (lazy, cached)."""
    global _crypt5_keys
    if _crypt5_keys is not None:
        return _crypt5_keys

    data_path = Path(__file__).parent.parent / "data" / "crypt5_keys.json"
    if not data_path.exists():
        raise FileNotFoundError(f"crypt5 keys not found: {data_path}")

    raw = json.loads(data_path.read_text())
    # Decode base64 PKCS#8 DER once, store as bytes
    _crypt5_keys = {marker: base64.b64decode(key_b64) for marker, key_b64 in raw.items()}
    logger.info("Loaded %d crypt5 RSA keys", len(_crypt5_keys))
    return _crypt5_keys


# ---------------------------------------------------------------------------
# RSA decrypt helpers
# ---------------------------------------------------------------------------

def _pkcs1_decrypt(private_key, ciphertext: bytes) -> bytes:
    """RSA PKCS#1 v1.5 decrypt using pycryptodome."""
    cipher = PKCS1_cipher.new(private_key)
    # pycryptodome's PKCS1_v1_5.decrypt returns None on failure if sentinel not used
    # Use sentinel to detect failure
    sentinel = b"\x00" * 16
    result = cipher.decrypt(ciphertext, sentinel)
    if result is sentinel:
        raise ValueError("RSA PKCS#1 v1.5 decryption failed")
    return result


def _load_pkcs1_key(b64_der: str):
    """Load PKCS#1 RSA private key from base64-encoded DER."""
    der = base64.b64decode(b64_der)
    return CryptoRSA.import_key(der)


def _load_pkcs8_key(b64_der: bytes):
    """Load PKCS#8 RSA private key from raw DER bytes."""
    return CryptoRSA.import_key(b64_der)


# ---------------------------------------------------------------------------
# Crypt5 pipeline
# ---------------------------------------------------------------------------

def _block_pair_swap(s: str) -> str:
    """Whole-string CDAB permutation: every full 4-char block ABCD → CDAB."""
    full_len = len(s) - (len(s) % 4)
    out = []
    for offset in range(0, full_len, 4):
        out.append(s[offset + 2 : offset + 4])
        out.append(s[offset : offset + 2])
    return "".join(out) + s[full_len:]


def _decrypt_crypt5(payload: str) -> str:
    """Decrypt a crypt5 payload → plaintext URL."""
    shuffled = _block_pair_swap(payload)
    if len(shuffled) < 8:
        raise ValueError("crypt5 payload too short")

    marker = shuffled[:4] + shuffled[-4:]
    body = shuffled[4:-4]
    if len(body) < 13:
        raise ValueError("crypt5 body too short")

    nonce_str = body[:12]
    rest = body[12:]

    # Parse leading decimal digits for URL segment length
    m = re.match(r"^(\d+)", rest)
    if not m:
        raise ValueError("crypt5 segment length missing")
    segment_len = int(m.group(1))
    packed = rest[m.end() :]

    if len(packed) < 1 + segment_len:
        raise ValueError("crypt5 segment truncated")

    url_b64 = packed[1 : 1 + segment_len]
    enc_str = packed[1 + segment_len :]

    # Lookup RSA key by marker
    keys = _load_crypt5_keys()
    if marker not in keys:
        raise ValueError(f"No RSA key found for marker: {marker}")

    private_key = _load_pkcs8_key(keys[marker])

    # RSA decrypt
    enc_bytes = _b64_decode_urlsafe(enc_str)
    rsa_plaintext_bytes = _pkcs1_decrypt(private_key, enc_bytes)

    # swapPairs → base64-decode → ChaCha20 key
    rsa_plaintext_str = rsa_plaintext_bytes.decode("latin-1")
    chacha_key = _b64_decode_urlsafe(_swap_pairs(rsa_plaintext_str))

    # ChaCha20-Poly1305 decrypt
    nonce = nonce_str.encode("ascii")
    aead = ChaCha20Poly1305(chacha_key)
    ciphertext = _b64_decode_urlsafe(url_b64)
    intermediate = aead.decrypt(nonce, ciphertext, None)

    # swapPairs → base64-decode → final URL
    intermediate_str = intermediate.decode("utf-8")
    final_bytes = _b64_decode_urlsafe(_swap_pairs(intermediate_str))
    return final_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# Crypt1–4 pipeline
# ---------------------------------------------------------------------------

def _decrypt_crypt1to4(ordinal: int, payload: str) -> str:
    """Decrypt crypt1–4 payload → plaintext URL."""
    if ordinal < 0 or ordinal >= len(_PKCS1_KEYS_B64):
        raise ValueError(f"Invalid key ordinal: {ordinal}")

    private_key = _load_pkcs1_key(_PKCS1_KEYS_B64[ordinal])
    key_size = (private_key.size_in_bits() + 7) // 8  # bytes
    cipher_bytes = _b64_decode_urlsafe(payload)

    plaintext_parts = []
    for i in range(0, len(cipher_bytes), key_size):
        block = cipher_bytes[i : i + key_size]
        plaintext_parts.append(_pkcs1_decrypt(private_key, block))

    plaintext = b"".join(plaintext_parts)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

HAPP_RE = re.compile(r"happ://(crypt|crypt2|crypt3|crypt4|crypt5)/([^\s]+)")


def decrypt_link(link: str) -> str:
    """
    Decrypt a happ://crypt* link.

    Accepts:
      happ://crypt/… , happ://crypt2/… , … , happ://crypt5/…
    Returns the decrypted URL.
    Raises ValueError on failure.
    """
    path = link.removeprefix("happ://")

    if path.startswith("crypt5/"):
        return _decrypt_crypt5(path.removeprefix("crypt5/"))
    if path.startswith("crypt4/"):
        return _decrypt_crypt1to4(3, path.removeprefix("crypt4/"))
    if path.startswith("crypt3/"):
        return _decrypt_crypt1to4(2, path.removeprefix("crypt3/"))
    if path.startswith("crypt2/"):
        return _decrypt_crypt1to4(1, path.removeprefix("crypt2/"))
    if path.startswith("crypt/"):
        return _decrypt_crypt1to4(0, path.removeprefix("crypt/"))

    raise ValueError(f"Unknown link format: {link}")


def decrypt_text(text: str) -> str:
    """Replace all happ:// links in text with their decrypted URLs."""

    def _replace(m: re.Match) -> str:
        try:
            return decrypt_link(m.group(0))
        except Exception as e:
            logger.warning("Failed to decrypt %s: %s", m.group(0)[:40], e)
            return m.group(0)

    return HAPP_RE.sub(_replace, text)


def is_happ(text: str) -> bool:
    """Check if text contains happ:// links."""
    return bool(HAPP_RE.search(text))
