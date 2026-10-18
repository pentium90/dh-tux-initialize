"""Dahua initialization encryption primitives.

This module has no network or UI dependencies.  It parses the key/capability
response and builds the ``salt`` / ``cipher`` / ``content`` envelope used by
sessionless initialization RPC methods.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


IV = b"0000000000000000"
AES_BLOCK_SIZE = 16


class CryptoProtocolError(ValueError):
    """The device did not advertise a supported initialization crypto profile."""


@dataclass(frozen=True, repr=False)
class EncryptionProfile:
    """Validated crypto settings advertised by one device."""

    asymmetric: str
    cipher: str
    cipher_name: str
    security_baseline_version: str | None
    session_key_bytes: int
    rsa_public_key: rsa.RSAPublicKey = field(repr=False, compare=False)
    rsa_modulus_bits: int
    rsa_exponent: int
    advertised_ciphers: tuple[str, ...]
    advertised_padding: tuple[str, ...]

    @property
    def rsa_modulus_bytes(self) -> int:
        return (self.rsa_modulus_bits + 7) // 8

    @property
    def rsa_salt_bytes(self) -> int:
        """Length of the RSA-encrypted session key carried in the salt field."""
        return self.rsa_modulus_bytes

    @property
    def aes_key_bits(self) -> int:
        return self.session_key_bytes * 8

    def __repr__(self) -> str:
        return (
            "EncryptionProfile("
            f"asymmetric={self.asymmetric!r}, cipher={self.cipher!r}, "
            f"cipher_name={self.cipher_name!r}, "
            f"security_baseline_version={self.security_baseline_version!r}, "
            f"session_key_bytes={self.session_key_bytes}, "
            f"rsa_modulus_bits={self.rsa_modulus_bits}, "
            f"rsa_exponent={self.rsa_exponent}, "
            f"advertised_ciphers={self.advertised_ciphers!r}, "
            f"advertised_padding={self.advertised_padding!r}, "
            "rsa_public_key=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class EncryptedParameters:
    """Wire-safe encrypted fields; its representation contains no plaintext."""

    salt: str
    cipher: str
    content: str

    def as_dict(self) -> dict[str, str]:
        return {"salt": self.salt, "cipher": self.cipher, "content": self.content}

    def __repr__(self) -> str:
        return (
            "EncryptedParameters("
            f"salt=<hex:{len(self.salt)} chars>, cipher={self.cipher!r}, "
            f"content=<base64:{len(self.content)} chars>)"
        )


def parse_security_encrypt_info(
    response: Mapping[str, Any],
    dev_caps: Mapping[str, Any] | None = None,
    status: Mapping[str, Any] | None = None,
) -> EncryptionProfile:
    """Parse ``Security.getEncryptInfo`` and the matching DevInit capabilities.

    Dahua's web client recognizes the wire cipher values ``AES-128``,
    ``ROAE-256`` and ``RPAC-256``.  ``AES`` is the legacy capability spelling;
    an advertised baseline/key length resolves its key size, and inconsistent
    or ambiguous capability combinations are rejected. Explicit AES-256 is
    also accepted when the device advertises that exact capability.
    """
    params = _response_params(response, "Security.getEncryptInfo")
    if _result_is_false(response, params):
        raise CryptoProtocolError("Security.getEncryptInfo reported failure")

    asymmetric = params.get("asymmetric")
    if not isinstance(asymmetric, str) or asymmetric.upper() != "RSA":
        raise CryptoProtocolError("unsupported asymmetric encryption scheme")

    public_key = _parse_rsa_public_key(params.get("pub"))
    advertised_ciphers = _string_list(params.get("cipher"), "cipher")
    cipher, cipher_key_bytes = _select_cipher(advertised_ciphers)

    baselines = _find_values((params, dev_caps, status), _BASELINE_KEYS)
    baseline = _one_consistent_string(baselines, "SecurityBaselineVersion")
    baseline_key_bytes = _key_bytes_for_baseline(baseline) if baseline is not None else None

    advertised_key_bytes = _advertised_key_length((params, dev_caps, status))
    explicit_lengths = [length for length in (cipher_key_bytes, advertised_key_bytes) if length]
    if explicit_lengths and len(set(explicit_lengths)) != 1:
        raise CryptoProtocolError("conflicting advertised AES key lengths")
    explicit_length = explicit_lengths[0] if explicit_lengths else None

    if baseline_key_bytes is not None and explicit_length is not None:
        if baseline_key_bytes != explicit_length:
            raise CryptoProtocolError("AES key length conflicts with security baseline")
        session_key_bytes = baseline_key_bytes
    elif explicit_length is not None:
        session_key_bytes = explicit_length
    elif baseline_key_bytes is not None:
        session_key_bytes = baseline_key_bytes
    else:
        raise CryptoProtocolError("device did not advertise a usable AES key length or baseline")

    if session_key_bytes == 16 and cipher not in {"AES-128", "AES"}:
        raise CryptoProtocolError("advertised cipher requires a 32-byte AES key")
    if session_key_bytes == 32 and cipher in {"AES-128", "AES"}:
        raise CryptoProtocolError("advertised AES-128 cipher conflicts with the 32-byte key profile")
    if cipher == "AES":
        # The AES token is the legacy spelling. It maps to AES-128 only when
        # the key length is actually 16 bytes; it never silently becomes 256.
        cipher = "AES-128"
    cipher_name = f"AES-{session_key_bytes * 8}-CBC"

    padding_values = _string_list(params.get("AESPadding"), "AESPadding", optional=True)
    if padding_values:
        supported_padding = {_normalize(item) for item in padding_values}
        if not supported_padding.intersection({"zero", "zeropad", "zeropadding"}):
            raise CryptoProtocolError("device does not advertise zero padding")
    else:
        # The documented DevInit envelope uses zero-padded JSON.  Several
        # versions omit AESPadding from getEncryptInfo entirely.
        padding_values = ("ZeroPadding (protocol default)",)

    return EncryptionProfile(
        asymmetric="RSA",
        cipher=cipher,
        cipher_name=cipher_name,
        security_baseline_version=baseline,
        session_key_bytes=session_key_bytes,
        rsa_public_key=public_key,
        rsa_modulus_bits=public_key.key_size,
        rsa_exponent=public_key.public_numbers().e,
        advertised_ciphers=advertised_ciphers,
        advertised_padding=tuple(padding_values),
    )


def describe_security_encrypt_info(
    response: Mapping[str, Any],
    dev_caps: Mapping[str, Any] | None = None,
    status: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract useful, secret-safe crypto details even for unsupported profiles."""
    summary: dict[str, Any] = {}
    try:
        params = _response_params(response, "Security.getEncryptInfo")
    except CryptoProtocolError:
        return summary

    asymmetric = params.get("asymmetric")
    if isinstance(asymmetric, str):
        summary["asymmetric"] = asymmetric

    ciphers: tuple[str, ...] = ()
    try:
        ciphers = _string_list(params.get("cipher"), "cipher")
        summary["advertised_ciphers"] = list(ciphers)
        summary["device_cipher"] = _select_cipher(ciphers)[0]
    except CryptoProtocolError:
        pass

    baselines = [
        value for value in _find_values((params, dev_caps, status), _BASELINE_KEYS)
        if value is not None
    ]
    baseline_bytes = None
    if len(baselines) == 1 and isinstance(baselines[0], str):
        baseline = baselines[0].strip()
        summary["security_baseline_version"] = baseline
        try:
            baseline_bytes = _key_bytes_for_baseline(baseline)
        except CryptoProtocolError:
            pass

    try:
        advertised_bytes = _advertised_key_length((params, dev_caps, status))
    except CryptoProtocolError:
        advertised_bytes = None
    try:
        cipher_bytes = _select_cipher(ciphers)[1] if ciphers else None
    except CryptoProtocolError:
        cipher_bytes = None
    lengths = {value for value in (baseline_bytes, advertised_bytes, cipher_bytes) if value is not None}
    if len(lengths) == 1:
        summary["session_key_length_bytes"] = next(iter(lengths))

    try:
        public_key = _parse_rsa_public_key(params.get("pub"))
    except CryptoProtocolError:
        pass
    else:
        modulus_bytes = (public_key.key_size + 7) // 8
        summary.update(
            rsa_modulus_bits=public_key.key_size,
            rsa_modulus_bytes=modulus_bytes,
            rsa_exponent=public_key.public_numbers().e,
            rsa_encrypted_salt_length_bytes=modulus_bytes,
        )
    return summary


def encrypt_json_content(
    payload: Mapping[str, Any],
    *,
    key: bytes,
    cipher_name: str,
) -> str:
    """Compact-JSON encode, zero-pad, AES-CBC encrypt, and Base64 encode."""
    if not isinstance(payload, Mapping):
        raise CryptoProtocolError("encrypted content must be a JSON object")
    try:
        wire_mapping = dict(payload.items())
        plaintext = json.dumps(
            wire_mapping,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise CryptoProtocolError("encrypted content is not valid JSON") from None
    return encrypt_content(plaintext, key=key, cipher_name=cipher_name)


def encrypt_content(plaintext: bytes, *, key: bytes, cipher_name: str) -> str:
    """Encrypt already-encoded bytes with the protocol's fixed IV and padding."""
    if cipher_name not in {"AES-128-CBC", "AES-256-CBC"}:
        raise CryptoProtocolError("unsupported AES-CBC variant")
    expected_bytes = 16 if cipher_name == "AES-128-CBC" else 32
    if len(key) != expected_bytes:
        raise CryptoProtocolError("session key length does not match cipher")
    if not isinstance(plaintext, bytes):
        raise CryptoProtocolError("encrypted content must be bytes")

    padded = plaintext + (b"\x00" * (-len(plaintext) % AES_BLOCK_SIZE))
    encryptor = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode("ascii")


def encrypt_parameters(
    payload: Mapping[str, Any],
    profile: EncryptionProfile,
    *,
    random_key: str | bytes | None = None,
    random_digits: Callable[[int], str] | None = None,
    rsa_encryptor: Callable[[rsa.RSAPublicKey, bytes], bytes] | None = None,
) -> EncryptedParameters:
    """Build the encrypted ``salt`` / ``cipher`` / ``content`` DevInit fields.

    ``random_key`` and ``rsa_encryptor`` are injectable so the AES wire vector
    and outer request builder can be tested without a camera.
    """
    key = _make_session_key(profile, random_key=random_key, random_digits=random_digits)
    encrypt_rsa = rsa_encryptor or (
        lambda public_key, clear_key: public_key.encrypt(clear_key, padding.PKCS1v15())
    )
    try:
        encrypted_key = encrypt_rsa(profile.rsa_public_key, key)
    except Exception:
        raise CryptoProtocolError("RSA session-key encryption failed") from None
    content = encrypt_json_content(payload, key=key, cipher_name=profile.cipher_name)
    return EncryptedParameters(
        # Dahua's DevInit envelope carries RSA ciphertext as uppercase hex.
        salt=encrypted_key.hex().upper(),
        cipher=profile.cipher,
        content=content,
    )


_BASELINE_KEYS = {
    "securitybaselineversion",
    "securitybaseline",
}
_KEY_LENGTH_KEYS = {
    "aeskeylength",
    "aeskeysize",
    "sessionkeylength",
    "sessionkeysize",
    "encryptkeylength",
    "encryptkeysize",
    "keylength",
    "keysize",
    "keylen",
}


def _response_params(response: Mapping[str, Any], method: str) -> Mapping[str, Any]:
    if not isinstance(response, Mapping):
        raise CryptoProtocolError(f"{method} response must be an object")
    params = response.get("params")
    if isinstance(params, Mapping):
        return params
    if "pub" in response or "asymmetric" in response:
        return response
    raise CryptoProtocolError(f"{method} response has no params object")


def _result_is_false(response: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    return response.get("result") is False or params.get("result") is False


def _parse_rsa_public_key(value: Any) -> rsa.RSAPublicKey:
    if isinstance(value, Mapping):
        modulus = value.get("N", value.get("n"))
        exponent = value.get("E", value.get("e"))
        if modulus is None or exponent is None:
            raise CryptoProtocolError("RSA public key is incomplete")
        n = _parse_key_component(modulus)
        e = _parse_key_component(exponent)
        return _rsa_key_from_numbers(n, e)

    if not isinstance(value, str) or not value.strip():
        raise CryptoProtocolError("RSA public key is missing")
    text = value.strip()
    if "-----BEGIN" in text:
        try:
            key = serialization.load_pem_public_key(text.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError):
            raise CryptoProtocolError("RSA public key is malformed") from None
        if not isinstance(key, rsa.RSAPublicKey):
            raise CryptoProtocolError("public key is not RSA")
        return key

    if re.search(r"(?:^|,)\s*N\s*:", text, flags=re.IGNORECASE):
        values: dict[str, str] = {}
        for component in text.split(","):
            if ":" not in component:
                raise CryptoProtocolError("RSA public key is malformed")
            name, number = component.split(":", 1)
            values[name.strip().casefold()] = number.strip()
        if not values.get("n") or not values.get("e"):
            raise CryptoProtocolError("RSA public key is incomplete")
        return _rsa_key_from_numbers(_parse_integer(values["n"], radix=16), _parse_integer(values["e"], radix=16))

    try:
        der = base64.b64decode(text, validate=True)
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError):
        raise CryptoProtocolError("RSA public key is malformed") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoProtocolError("public key is not RSA")
    return key


def _rsa_key_from_numbers(n: int, e: int) -> rsa.RSAPublicKey:
    try:
        return rsa.RSAPublicNumbers(e=e, n=n).public_key()
    except (ValueError, TypeError):
        raise CryptoProtocolError("RSA public key numbers are invalid") from None


def _parse_integer(value: Any, *, radix: int | None = None) -> int:
    if isinstance(value, bool):
        raise CryptoProtocolError("RSA public key numbers are invalid")
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value:
        raise CryptoProtocolError("RSA public key numbers are invalid")
    try:
        return int(value, radix or (16 if value.casefold().startswith("0x") else 10))
    except ValueError:
        raise CryptoProtocolError("RSA public key numbers are invalid") from None


def _parse_key_component(value: Any) -> int:
    if isinstance(value, str) and not value.casefold().startswith("0x"):
        return _parse_integer(value, radix=16)
    return _parse_integer(value)


def _select_cipher(values: Sequence[str]) -> tuple[str, int | None]:
    explicit: dict[str, int] = {}
    has_legacy_aes = False
    for value in values:
        normalized = _normalize(value)
        if normalized == "aes":
            has_legacy_aes = True
        elif normalized in {"aes128", "aes128cbc"}:
            explicit["AES-128"] = 16
        elif normalized in {"aes256", "aes256cbc"}:
            explicit["AES-256"] = 32
        elif normalized in {"roae", "roae256"}:
            explicit["ROAE-256"] = 32
        elif normalized in {"rpac", "rpac256"}:
            explicit["RPAC-256"] = 32
        else:
            continue

    # This follows Dahua's client cipher selection: ROAE takes precedence over
    # RPAC, with AES as the legacy fallback. A single capability response may
    # expose more than one supported option.
    for candidate in ("ROAE-256", "RPAC-256", "AES-256", "AES-128"):
        if candidate in explicit:
            return candidate, explicit[candidate]
    if has_legacy_aes:
        return "AES", None
    if not explicit:
        raise CryptoProtocolError("device does not advertise a supported AES cipher")
    raise CryptoProtocolError("device does not advertise a supported AES cipher")


def _string_list(value: Any, field_name: str, *, optional: bool = False) -> tuple[str, ...]:
    if value is None and optional:
        return ()
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = tuple(value)
    else:
        raise CryptoProtocolError(f"{field_name} capability is malformed")
    if not values or any(not isinstance(item, str) or not item for item in values):
        raise CryptoProtocolError(f"{field_name} capability is malformed")
    return tuple(values)


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _find_values(roots: Sequence[Any] | None, keys: set[str]) -> list[Any]:
    found: list[Any] = []

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                if isinstance(key, str) and _normalize(key) in keys:
                    found.append(value)
                if isinstance(value, (Mapping, list, tuple)):
                    visit(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for value in node:
                visit(value, depth + 1)

    if roots is not None:
        for root in roots:
            visit(root)
    return found


def _one_consistent_string(values: Sequence[Any], field_name: str) -> str | None:
    values = [value for value in values if value is not None]
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise CryptoProtocolError(f"{field_name} capability is malformed")
    normalized = {value.strip() for value in values}
    if len(normalized) > 1:
        raise CryptoProtocolError(f"conflicting {field_name} values")
    if values and not normalized:
        raise CryptoProtocolError(f"{field_name} capability is malformed")
    return next(iter(normalized), None)


def _key_bytes_for_baseline(version: str | None) -> int | None:
    if version is None:
        return None
    match = re.fullmatch(r"\s*[vV]?\s*(\d+)\.(\d+)(?:\.\d+)*\s*", version)
    if match is None:
        raise CryptoProtocolError("SecurityBaselineVersion is malformed")
    baseline = (int(match.group(1)), int(match.group(2)))
    return 32 if baseline >= (2, 0) else 16


def _advertised_key_length(roots: Sequence[Any]) -> int | None:
    values = _find_values(roots, _KEY_LENGTH_KEYS)
    parsed: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise CryptoProtocolError("advertised AES key length is malformed")
        try:
            number = int(value)
        except ValueError:
            raise CryptoProtocolError("advertised AES key length is malformed") from None
        if number in (16, 32):
            parsed.add(number)
        elif number in (128, 256):
            parsed.add(number // 8)
        else:
            raise CryptoProtocolError("unsupported advertised AES key length")
    if len(parsed) > 1:
        raise CryptoProtocolError("conflicting advertised AES key lengths")
    return next(iter(parsed), None)


def _make_session_key(
    profile: EncryptionProfile,
    *,
    random_key: str | bytes | None,
    random_digits: Callable[[int], str] | None,
) -> bytes:
    length = profile.session_key_bytes
    if random_key is None:
        generator = random_digits or (lambda count: "".join(secrets.choice("0123456789") for _ in range(count)))
        try:
            candidate = generator(length)
        except Exception:
            raise CryptoProtocolError("session key generation failed") from None
        if not isinstance(candidate, str):
            raise CryptoProtocolError("session key generator returned invalid data")
        try:
            key = candidate.encode("ascii")
        except UnicodeEncodeError:
            raise CryptoProtocolError("session key must contain ASCII digits") from None
    elif isinstance(random_key, str):
        try:
            key = random_key.encode("ascii")
        except UnicodeEncodeError:
            raise CryptoProtocolError("session key must contain ASCII digits") from None
    elif isinstance(random_key, bytes):
        key = random_key
    else:
        raise CryptoProtocolError("session key has invalid type")

    if len(key) != length or any(byte < 48 or byte > 57 for byte in key):
        raise CryptoProtocolError("session key must be the advertised number of ASCII digits")
    return key
