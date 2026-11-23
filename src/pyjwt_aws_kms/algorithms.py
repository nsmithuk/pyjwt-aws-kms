"""PyJWT algorithms that sign with AWS KMS."""

from __future__ import annotations

from typing import Any, override

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import Algorithm
from jwt.exceptions import InvalidKeyError
from jwt.utils import der_to_raw_signature

from .key import KMSKey

# JWT alg -> (KMS SigningAlgorithm, EC curve for DER -> raw r||s conversion)
_SPECS: dict[str, tuple[str, type[ec.EllipticCurve] | None]] = {
    "RS256": ("RSASSA_PKCS1_V1_5_SHA_256", None),
    "RS384": ("RSASSA_PKCS1_V1_5_SHA_384", None),
    "RS512": ("RSASSA_PKCS1_V1_5_SHA_512", None),
    "PS256": ("RSASSA_PSS_SHA_256", None),
    "PS384": ("RSASSA_PSS_SHA_384", None),
    "PS512": ("RSASSA_PSS_SHA_512", None),
    "ES256": ("ECDSA_SHA_256", ec.SECP256R1),
    "ES384": ("ECDSA_SHA_384", ec.SECP384R1),
    "ES512": ("ECDSA_SHA_512", ec.SECP521R1),
    "ES256K": ("ECDSA_SHA_256", ec.SECP256K1),
    "EdDSA": ("ED25519_SHA_512", None),
}
# Ed25519 is the only algorithm here without a KMS DIGEST mode, so it is sent RAW.
# Everything else is hashed locally and sent as DIGEST.
_RAW_MESSAGE_ALGORITHMS = {"ED25519_SHA_512"}
# KMS limit for MessageType=RAW.
_MAX_RAW_MESSAGE_BYTES = 4096


class KMSAlgorithm(Algorithm):
    """Signs with KMS when given a :class:`KMSKey`; otherwise behaves like ``delegate``.

    Verification with a :class:`KMSKey` uses the key's cached public key locally,
    so no KMS call (or cost) is made per verification.
    """

    def __init__(
        self,
        delegate: Algorithm,
        signing_algorithm: str,
        curve: type[ec.EllipticCurve] | None = None,
    ) -> None:
        self._delegate = delegate
        self.signing_algorithm = signing_algorithm
        self._curve = curve

    def _checked_public_key(self, key: KMSKey) -> Any:
        """The KMS key's public half, validated for this algorithm.

        The delegate's ``prepare_key`` checks the key family and (for ECDSA) the
        curve, raising :class:`jwt.InvalidKeyError` on a mismatch.
        """
        try:
            return self._delegate.prepare_key(key.public_key())
        except TypeError as e:
            # Delegates raise TypeError for a cryptography key of the wrong family.
            raise InvalidKeyError(
                f"{key!r} has the wrong key type for this algorithm"
            ) from e

    @override
    def prepare_key(self, key: Any) -> Any:
        if isinstance(key, KMSKey):
            return key
        return self._delegate.prepare_key(key)

    @override
    def check_key_length(self, key: Any) -> str | None:
        if isinstance(key, KMSKey):
            return self._delegate.check_key_length(self._checked_public_key(key))
        return self._delegate.check_key_length(key)

    @override
    def sign(self, msg: bytes, key: Any) -> bytes:
        if not isinstance(key, KMSKey):
            return self._delegate.sign(msg, key)

        # KMS does not catch every mismatch (ES256 and ES256K share ECDSA_SHA_256),
        # so check the key locally before signing. The public key is cached.
        self._checked_public_key(key)

        if self.signing_algorithm in _RAW_MESSAGE_ALGORITHMS:
            if len(msg) > _MAX_RAW_MESSAGE_BYTES:
                raise ValueError(
                    f"{self.signing_algorithm} can sign at most "
                    f"{_MAX_RAW_MESSAGE_BYTES} bytes in KMS; got {len(msg)}"
                )
            message, message_type = msg, "RAW"
        else:
            # Hash locally: no size limit, and the message never leaves the process.
            message, message_type = self._delegate.compute_hash_digest(msg), "DIGEST"

        response = key.client.sign(
            KeyId=key.key_id,
            Message=message,
            MessageType=message_type,  # type: ignore[arg-type]
            SigningAlgorithm=self.signing_algorithm,  # type: ignore[arg-type]
        )
        signature = response["Signature"]
        if self._curve is not None:
            # KMS returns DER; JWS requires fixed-width r || s.
            return der_to_raw_signature(signature, self._curve())
        return signature

    @override
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        if not isinstance(key, KMSKey):
            return self._delegate.verify(msg, key, sig)
        return self._delegate.verify(msg, self._checked_public_key(key), sig)

    # Instance methods rather than static ones, so JWK import/export keeps working
    # for non-KMS keys through the registry (jwt.get_algorithm_by_name(...)).
    @override
    def to_jwk(self, key_obj: Any, as_dict: bool = False) -> Any:  # type: ignore[override]
        if isinstance(key_obj, KMSKey):
            raise NotImplementedError(
                "KMSAlgorithm does not support JWK export of a KMSKey; "
                "export key.public_key() instead"
            )
        if as_dict:
            return self._delegate.to_jwk(key_obj, as_dict=True)
        return self._delegate.to_jwk(key_obj, as_dict=False)

    @override
    def from_jwk(self, jwk: Any) -> Any:  # type: ignore[override]
        return self._delegate.from_jwk(jwk)


def _registry(jws: jwt.PyJWS | None) -> dict[str, Algorithm]:
    # PyJWT has no public "replace" operation; unregister + register would leave a
    # window in which the name is missing for other threads. Swapping the dict
    # entry is a single atomic assignment.
    target = jws if jws is not None else jwt.api_jws._jws_global_obj
    return target._algorithms


def register_algorithms(jws: jwt.PyJWS | None = None) -> None:
    """Make PyJWT accept :class:`KMSKey` for the asymmetric algorithms.

    Registers over the standard names (RS256, ES256, ...). Each wrapper falls back
    to the algorithm it replaced for non-KMS keys, so existing behaviour is kept.
    Names not enabled on ``jws`` (e.g. ``PyJWS(algorithms=[...])``) are skipped.

    :param jws: A ``PyJWS`` instance to register on. Defaults to the global
        registry used by ``jwt.encode`` / ``jwt.decode``.
    """
    algorithms = _registry(jws)
    for name, (signing_algorithm, curve) in _SPECS.items():
        existing = algorithms.get(name)
        if existing is None:
            continue
        if isinstance(existing, KMSAlgorithm):
            existing = existing._delegate
        algorithms[name] = KMSAlgorithm(existing, signing_algorithm, curve)
