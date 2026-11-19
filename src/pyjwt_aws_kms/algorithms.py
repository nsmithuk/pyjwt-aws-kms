"""PyJWT algorithms that sign with AWS KMS."""

from __future__ import annotations

from typing import Any, NoReturn, override

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import Algorithm
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

    @override
    def prepare_key(self, key: Any) -> Any:
        if isinstance(key, KMSKey):
            return key
        return self._delegate.prepare_key(key)

    @override
    def sign(self, msg: bytes, key: Any) -> bytes:
        if not isinstance(key, KMSKey):
            return self._delegate.sign(msg, key)

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
        # prepare_key validates the key family (and EC curve) for this algorithm.
        public_key = self._delegate.prepare_key(key.public_key())
        return self._delegate.verify(msg, public_key, sig)

    @staticmethod
    @override
    def to_jwk(key_obj: Any, as_dict: bool = False) -> NoReturn:
        raise NotImplementedError("KMSAlgorithm does not support JWK export")

    @staticmethod
    @override
    def from_jwk(jwk: Any) -> NoReturn:
        raise NotImplementedError("KMSAlgorithm does not support JWK import")


def register_algorithms(jws: jwt.PyJWS | None = None) -> None:
    """Make PyJWT accept :class:`KMSKey` for the asymmetric algorithms.

    Registers over the standard names (RS256, ES256, ...). Each wrapper falls back
    to the algorithm it replaced for non-KMS keys, so existing behaviour is kept.

    :param jws: A ``PyJWS`` instance to register on. Defaults to the global
        registry used by ``jwt.encode`` / ``jwt.decode``.
    """
    register = jws.register_algorithm if jws else jwt.register_algorithm
    unregister = jws.unregister_algorithm if jws else jwt.unregister_algorithm
    lookup = jws.get_algorithm_by_name if jws else jwt.get_algorithm_by_name
    for name, (signing_algorithm, curve) in _SPECS.items():
        existing = lookup(name)
        if isinstance(existing, KMSAlgorithm):
            existing = existing._delegate
        # PyJWT refuses to register over an existing name.
        unregister(name)
        register(name, KMSAlgorithm(existing, signing_algorithm, curve))
