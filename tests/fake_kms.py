"""A minimal in-process stand-in for the KMS client, backed by real keys.

moto does not implement MessageType=DIGEST and signs RSA-PSS with a non-JWS salt
length, so it cannot validate what this library sends. This fake follows KMS's
documented behaviour for the operations we use.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_MAX_RAW_BYTES = 4096


class FakeKMS:
    def __init__(self) -> None:
        self._keys: dict[str, Any] = {}
        self.sign_calls: list[dict[str, Any]] = []

    def add_key(self, private_key: Any) -> str:
        key_id = f"key-{len(self._keys)}"
        self._keys[key_id] = private_key
        return key_id

    def get_public_key(self, KeyId: str) -> dict[str, bytes]:
        der = (
            self._keys[KeyId]
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return {"PublicKey": der}

    def sign(
        self, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str
    ) -> dict[str, bytes]:
        self.sign_calls.append(
            {"Message": Message, "MessageType": MessageType, "Alg": SigningAlgorithm}
        )
        key = self._keys[KeyId]

        if SigningAlgorithm == "ED25519_SHA_512":
            assert isinstance(key, ed25519.Ed25519PrivateKey)
            assert MessageType == "RAW", "KMS has no DIGEST mode for Ed25519"
            assert len(Message) <= _MAX_RAW_BYTES
            return {"Signature": key.sign(Message)}

        hash_cls = _HASHES[SigningAlgorithm.rsplit("_", 1)[1]]
        hash_alg = hash_cls()
        if MessageType == "DIGEST":
            assert len(Message) == hash_alg.digest_size, "digest has the wrong length"
            signing_hash: Any = Prehashed(hash_alg)
        else:
            assert len(Message) <= _MAX_RAW_BYTES
            signing_hash = hash_alg

        if SigningAlgorithm.startswith("RSASSA_PKCS1_V1_5"):
            assert isinstance(key, rsa.RSAPrivateKey)
            return {"Signature": key.sign(Message, padding.PKCS1v15(), signing_hash)}
        if SigningAlgorithm.startswith("RSASSA_PSS"):
            assert isinstance(key, rsa.RSAPrivateKey)
            pss = padding.PSS(
                mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size
            )
            return {"Signature": key.sign(Message, pss, signing_hash)}
        if SigningAlgorithm.startswith("ECDSA"):
            assert isinstance(key, ec.EllipticCurvePrivateKey)
            return {"Signature": key.sign(Message, ec.ECDSA(signing_hash))}
        raise AssertionError(f"unsupported signing algorithm {SigningAlgorithm}")
