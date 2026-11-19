"""A reference to an asymmetric AWS KMS key, usable as a PyJWT key."""

from __future__ import annotations

from typing import TYPE_CHECKING

import boto3
from cryptography.hazmat.primitives.serialization import load_der_public_key

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
    from mypy_boto3_kms import KMSClient


class KMSKey:
    """Identifies an asymmetric KMS key and the client used to reach it.

    Pass an instance as the ``key`` argument of ``jwt.encode`` / ``jwt.decode``.

    :param key_id: A key ID, key ARN, alias name or alias ARN.
    :param client: A boto3 KMS client. If omitted, one is created on first use
        with boto3's default configuration.
    """

    def __init__(self, key_id: str, client: KMSClient | None = None) -> None:
        self.key_id = key_id
        self._client = client
        self._public_key: PublicKeyTypes | None = None

    @property
    def client(self) -> KMSClient:
        if self._client is None:
            self._client = boto3.client("kms")
        return self._client

    def public_key(self) -> PublicKeyTypes:
        """The key's public half, fetched once with ``kms:GetPublicKey`` and cached."""
        if self._public_key is None:
            response = self.client.get_public_key(KeyId=self.key_id)
            self._public_key = load_der_public_key(response["PublicKey"])
        return self._public_key

    def __repr__(self) -> str:
        return f"KMSKey(key_id={self.key_id!r})"
