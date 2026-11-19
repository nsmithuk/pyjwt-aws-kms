"""Functional tests against a running Local KMS (the keys are seeded into its image).

Start it with ``./run-local-kms.sh``. Override the endpoint with LOCAL_KMS_ENDPOINT.
The tests are skipped when nothing is listening.

Set REAL_KMS=true to run the same tests against real AWS KMS instead (region from
AWS_REGION / AWS_DEFAULT_REGION, default eu-west-2; credentials from the usual boto3
chain). The aliases below must exist there. Needs kms:DescribeKey, kms:GetPublicKey
and kms:Sign on them.

Tokens are verified two ways: through this library (cached KMS public key) and
independently with a plain ``cryptography`` public key, so a wrong signature
encoding (DER vs r||s, PSS salt length, ...) can't pass by agreeing with itself.
"""

from __future__ import annotations

import os

import boto3
import jwt
import pytest
from botocore.config import Config
from botocore.exceptions import EndpointConnectionError, NoCredentialsError
from cryptography.hazmat.primitives.serialization import load_der_public_key

from pyjwt_aws_kms import KMSKey, register_algorithms

pytestmark = pytest.mark.integration

REAL_KMS = os.environ.get("REAL_KMS", "").lower() in ("1", "true", "yes")
ENDPOINT = os.environ.get("LOCAL_KMS_ENDPOINT", "http://localhost:8080")
REGION = (
    os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "eu-west-2"
)

# JWT alg -> seeded alias
CASES = {
    "RS256": "alias/seed_rsa_2048_sign_verify",
    "RS384": "alias/seed_rsa_3072_sign_verify",
    "RS512": "alias/seed_rsa_4096_sign_verify",
    "PS256": "alias/seed_rsa_2048_sign_verify",
    "PS384": "alias/seed_rsa_3072_sign_verify",
    "PS512": "alias/seed_rsa_4096_sign_verify",
    "ES256": "alias/seed_ecc_nist_p256_sign_verify",
    "ES384": "alias/seed_ecc_nist_p384_sign_verify",
    "ES512": "alias/seed_ecc_nist_p521_sign_verify",
    "ES256K": "alias/seed_ecc_secg_p256k1_sign_verify",
    "EdDSA": "alias/seed_ecc_nist_edwards25519_sign_verify",
}


@pytest.fixture(scope="module")
def client():
    config = Config(retries={"max_attempts": 1}, connect_timeout=5)
    if REAL_KMS:
        # Real AWS: standard credential chain (env vars, profile, SSO, ...).
        kms = boto3.client("kms", region_name=REGION, config=config)
    else:
        kms = boto3.client(
            "kms",
            endpoint_url=ENDPOINT,
            region_name=REGION,
            aws_access_key_id="local",
            aws_secret_access_key="local",
            config=config,
        )
    try:
        kms.describe_key(KeyId=CASES["ES256"])
    except EndpointConnectionError:
        pytest.skip(f"Local KMS not reachable at {ENDPOINT} (run run-local-kms.sh)")
    except NoCredentialsError:
        pytest.skip("REAL_KMS set but no AWS credentials were found")
    return kms


@pytest.fixture(autouse=True)
def _registered():
    register_algorithms()


@pytest.mark.parametrize("alg", CASES)
def test_sign_and_verify(client, alg):
    key = KMSKey(CASES[alg], client)
    payload = {"sub": "functional-test", "alg": alg}

    token = jwt.encode(payload, key, algorithm=alg)

    # Through the library: public key fetched from KMS and cached.
    assert jwt.decode(token, key, algorithms=[alg]) == payload

    # Independently: a plain cryptography key, no KMS wrapper involved.
    public = load_der_public_key(client.get_public_key(KeyId=CASES[alg])["PublicKey"])
    assert jwt.decode(token, public, algorithms=[alg]) == payload  # type: ignore[arg-type]


@pytest.mark.parametrize("alg", [a for a in CASES if a != "EdDSA"])
def test_large_payload_is_signed_via_digest(client, alg):
    """Over KMS's 4096-byte RAW limit, so only works because we send a digest."""
    key = KMSKey(CASES[alg], client)
    payload = {"blob": "x" * 10_000}
    token = jwt.encode(payload, key, algorithm=alg)
    assert jwt.decode(token, key, algorithms=[alg]) == payload


def test_eddsa_oversize_payload_rejected(client):
    key = KMSKey(CASES["EdDSA"], client)
    with pytest.raises(ValueError, match="at most 4096"):
        jwt.encode({"blob": "x" * 10_000}, key, algorithm="EdDSA")


def test_tampered_token_rejected(client):
    key = KMSKey(CASES["ES256"], client)
    token = jwt.encode({"sub": "x"}, key, algorithm="ES256")
    header, _, signature = token.split(".")
    forged = jwt.utils.base64url_encode(b'{"sub":"evil"}').decode()
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(f"{header}.{forged}.{signature}", key, algorithms=["ES256"])


def test_key_resolved_by_alias_and_by_key_id_agree(client):
    alias = CASES["ES256"]
    key_id = client.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
    token = jwt.encode({"sub": "x"}, KMSKey(alias, client), algorithm="ES256")
    assert jwt.decode(token, KMSKey(key_id, client), algorithms=["ES256"]) == {
        "sub": "x"
    }
