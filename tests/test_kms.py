import hashlib

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from pyjwt_aws_kms import KMSAlgorithm, KMSKey, register_algorithms

from .fake_kms import FakeKMS

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

CASES = [
    ("RS256", lambda: RSA_KEY, "sha256"),
    ("RS384", lambda: RSA_KEY, "sha384"),
    ("RS512", lambda: RSA_KEY, "sha512"),
    ("PS256", lambda: RSA_KEY, "sha256"),
    ("PS384", lambda: RSA_KEY, "sha384"),
    ("PS512", lambda: RSA_KEY, "sha512"),
    ("ES256", lambda: ec.generate_private_key(ec.SECP256R1()), "sha256"),
    ("ES384", lambda: ec.generate_private_key(ec.SECP384R1()), "sha384"),
    ("ES512", lambda: ec.generate_private_key(ec.SECP521R1()), "sha512"),
    ("ES256K", lambda: ec.generate_private_key(ec.SECP256K1()), "sha256"),
    ("EdDSA", lambda: ed25519.Ed25519PrivateKey.generate(), None),
]


@pytest.fixture(autouse=True)
def _registered():
    register_algorithms()


@pytest.fixture
def kms() -> FakeKMS:
    return FakeKMS()


def make_key(kms: FakeKMS, private_key) -> KMSKey:
    return KMSKey(kms.add_key(private_key), kms)  # type: ignore[arg-type]


@pytest.mark.parametrize(("alg", "new_key", "digest"), CASES, ids=[c[0] for c in CASES])
def test_round_trip(kms, alg, new_key, digest):
    key = make_key(kms, new_key())
    token = jwt.encode({"sub": "x"}, key, algorithm=alg, headers={"kid": key.key_id})
    assert jwt.get_unverified_header(token)["kid"] == key.key_id
    assert jwt.decode(token, key, algorithms=[alg]) == {"sub": "x"}


@pytest.mark.parametrize(("alg", "new_key", "digest"), CASES, ids=[c[0] for c in CASES])
def test_digest_computed_locally_except_eddsa(kms, alg, new_key, digest):
    key = make_key(kms, new_key())
    token = jwt.encode({"sub": "x"}, key, algorithm=alg)
    (call,) = kms.sign_calls
    signing_input = token.rsplit(".", 1)[0].encode()
    if digest is None:
        assert call["MessageType"] == "RAW"
        assert call["Message"] == signing_input
    else:
        assert call["MessageType"] == "DIGEST"
        assert call["Message"] == hashlib.new(digest, signing_input).digest()


def test_large_message_has_no_size_limit(kms):
    key = make_key(kms, RSA_KEY)
    payload = {"blob": "x" * 10_000}
    token = jwt.encode(payload, key, algorithm="RS256")
    assert jwt.decode(token, key, algorithms=["RS256"]) == payload


def test_eddsa_oversize_message_rejected(kms):
    key = make_key(kms, ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(ValueError, match="at most 4096"):
        jwt.encode({"blob": "x" * 10_000}, key, algorithm="EdDSA")


def test_tampered_token_rejected(kms):
    key = make_key(kms, ec.generate_private_key(ec.SECP256R1()))
    token = jwt.encode({"sub": "x"}, key, algorithm="ES256")
    header, _, signature = token.split(".")
    forged = jwt.utils.base64url_encode(b'{"sub":"evil"}').decode()
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(f"{header}.{forged}.{signature}", key, algorithms=["ES256"])


def test_wrong_curve_rejected(kms):
    signer = make_key(kms, ec.generate_private_key(ec.SECP384R1()))
    other = make_key(kms, ec.generate_private_key(ec.SECP256R1()))
    token = jwt.encode({"sub": "x"}, signer, algorithm="ES384")
    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(token, other, algorithms=["ES384"])


def test_local_keys_still_work():
    private = ec.generate_private_key(ec.SECP256R1())
    token = jwt.encode({"a": 1}, private, algorithm="ES256")
    assert jwt.decode(token, private.public_key(), algorithms=["ES256"]) == {"a": 1}


def test_public_key_cached(kms):
    key = make_key(kms, RSA_KEY)
    assert key.public_key() is key.public_key()


def test_register_is_idempotent():
    register_algorithms()
    register_algorithms()
    algorithm = jwt.get_algorithm_by_name("RS256")
    assert isinstance(algorithm, KMSAlgorithm)
    assert not isinstance(algorithm._delegate, KMSAlgorithm)


# --- Regression tests -------------------------------------------------------

WEAK_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=1024)


def test_minimum_key_length_still_enforced_for_local_keys():
    jws = jwt.PyJWS(options={"enforce_minimum_key_length": True})
    register_algorithms(jws)
    with pytest.raises(jwt.InvalidKeyError, match="1024 bits"):
        jws.encode(b"{}", WEAK_RSA_KEY, algorithm="RS256")


def test_minimum_key_length_warns_for_local_keys():
    with pytest.warns(jwt.warnings.InsecureKeyLengthWarning):
        jwt.encode({}, WEAK_RSA_KEY, algorithm="RS256")


def test_minimum_key_length_enforced_for_kms_keys(kms):
    jws = jwt.PyJWS(options={"enforce_minimum_key_length": True})
    register_algorithms(jws)
    with pytest.raises(jwt.InvalidKeyError, match="1024 bits"):
        jws.encode(b"{}", make_key(kms, WEAK_RSA_KEY), algorithm="RS256")
    assert kms.sign_calls == []


@pytest.mark.parametrize(
    ("alg", "new_key"),
    [
        # KMS itself would accept these two: both use ECDSA_SHA_256.
        ("ES256", lambda: ec.generate_private_key(ec.SECP256K1())),
        ("ES256K", lambda: ec.generate_private_key(ec.SECP256R1())),
        ("RS256", lambda: ec.generate_private_key(ec.SECP256R1())),
        ("ES256", lambda: RSA_KEY),
        ("EdDSA", lambda: RSA_KEY),
    ],
)
def test_sign_rejects_key_that_does_not_match_alg(kms, alg, new_key):
    key = make_key(kms, new_key())
    with pytest.raises(jwt.InvalidKeyError):
        jwt.encode({"sub": "x"}, key, algorithm=alg)
    assert kms.sign_calls == []


def test_verify_with_wrong_key_family_raises_invalid_key(kms):
    token = jwt.encode({"sub": "x"}, make_key(kms, RSA_KEY), algorithm="RS256")
    ec_key = make_key(kms, ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(token, ec_key, algorithms=["RS256"])


@pytest.mark.parametrize(
    ("alg", "public_key"),
    [
        ("RS256", RSA_KEY.public_key()),
        ("ES256", ec.generate_private_key(ec.SECP256R1()).public_key()),
        ("EdDSA", ed25519.Ed25519PrivateKey.generate().public_key()),
    ],
)
def test_jwk_round_trip_through_registry_for_local_keys(alg, public_key):
    algorithm = jwt.get_algorithm_by_name(alg)
    assert isinstance(algorithm, KMSAlgorithm)
    jwk = algorithm.to_jwk(public_key, as_dict=True)
    assert isinstance(jwk, dict)
    assert algorithm.to_jwk(algorithm.from_jwk(jwk), as_dict=True) == jwk
    assert isinstance(algorithm.to_jwk(public_key), str)


def test_jwk_export_of_kms_key_not_supported(kms):
    with pytest.raises(NotImplementedError):
        jwt.get_algorithm_by_name("RS256").to_jwk(make_key(kms, RSA_KEY))


def test_register_on_restricted_instance_skips_disabled_algorithms(kms):
    jws = jwt.PyJWS(algorithms=["ES256"])
    register_algorithms(jws)
    assert jws.get_algorithms() == ["ES256"]
    assert isinstance(jws.get_algorithm_by_name("ES256"), KMSAlgorithm)
    key = make_key(kms, ec.generate_private_key(ec.SECP256R1()))
    token = jws.encode(b'{"sub":"x"}', key, algorithm="ES256")
    assert jws.decode(token, key, algorithms=["ES256"]) == b'{"sub":"x"}'


def test_register_keeps_every_name_registered():
    before = set(jwt.api_jws._jws_global_obj.get_algorithms())
    register_algorithms()
    assert set(jwt.api_jws._jws_global_obj.get_algorithms()) == before
