# pyjwt-aws-kms

Sign JSON Web Tokens with [PyJWT](https://pyjwt.readthedocs.io/) using an asymmetric key held in
[AWS KMS](https://aws.amazon.com/kms/). The private key never leaves KMS: your application sends
KMS the data to sign and gets a signature back.

```python
import jwt
from pyjwt_aws_kms import KMSKey, register_algorithms

register_algorithms()

key = KMSKey("alias/my-signing-key")
token = jwt.encode(
    {"sub": "user-123"}, key, algorithm="ES256", headers={"kid": key.key_id}
)
claims = jwt.decode(token, key, algorithms=["ES256"])
```

- Requires Python 3.12+ and PyJWT 2.8+ (with the `cryptography` extra, which is installed for you).
- Signing calls KMS. Verification does not: it uses the key's public half, fetched once and cached.
- Asymmetric algorithms only. HMAC (HS256/384/512) is not supported yet.

## Install

```sh
pip install pyjwt-aws-kms
# or
uv add pyjwt-aws-kms
```

## Usage

### 1. Register the algorithms

Call `register_algorithms()` once at start-up, before you encode or decode:

```python
from pyjwt_aws_kms import register_algorithms

register_algorithms()
```

This extends PyJWT's standard algorithms (`RS256`, `ES256`, ...) so they also accept a KMS key.
Anything else keeps working exactly as before: if you pass a normal key (a PEM string, a
`cryptography` key object, a `PyJWK`), PyJWT handles it as it always did. You can mix KMS and
local keys in the same application.

### 2. Create a `KMSKey`

```python
from pyjwt_aws_kms import KMSKey

key = KMSKey("alias/my-signing-key")
```

The first argument is anything KMS accepts as a `KeyId`: a key ID, a key ARN, an alias name or an
alias ARN.

A `KMSKey` creates a default boto3 KMS client on first use. To control the region, credentials,
retries or endpoint, pass your own:

```python
import boto3

client = boto3.client("kms", region_name="eu-west-2")
key = KMSKey("alias/my-signing-key", client)
```

Reuse one `KMSKey` per KMS key rather than creating one per request, so the cached public key is
reused.

### 3. Sign and verify

Use the key as the `key` argument of `jwt.encode` and `jwt.decode`, with an `algorithm` that
matches the KMS key's type (see below):

```python
token = jwt.encode(
    {"sub": "user-123", "iss": "https://example.com"},
    key,
    algorithm="RS256",
    headers={"kid": key.key_id},
)

claims = jwt.decode(token, key, algorithms=["RS256"], issuer="https://example.com")
```

All the usual PyJWT behaviour (claim validation, `options`, `PyJWT` instances) is unchanged.

`kid` is not set automatically. If you want a key identifier in the header, pass it as above.

### Verifying without KMS

Because KMS keys are asymmetric, anyone with the public key can verify your tokens. They don't need
AWS access or this library. You can fetch the public key once and give it to them (or publish it
yourself, for example in a JWKS endpoint):

```python
public_key = key.public_key()  # a cryptography public key object
jwt.decode(token, public_key, algorithms=["RS256"])
```

## Supported algorithms

The JWT `algorithm` must match the KMS key's key spec:

| JWT `alg`               | KMS key spec                                | KMS signing algorithm                    |
|-------------------------|---------------------------------------------|------------------------------------------|
| `RS256` `RS384` `RS512` | `RSA_2048` / `RSA_3072` / `RSA_4096`        | `RSASSA_PKCS1_V1_5_SHA_256` / `384` / `512` |
| `PS256` `PS384` `PS512` | `RSA_2048` / `RSA_3072` / `RSA_4096`        | `RSASSA_PSS_SHA_256` / `384` / `512`     |
| `ES256`                 | `ECC_NIST_P256`                             | `ECDSA_SHA_256`                          |
| `ES384`                 | `ECC_NIST_P384`                             | `ECDSA_SHA_384`                          |
| `ES512`                 | `ECC_NIST_P521`                             | `ECDSA_SHA_512`                          |
| `ES256K`                | `ECC_SECG_P256K1`                           | `ECDSA_SHA_256`                          |
| `EdDSA`                 | `ECC_NIST_EDWARDS25519`                     | `ED25519_SHA_512`                        |

The KMS key's usage must be `SIGN_VERIFY`. Using an algorithm that doesn't match the key (for
example `ES256` with an RSA key) makes KMS reject the request and boto3 raises its usual
`ClientError`.

Not supported: HMAC (`HS*`), RSA-OAEP / encryption keys, ML-DSA, and JWK import/export through
PyJWT (`PyJWK`) for KMS keys.

## Permissions

The IAM principal needs, on the KMS key:

| To do this | Permission |
|------------|------------|
| Sign (`jwt.encode`) | `kms:Sign` |
| Verify with the `KMSKey` (`jwt.decode`) | `kms:GetPublicKey` (called once per `KMSKey`, then cached) |

Example policy statement:

```json
{
  "Effect": "Allow",
  "Action": ["kms:Sign", "kms:GetPublicKey"],
  "Resource": "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
```

A service that only issues tokens needs just `kms:Sign`. One that only verifies needs just
`kms:GetPublicKey`, or no AWS access at all if you hand it the public key.

IAM resource ARNs refer to the key, not its alias, so use the key ARN in policies even if your
code uses an alias.

## How signing works

- **Hashing is done locally.** For every algorithm except EdDSA, the library hashes the JWT's
  signing input and sends KMS the digest (`MessageType=DIGEST`). KMS therefore never sees your
  token contents, and there is no size limit on the payload.
- **EdDSA** is the exception: KMS has no digest mode for Ed25519, so the raw signing input is sent
  (`MessageType=RAW`). KMS limits that to 4096 bytes, so a larger token raises `ValueError`
  before any request is made.
- **ECDSA** signatures come back from KMS in DER form. They are converted to the fixed-width
  `r || s` form that JWS requires.
- **Verification** is done locally with `cryptography`, using the public key from
  `GetPublicKey`. It does not call KMS's `Verify` API, so it costs nothing and isn't subject to KMS
  request quotas. The key family and (for ECDSA) curve are checked against the algorithm, so a
  token can't be verified with a key of the wrong type.

## Using your own `PyJWT` / `PyJWS` instance

By default `register_algorithms()` registers on PyJWT's global registry, which is what
`jwt.encode` and `jwt.decode` use. To keep it contained, register on a `PyJWS` instance instead:

```python
import jwt
from pyjwt_aws_kms import register_algorithms

jws = jwt.PyJWS()
register_algorithms(jws)

jws.encode(b'{"sub":"x"}', key, algorithm="ES256")
```

Calling `register_algorithms()` more than once is safe.

## Local development against Local KMS

[Local KMS](https://github.com/nsmithuk/local-kms) emulates KMS for development and tests. Point
the boto3 client at it:

```python
client = boto3.client(
    "kms",
    endpoint_url="http://localhost:8080",
    region_name="eu-west-2",
    aws_access_key_id="local",  # any value; Local KMS doesn't check them
    aws_secret_access_key="local",
)
key = KMSKey("alias/seed_ecc_nist_p256_sign_verify", client)
```

> **Note:** use Local KMS 4.0.0-rc.2 or later. Earlier releases signed `PS256`/`PS384`/`PS512` with
> the wrong RSA-PSS salt length, so those tokens failed verification in standard libraries.

## Development

The project uses [uv](https://docs.astral.sh/uv/) and hatchling.

```sh
uv sync                  # create .venv and install dependencies
uv run pytest            # unit tests (+ functional tests if Local KMS is running)
uv run ruff check .
uv run mypy src
```

There are two kinds of test:

- **Unit tests** (`tests/test_kms.py`) use an in-process fake KMS client, so they need nothing
  running.
- **Functional tests** (`tests/test_local_kms.py`) run against a real KMS endpoint and are skipped
  if none is reachable.

To run the functional tests against Local KMS, start it with the seed file, then run pytest:

```sh
./run-local-kms.sh       # needs Docker; listens on 127.0.0.1:8080
uv run pytest tests/test_local_kms.py
```

To run the same tests against real AWS KMS, set `REAL_KMS=true` and provide credentials the usual
way (environment variables, a profile, SSO). The region defaults to `eu-west-2`, or set
`AWS_REGION`:

```sh
REAL_KMS=true uv run pytest tests/test_local_kms.py
```

The aliases listed in `CASES` in `tests/test_local_kms.py` (for example
`alias/seed_rsa_2048_sign_verify`) must exist in that account and region. They match the keys
seeded into the Local KMS image. The identity needs `kms:DescribeKey`, `kms:GetPublicKey` and
`kms:Sign` on them.

## Licence

[MIT](LICENSE)
