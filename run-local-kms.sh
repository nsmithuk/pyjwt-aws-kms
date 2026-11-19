#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

docker run --rm -p 127.0.0.1:8080:8080 -e KMS_SEED_PATH=/seed.yaml nsmithuk/local-kms:4.0.0-rc.2
