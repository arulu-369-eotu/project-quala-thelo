#!/usr/bin/env bash
set -euo pipefail
# Local test dependency only; never replace the operating system OpenSSL.
test_openssl_root="${1:-$PWD/.test-openssl}"
test_openssl_version="3.5.8"
test_openssl_sha="a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"
mkdir -p "$test_openssl_root"
test_openssl_root="$(cd "$test_openssl_root" && pwd)"
test_openssl_archive="$test_openssl_root/openssl-$test_openssl_version.tar.gz"
curl --fail --silent --show-error --location --retry 2 --max-time 120 \
  "https://github.com/openssl/openssl/releases/download/openssl-$test_openssl_version/openssl-$test_openssl_version.tar.gz" \
  -o "$test_openssl_archive"
python3 - "$test_openssl_archive" "$test_openssl_sha" <<'PY'
import hashlib, pathlib, sys
if hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('OpenSSL source checksum mismatch')
PY
tar -xzf "$test_openssl_archive" -C "$test_openssl_root"
cd "$test_openssl_root/openssl-$test_openssl_version"
./Configure linux-x86_64 shared no-tests
make -j2 build_libs
printf 'Use UQL_OPENSSL_LIBRARY=%s/libcrypto.so.3\n' "$PWD"
