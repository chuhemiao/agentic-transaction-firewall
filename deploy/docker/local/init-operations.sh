#!/usr/bin/env bash
set -euo pipefail

authority_dir=/metrics-authority
trust_dir=/metrics-trust
client_dir=/metrics-client
invalid_dir=/metrics-invalid
approved_uri=spiffe://atf.local/metrics-reader
rotate="${ATF_ROTATE_METRICS_PKI:-false}"

if [[ "${rotate}" != "true" && "${rotate}" != "false" ]]; then
  echo "ATF_ROTATE_METRICS_PKI must be true or false" >&2
  exit 2
fi

umask 077

approved_public_key_hash() {
  openssl x509 -in "${client_dir}/client.crt" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | tail -c 32 \
    | openssl dgst -sha256 -r \
    | awk '{print $1}'
}

existing_pki_is_valid() {
  [[ -s "${authority_dir}/client-ca.key" \
    && -s "${authority_dir}/client-ca.crt" \
    && -s "${trust_dir}/client-ca.crt" \
    && -s "${trust_dir}/approved-public-key-sha256" \
    && -s "${client_dir}/client.key" \
    && -s "${client_dir}/client.crt" ]] || return 1
  openssl x509 -checkend 300 -noout -in "${trust_dir}/client-ca.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkend 300 -noout -in "${client_dir}/client.crt" >/dev/null 2>&1 || return 1
  openssl verify -purpose sslclient -CAfile "${trust_dir}/client-ca.crt" \
    "${client_dir}/client.crt" >/dev/null 2>&1 || return 1
  openssl x509 -in "${client_dir}/client.crt" -noout -ext subjectAltName 2>/dev/null \
    | grep -Fq "URI:${approved_uri}" || return 1
  [[ "$(approved_public_key_hash)" == "$(tr -d '\r\n' <"${trust_dir}/approved-public-key-sha256")" ]]
}

if [[ "${rotate}" == "false" ]] && existing_pki_is_valid; then
  echo "development Metrics client PKI is valid"
  exit 0
fi

work_dir="$(mktemp -d /tmp/atf-operations-pki.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT

generate_key() {
  openssl genpkey -algorithm ED25519 -out "$1" >/dev/null 2>&1
}

generate_csr() {
  local key="$1"
  local csr="$2"
  local subject="$3"
  local eku="$4"
  local uri="$5"
  openssl req -new -key "${key}" -out "${csr}" -subj "${subject}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=${eku}" \
    -addext "subjectAltName=URI:${uri}" >/dev/null 2>&1
}

sign_client() {
  local csr="$1"
  local certificate="$2"
  local serial="$3"
  shift 3
  openssl x509 -req -in "${csr}" \
    -CA "${work_dir}/client-ca.crt" -CAkey "${work_dir}/client-ca.key" \
    -set_serial "${serial}" -copy_extensions copy "$@" \
    -out "${certificate}" >/dev/null 2>&1
}

generate_key "${work_dir}/client-ca.key"
openssl req -x509 -new -key "${work_dir}/client-ca.key" \
  -out "${work_dir}/client-ca.crt" -days 30 \
  -subj "/CN=ATF Local Metrics Client CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

generate_key "${work_dir}/client.key"
generate_csr "${work_dir}/client.key" "${work_dir}/client.csr" \
  "/CN=ATF Local Metrics Reader" clientAuth "${approved_uri}"
sign_client "${work_dir}/client.csr" "${work_dir}/client.crt" 1001 -days 7

generate_key "${work_dir}/unapproved.key"
generate_csr "${work_dir}/unapproved.key" "${work_dir}/unapproved.csr" \
  "/CN=ATF Unapproved Metrics Reader" clientAuth spiffe://atf.local/unapproved
sign_client "${work_dir}/unapproved.csr" "${work_dir}/unapproved.crt" 1002 -days 7

generate_key "${work_dir}/wrong-eku.key"
generate_csr "${work_dir}/wrong-eku.key" "${work_dir}/wrong-eku.csr" \
  "/CN=ATF Wrong EKU Fixture" serverAuth "${approved_uri}"
sign_client "${work_dir}/wrong-eku.csr" "${work_dir}/wrong-eku.crt" 1003 -days 7

generate_key "${work_dir}/expired.key"
generate_csr "${work_dir}/expired.key" "${work_dir}/expired.csr" \
  "/CN=ATF Expired Fixture" clientAuth "${approved_uri}"
sign_client "${work_dir}/expired.csr" "${work_dir}/expired.crt" 1004 \
  -not_before 20200101000000Z -not_after 20200102000000Z

generate_key "${work_dir}/future.key"
generate_csr "${work_dir}/future.key" "${work_dir}/future.csr" \
  "/CN=ATF Future Fixture" clientAuth "${approved_uri}"
sign_client "${work_dir}/future.csr" "${work_dir}/future.crt" 1005 \
  -not_before 20990101000000Z -not_after 20990102000000Z

generate_key "${work_dir}/wrong-ca.key"
openssl req -x509 -new -key "${work_dir}/wrong-ca.key" \
  -out "${work_dir}/wrong-ca.crt" -days 30 \
  -subj "/CN=ATF Wrong Metrics CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
generate_key "${work_dir}/wrong-client.key"
generate_csr "${work_dir}/wrong-client.key" "${work_dir}/wrong-client.csr" \
  "/CN=ATF Wrong CA Fixture" clientAuth "${approved_uri}"
openssl x509 -req -in "${work_dir}/wrong-client.csr" \
  -CA "${work_dir}/wrong-ca.crt" -CAkey "${work_dir}/wrong-ca.key" \
  -set_serial 2001 -days 7 -copy_extensions copy \
  -out "${work_dir}/wrong-client.crt" >/dev/null 2>&1

public_key_hash="$(openssl x509 -in "${work_dir}/client.crt" -pubkey -noout \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | tail -c 32 \
  | openssl dgst -sha256 -r | awk '{print $1}')"
if [[ ! "${public_key_hash}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "failed to derive the approved Metrics client public-key fingerprint" >&2
  exit 1
fi

install -m 0400 "${work_dir}/client-ca.key" "${authority_dir}/client-ca.key"
install -m 0444 "${work_dir}/client-ca.crt" "${authority_dir}/client-ca.crt"
install -m 0444 "${work_dir}/client-ca.crt" "${trust_dir}/client-ca.crt"
printf '%s\n' "${public_key_hash}" >"${trust_dir}/approved-public-key-sha256.tmp"
chmod 0444 "${trust_dir}/approved-public-key-sha256.tmp"
mv -f "${trust_dir}/approved-public-key-sha256.tmp" \
  "${trust_dir}/approved-public-key-sha256"
install -m 0400 "${work_dir}/client.key" "${client_dir}/client.key"
install -m 0444 "${work_dir}/client.crt" "${client_dir}/client.crt"

for fixture in unapproved wrong-eku expired future wrong-client; do
  install -m 0400 "${work_dir}/${fixture}.key" "${invalid_dir}/${fixture}.key"
  install -m 0444 "${work_dir}/${fixture}.crt" "${invalid_dir}/${fixture}.crt"
done

existing_pki_is_valid || {
  echo "generated development Metrics client PKI failed validation" >&2
  exit 1
}
echo "development Metrics client PKI generated"
