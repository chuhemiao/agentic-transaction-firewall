#!/bin/sh
set -eu

fingerprint_file=/metrics-trust/approved-public-key-sha256
if [ ! -r "${fingerprint_file}" ]; then
    echo "ATF local edge is missing the approved Metrics client fingerprint" >&2
    exit 1
fi
ATF_METRICS_CLIENT_PUBLIC_KEY_SHA256="$(tr -d '\r\n' <"${fingerprint_file}")"
case "${ATF_METRICS_CLIENT_PUBLIC_KEY_SHA256}" in
    ''|*[!0-9a-f]*)
        echo "ATF local edge received an invalid Metrics client fingerprint" >&2
        exit 1
        ;;
esac
if [ "${#ATF_METRICS_CLIENT_PUBLIC_KEY_SHA256}" -ne 64 ]; then
    echo "ATF local edge received an invalid Metrics client fingerprint" >&2
    exit 1
fi
export ATF_METRICS_CLIENT_PUBLIC_KEY_SHA256

caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
caddy_pid=$!

terminate() {
    kill -TERM "${caddy_pid}" 2>/dev/null || true
    wait "${caddy_pid}" 2>/dev/null || true
}
trap terminate INT TERM

attempt=0
while [ "${attempt}" -lt 30 ]; do
    if [ -r /data/caddy/pki/authorities/local/root.crt ]; then
        cp /data/caddy/pki/authorities/local/root.crt /ca/root.crt
        chmod 0444 /ca/root.crt
        wait "${caddy_pid}"
        exit $?
    fi
    if ! kill -0 "${caddy_pid}" 2>/dev/null; then
        wait "${caddy_pid}"
        exit $?
    fi
    attempt=$((attempt + 1))
    sleep 1
done

echo "ATF local edge could not export its public root certificate" >&2
terminate
exit 1
