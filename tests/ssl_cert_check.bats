#!/usr/bin/env bats

bats_require_minimum_version 1.5.0

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../ssl-cert-check"
    FIXTURE_DIR="${BATS_TEST_TMPDIR}/fixtures"
    mkdir -p "${FIXTURE_DIR}/certs"

    CERT="${FIXTURE_DIR}/valid.crt"
    KEY="${FIXTURE_DIR}/valid.key"
    DER_CERT="${FIXTURE_DIR}/valid.der"
    PKCS12_CERT="${FIXTURE_DIR}/valid.p12"
    INVALID_CERT="${FIXTURE_DIR}/invalid.txt"
    SERVER_FILE="${FIXTURE_DIR}/servers.txt"
    BAD_SERVER_FILE="${FIXTURE_DIR}/bad-servers.txt"
    MAIL_LOG="${FIXTURE_DIR}/mail.log"
    FAKE_MAIL="${FIXTURE_DIR}/fake-mail"

    openssl req -x509 -newkey rsa:2048 -nodes -days 120 \
        -subj "/C=US/O=MattyCA/CN=localhost" \
        -keyout "${KEY}" -out "${CERT}" >/dev/null 2>&1
    openssl x509 -in "${CERT}" -outform DER -out "${DER_CERT}" >/dev/null 2>&1
    openssl pkcs12 -export -in "${CERT}" -inkey "${KEY}" -out "${PKCS12_CERT}" \
        -password pass:testpass >/dev/null 2>&1

    printf "not a certificate\n" > "${INVALID_CERT}"
    cp "${CERT}" "${FIXTURE_DIR}/certs/valid with spaces.crt"

    cat > "${FAKE_MAIL}" <<'MAIL'
#!/usr/bin/env bash
{
    printf 'args:'
    printf ' <%s>' "$@"
    printf '\nbody:\n'
    cat
} >> "${SSL_CERT_CHECK_TEST_MAIL_LOG}"
MAIL
    chmod +x "${FAKE_MAIL}"

    export TMPDIR="${BATS_TEST_TMPDIR}"
    export TIMEOUT_SECONDS=3
}

teardown() {
    if [ -n "${TLS_SERVER_PID:-}" ]; then
        kill "${TLS_SERVER_PID}" >/dev/null 2>&1 || true
        wait "${TLS_SERVER_PID}" >/dev/null 2>&1 || true
    fi
}

run_check() {
    run --separate-stderr "${SCRIPT}" "$@"
}

assert_no_internal_errors() {
    [ "${stderr:-}" = "" ]
    [[ "${output}" != *"/bin/grep:"* ]]
    [[ "${output}" != *"No such file or directory"* ]]
    [[ "${output}" != *"integer expression expected"* ]]
    [[ "${output}" != *"syntax error"* ]]
}

start_tls_server() {
    TLS_PORT=$((20000 + RANDOM % 20000))
    openssl s_server -quiet -accept "${TLS_PORT}" -cert "${CERT}" -key "${KEY}" \
        > "${FIXTURE_DIR}/s_server.out" 2> "${FIXTURE_DIR}/s_server.err" &
    TLS_SERVER_PID=$!
    sleep 1
}

@test "-V prints the program version" {
    run_check -V

    [ "${status}" -eq 0 ]
    [[ "${output}" =~ ^[0-9]+(\.[0-9]+)?$ ]]
    assert_no_internal_errors
}

@test "-h prints usage" {
    run_check -h

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Usage:"* ]]
    [[ "${output}" == *"-c cert file"* ]]
    assert_no_internal_errors
}

@test "-c checks a PEM certificate file" {
    run_check -c "${CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Valid"* ]]
    [[ "${output}" == *"${CERT}"* ]]
    assert_no_internal_errors
}

@test "-b suppresses the table header" {
    run_check -b -c "${CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Valid"* ]]
    [[ "${output}" != *"Host"* ]]
    [[ "${output}" != *"--------"* ]]
    assert_no_internal_errors
}

@test "-q suppresses output" {
    run_check -q -c "${CERT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    assert_no_internal_errors
}

@test "-x changes the warning threshold" {
    run_check -x 365 -c "${CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Expiring"* ]]
    assert_no_internal_errors
}

@test "-i includes issuer output" {
    run_check -i -c "${CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"MattyCA"* ]]
    [[ "${output}" == *"Valid"* ]]
    assert_no_internal_errors
}

@test "-S prints validation metadata" {
    run_check -S -c "${CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Common Name"* ]]
    [[ "${output}" == *"Serial #"* ]]
    [[ "${output}" == *"localhost"* ]]
    assert_no_internal_errors
}

@test "-t der checks a DER certificate file" {
    run_check -t der -c "${DER_CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Valid"* ]]
    assert_no_internal_errors
}

@test "-k checks a PKCS12 certificate file" {
    run_check -k testpass -c "${PKCS12_CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Valid"* ]]
    assert_no_internal_errors
}

@test "-d checks certificates in a directory, including names with spaces" {
    run_check -d "${FIXTURE_DIR}/certs"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"valid with spaces.crt"* ]]
    [[ "${output}" == *"Valid"* ]]
    assert_no_internal_errors
}

@test "-f checks FILE entries from a list" {
    printf '%s FILE\n# ignored\n\n' "${CERT}" > "${SERVER_FILE}"

    run_check -f "${SERVER_FILE}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Valid"* ]]
    assert_no_internal_errors
}

@test "-s and -p check a remote TLS endpoint without shell errors" {
    start_tls_server

    run_check -s 127.0.0.1 -p "${TLS_PORT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"127.0.0.1:${TLS_PORT}"* ]]
    [[ "${output}" == *"Certificate verify failed"* || "${output}" == *"TLS connection failed"* || "${output}" == *"Unable to parse certificate"* ]]
    assert_no_internal_errors
}

@test "-a, -e, and -E send mail for warning certificates" {
    export SSL_CERT_CHECK_TEST_MAIL_LOG="${MAIL_LOG}"

    run --separate-stderr env MAIL="${FAKE_MAIL}" MAILMODE=mail "${SCRIPT}" \
        -a -e admin@example.test -E sender@example.test -x 365 -c "${CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Expiring"* ]]
    assert_no_internal_errors
    [[ "$(cat "${MAIL_LOG}")" == *"<-r> <sender@example.test>"* ]]
    [[ "$(cat "${MAIL_LOG}")" == *"<admin@example.test>"* ]]
    [[ "$(cat "${MAIL_LOG}")" == *"will expire"* ]]
}

@test "invalid certificate data is reported without internal errors" {
    run_check -c "${INVALID_CERT}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Unable to parse certificate"* ]]
    assert_no_internal_errors
}

@test "missing certificate file is reported without internal errors" {
    run_check -c "${FIXTURE_DIR}/missing.crt"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Unreadable certificate"* ]]
    assert_no_internal_errors
}

@test "missing server list is reported without internal errors" {
    run_check -f "${FIXTURE_DIR}/missing-list.txt"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Unable to read server file"* ]]
    assert_no_internal_errors
}

@test "malformed server list data is reported without internal errors" {
    printf 'this line has too many fields\n' > "${BAD_SERVER_FILE}"

    run_check -f "${BAD_SERVER_FILE}"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Malformed input line"* ]]
    assert_no_internal_errors
}

@test "missing directory is reported without internal errors" {
    run_check -d "${FIXTURE_DIR}/missing-directory"

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Unable to read directory"* ]]
    assert_no_internal_errors
}

@test "invalid -x data is rejected cleanly" {
    run_check -x nope -c "${CERT}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"warning interval must be a non-negative integer"* ]]
    assert_no_internal_errors
}

@test "invalid TIMEOUT_SECONDS data is rejected cleanly" {
    run --separate-stderr env TIMEOUT_SECONDS=bad "${SCRIPT}" -c "${CERT}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"TIMEOUT_SECONDS must be a positive integer"* ]]
    assert_no_internal_errors
}
