# shellcheck shell=bash
# Sourced by the other scripts.

SERVICE="${KEYCHAIN_SERVICE:-apple-release}"

die() { echo "ERROR: $*" >&2; exit 1; }

keychain() { security find-generic-password -s "$SERVICE" -a "$1" -w 2>/dev/null || true; }

# Environment variables win over the Keychain, so CI can supply its own.
release_identity() { echo "${DEVELOPER_ID_APPLICATION:-$(keychain signing-identity)}"; }

# The find-identity line for an identity given by name or SHA-1. Empty when it is not installed or not valid.
installed_identity() { security find-identity -v -p codesigning | grep -F -- "$1" || true; }

# The Team ID is the OU of the certificate. The bracketed suffix of an Apple Development identity is a per-person ID,
# so the name is never parsed for it.
team_id() {
    local name line
    line=$(installed_identity "$1")
    name=$(sed -n 's/.*"\(.*\)".*/\1/p' <<<"$line" | head -n 1)
    [[ -n "$name" ]] || return 0
    security find-certificate -c "$name" -p 2>/dev/null | openssl x509 -noout -subject 2>/dev/null |
        sed -nE 's/.*OU *= *([A-Z0-9]{10}).*/\1/p'
}

# notary_auth <private directory>: sets the auth array for notarytool. notarytool only reads the API key from a file,
# so the key is written to that directory, which the caller removes on exit.
notary_auth() {
    local issuer key_id key_path="${APPLE_API_KEY_PATH:-}"
    issuer="${APPLE_API_ISSUER:-$(keychain api-issuer)}"
    key_id="${APPLE_API_KEY:-$(keychain api-key)}"
    [[ -n "$issuer" && -n "$key_id" ]] || die "API issuer or key ID not set; run make setup"
    if [[ -z "$key_path" ]]; then
        key_path="$1/AuthKey.p8"
        (umask 077 && keychain api-key-file | base64 -d >"$key_path")
    fi
    [[ -s "$key_path" ]] || die "API key missing or empty; run make setup"
    # shellcheck disable=SC2034 # used by the scripts that source this
    auth=(--issuer "$issuer" --key-id "$key_id" --key "$key_path")
}
