#!/usr/bin/env bash
# Interactively store signing and notarisation credentials in the login keychain.
# Enter keeps the current value shown in [brackets].
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

# store <account> <value>
# The value goes to security's interactive mode on stdin. On argv, any local process could read it while the command
# runs. A pipe, because bash writes <<< to a temporary file. That mode takes one command per line and splits on spaces and quotes, hence the checks. Reading the item back
# catches a value the tool parsed differently.
store() {
    local line
    [[ "$2" != *[\"\\$'\n'$'\r']* ]] || die "$1 holds a double quote, backslash or line break; not stored"
    line="add-generic-password -U -s \"$SERVICE\" -a \"$1\" -w \"$2\""
    (( ${#line} <= 4000 )) || die "$1 is too long for security's stdin; not stored"
    printf '%s\n' "$line" | security -i >/dev/null || true
    [[ "$(keychain "$1")" == "$2" ]] || die "$1 did not read back as entered; check '$SERVICE' in Keychain Access"
    echo "  stored $1"
}

# prompt <account> <label> <default> required|optional
prompt() {
    local current value
    current=$(keychain "$1")
    current=${current:-$3}
    read -r -p "$2 [${current:-none}]: " value
    value=${value:-$current}
    if [[ -z "$value" ]]; then
        [[ "$4" == optional ]] || die "$1 is required"
        echo "  skipped $1"
        return
    fi
    store "$1" "$value"
}

# Stores the key's contents, so the .p8 can leave this Mac's disk afterwards.
prompt_key_file() {
    local current value
    current=$(keychain api-key-file)
    read -r -p "Path to the API key file, AuthKey_XXXXXXXXXX.p8 [$([[ -n "$current" ]] && echo stored || echo none)]: " value
    if [[ -z "$value" ]]; then
        [[ -n "$current" ]] || die "the API key file is required"
        echo "  kept api-key-file"
        return
    fi
    value="${value/#\~/$HOME}"
    [[ -f "$value" ]] || die "$value does not exist"
    [[ "$(head -n 1 "$value")" == "-----BEGIN PRIVATE KEY-----" ]] || die "$value is not a .p8 private key"
    store api-key-file "$(base64 <"$value" | tr -d '\n')"
}

[[ -t 0 ]] || die "run this in an interactive terminal"

identities=$(security find-identity -v -p codesigning)
echo "Storing credentials in Keychain service '$SERVICE'."
echo
echo "Installed signing identities:"
echo "$identities"
echo
first() { sed -n "s/.*\"\($1: .*\)\".*/\1/p" <<<"$identities" | head -n 1; }

prompt signing-identity "Developer ID Application identity" "$(first 'Developer ID Application')" required
prompt dev-signing-identity "Apple Development identity, for local builds" "$(first 'Apple Development')" optional
prompt api-issuer "App Store Connect API Issuer ID" "" required
prompt api-key "App Store Connect API Key ID" "" required
prompt_key_file
echo
echo "Done. Next: make check"
