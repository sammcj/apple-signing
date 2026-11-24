#!/usr/bin/env bash
# Show which credentials a release would use and try the API key. Exits non-zero if a release would not work.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

failed=0
ok() { echo "  ok       $*"; }
missing() { echo "  MISSING  $*" >&2; failed=1; }

for tool in notarytool stapler; do
    if xcrun --find "$tool" >/dev/null 2>&1; then ok "$tool"; else missing "$tool (install Xcode, then xcode-select)"; fi
done

identity=$(release_identity)
if [[ -z "$identity" ]]; then
    missing "Developer ID identity (make setup)"
else
    case "$(installed_identity "$identity")" in
        *"Developer ID Application: "*) ok "identity: $identity" ;;
        "") missing "certificate and private key for '$identity' in the Keychain" ;;
        *) missing "'$identity' is not a Developer ID Application identity" ;;
    esac
fi

if [[ -n "${APPLE_API_ISSUER:-$(keychain api-issuer)}" ]]; then ok "API issuer ID"; else missing "API issuer ID (make setup)"; fi
if [[ -n "${APPLE_API_KEY:-$(keychain api-key)}" ]]; then ok "API key ID"; else missing "API key ID (make setup)"; fi
# Only checks the item exists, without reading the secret.
if [[ -n "${APPLE_API_KEY_PATH:-}" ]]; then
    if [[ -f "$APPLE_API_KEY_PATH" ]]; then ok "API key: $APPLE_API_KEY_PATH"; else missing "$APPLE_API_KEY_PATH"; fi
elif security find-generic-password -s "$SERVICE" -a api-key-file >/dev/null 2>&1; then
    ok "API key: Keychain ($SERVICE/api-key-file)"
else
    missing "API key (make setup)"
fi

# Catches a wrong ID, a revoked key and an unsigned agreement before anything is built.
if [[ "$failed" == 0 ]]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    notary_auth "$work"
    if out=$(xcrun notarytool history "${auth[@]}" 2>&1); then ok "Apple accepts the API key"; else missing "Apple refused: $out"; fi
fi

for file in "${ENTITLEMENTS:-}" "${PROFILE:-}"; do
    [[ -z "$file" || -f "$file" ]] || missing "$file"
done
exit "$failed"
