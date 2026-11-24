#!/usr/bin/env bash
# Check an app, and its DMG when there is one. Reports every failure before exiting non-zero.
# Usage: verify.sh <app> [dmg]
# Optional env: ENTITLEMENTS (every key in it must be in the signed app)
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

app="${1:?usage: verify.sh <app> [dmg]}"
dmg="${2:-}"
[[ -d "$app" ]] || die "$app not found"

failed=0
fail() { echo "  FAIL  $*" >&2; failed=1; }
check() { # <label> <command...>
    local label="$1" out
    shift
    if out=$("$@" 2>&1); then echo "  ok    $label"; else fail "$label: $out"; fi
}
entitlements_of() { codesign -d --entitlements - --xml "$1" 2>/dev/null || true; }
team_of() { sed -n 's/^TeamIdentifier=//p' <<<"$1"; }

check "app signature" codesign --verify --deep --strict "$app"

# A missing entitlement does not fail at signing. macOS just denies the microphone, calendar and so on at run time.
if [[ -n "${ENTITLEMENTS:-}" ]]; then
    signed=$(entitlements_of "$app")
    while IFS= read -r key; do
        [[ "$signed" == *"<key>$key</key>"* ]] || fail "entitlement missing from the signed app: $key"
    done < <(plutil -convert xml1 -o - "$ENTITLEMENTS" | sed -n 's/.*<key>\(.*\)<\/key>.*/\1/p')
fi

signature=$(codesign -dvv "$app" 2>&1 || true)
release=no
[[ "$signature" != *"Authority=Developer ID Application"* ]] || release=yes
team=$(team_of "$signature")

while IFS= read -r file; do
    [[ "$(file -b "$file")" == *Mach-O* ]] || continue
    libraries=$(otool -L "$file")
    [[ "$libraries" != *$'\t'/opt/homebrew/* && "$libraries" != *$'\t'/usr/local/* ]] ||
        fail "links a library only this Mac has (otool -L): $file"
    [[ "$release" == yes ]] || continue
    # Notarisation rejects the first three. A different team fails library validation at launch.
    signature=$(codesign -dvv "$file" 2>&1 || true)
    [[ "$signature" =~ flags=[^\ ]*runtime ]] || fail "no hardened runtime: $file"
    [[ "$signature" == *"Timestamp="* ]] || fail "no secure timestamp: $file"
    [[ "$(entitlements_of "$file")" != *get-task-allow* ]] || fail "debug entitlement get-task-allow: $file"
    [[ "$(team_of "$signature")" == "$team" ]] || fail "signed by another team: $file"
done < <(find "$app/Contents" -type f)

if [[ "$release" == no ]]; then
    echo "  skip  release checks: the app is not Developer ID signed"
else
    check "app Gatekeeper" spctl --assess --type execute "$app"
    check "app staple" xcrun stapler validate "$app"
fi

if [[ -f "$dmg" ]]; then
    check "DMG signature" codesign --verify --strict "$dmg"
    check "DMG Gatekeeper" spctl --assess --type open --context context:primary-signature "$dmg"
    check "DMG staple" xcrun stapler validate "$dmg"
fi
exit "$failed"
