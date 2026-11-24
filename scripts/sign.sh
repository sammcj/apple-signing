#!/usr/bin/env bash
# Sign an app inside-out: every nested binary and bundle first, the app last. codesign --deep is not used to sign,
# because it would apply the app's entitlements to everything nested.
#
# Usage: sign.sh <app> dev|release
#   dev      SIGN_IDENTITY, else the Keychain's dev-signing-identity, else ad-hoc. No timestamp, so it works offline.
#   release  Developer ID with a secure timestamp, which notarisation requires.
# Optional env: ENTITLEMENTS (main app), PROFILE (provisioning profile to embed)
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

app="${1:?usage: sign.sh <app> dev|release}"
mode="${2:?usage: sign.sh <app> dev|release}"
[[ -d "$app" ]] || die "$app not found; run make bundle"

case "$mode" in
    dev)
        identity="${SIGN_IDENTITY:-$(keychain dev-signing-identity)}"
        identity="${identity:--}"
        timestamp=--timestamp=none
        ;;
    release)
        identity=$(release_identity)
        [[ -n "$identity" ]] || die "no Developer ID identity; run make setup"
        timestamp=--timestamp
        ;;
    *) die "mode must be dev or release" ;;
esac

flags=(--force --sign "$identity" "$timestamp")
if [[ "$identity" == - ]]; then
    # Hardened runtime turns on library validation, which refuses ad-hoc frameworks because they have no Team ID.
    echo "Signing ad-hoc, without hardened runtime"
else
    flags+=(--options runtime)
    echo "Signing with $identity"
fi

sign() {
    local out status=0
    out=$(codesign "${flags[@]}" "$@" 2>&1) || status=$?
    grep -v ': replacing existing signature$' <<<"$out" | grep . >&2 || true
    return "$status"
}

main_executable() { # <bundle>; empty when it holds no code
    local plist name dir="$1/Contents/MacOS"
    if [[ "$1" == *.framework ]]; then
        name=$(basename "$1" .framework)
        if [[ -d "$1/Versions" ]]; then dir="$1/Versions/$(readlink "$1/Versions/Current")"; else dir="$1"; fi
    else
        plist="$1/Contents/Info.plist"
        [[ -f "$plist" ]] || return 0
        name=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || return 0
    fi
    if [[ -f "$dir/$name" ]]; then echo "$dir/$name"; fi
}

# A bundle's main executable is sealed by signing the bundle, so it is left out of the loose binaries.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
main_executable "$app" >"$work/mains"
while IFS= read -r bundle; do
    main=$(main_executable "$bundle")
    [[ -n "$main" ]] || continue
    echo "$main" >>"$work/mains"
    echo "$bundle" >>"$work/items"
done < <(find "$app/Contents" -type d \( -name '*.framework' -o -name '*.app' -o -name '*.xpc' -o -name '*.appex' \
    -o -name '*.bundle' -o -name '*.plugin' -o -name '*.systemextension' \))
while IFS= read -r file; do
    [[ "$(file -b "$file")" == *Mach-O* ]] || continue
    grep -qxF -- "$file" "$work/mains" || echo "$file" >>"$work/items"
done < <(find "$app/Contents" -type f -not -path '*/_CodeSignature/*')

# Deepest path first. Nested code keeps its own entitlements: JIT helpers and Sparkle's Downloader need theirs.
if [[ -f "$work/items" ]]; then
    while IFS= read -r item; do
        sign --preserve-metadata=entitlements "$item"
    done < <(awk -F/ '{print NF "\t" $0}' "$work/items" | sort -rn | cut -f2-)
fi

if [[ -n "${PROFILE:-}" ]]; then
    cp "$PROFILE" "$app/Contents/embedded.provisionprofile"
fi

if [[ -n "${ENTITLEMENTS:-}" ]]; then
    team=XXXXXXXXXX
    if [[ "$identity" != - ]] && grep -q __TEAM_ID__ "$ENTITLEMENTS"; then
        team=$(team_id "$identity") || true
        [[ -n "$team" ]] || die "no Team ID found in the certificate for '$identity'"
    fi
    sed "s/__TEAM_ID__/$team/g" "$ENTITLEMENTS" >"$work/app.entitlements"
    plutil -lint -s "$work/app.entitlements"
    sign --entitlements "$work/app.entitlements" "$app"
else
    sign --preserve-metadata=entitlements "$app"
fi
codesign --verify --deep --strict "$app"
