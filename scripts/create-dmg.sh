#!/usr/bin/env bash
# Package an app into a Developer ID signed DMG with an /Applications link.
# Usage: create-dmg.sh <app> <dmg>
#
# Creates, mounts, copies and converts explicitly. 'hdiutil create -srcfolder' can fail with "Operation not permitted"
# when macOS blocks its implicit mount under /Volumes.
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

app="${1:?usage: create-dmg.sh <app> <dmg>}"
dmg="${2:?usage: create-dmg.sh <app> <dmg>}"
[[ -d "$app" ]] || die "$app not found"
identity=$(release_identity)
[[ -n "$identity" ]] || die "no Developer ID identity; run make setup"

work=$(mktemp -d)
mount="$work/mount"
mkdir -p "$mount" "$(dirname "$dmg")"
trap 'hdiutil detach "$mount" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

size=$(du -sm "$app" | cut -f1)
hdiutil create -quiet -volname "$(basename "$app" .app)" -fs HFS+ -size "$((size + size / 10 + 20))m" "$work/rw.dmg"
hdiutil attach -quiet "$work/rw.dmg" -mountpoint "$mount" -nobrowse -noverify -noautoopen
# ditto keeps signatures, extended attributes and the stapled ticket.
ditto "$app" "$mount/$(basename "$app")"
ln -s /Applications "$mount/Applications"
hdiutil detach -quiet "$mount"
rm -f "$dmg"
hdiutil convert -quiet "$work/rw.dmg" -format ULFO -o "$dmg"
codesign --force --sign "$identity" --timestamp "$dmg"
echo "Created $dmg ($(du -h "$dmg" | cut -f1 | tr -d ' '))"
