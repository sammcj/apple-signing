#!/usr/bin/env bash
# Submit a file to Apple's notary service and staple the ticket.
# Usage: notarise.sh <file to submit> <path to staple>
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

submit="${1:?usage: notarise.sh <file to submit> <path to staple>}"
staple="${2:?usage: notarise.sh <file to submit> <path to staple>}"

# mktemp -d makes a directory only this user can read. It is removed however the script ends.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
notary_auth "$work"
field() { plutil -extract "$1" raw -o - - <<<"$2" 2>/dev/null || true; }

# Submitting and waiting are separate so the ID is on screen before a wait that can be long.
echo "Uploading $submit"
result=$(xcrun notarytool submit "$submit" "${auth[@]}" --no-wait --output-format json) || true
id=$(field id "$result")
[[ -n "$id" ]] || die "upload failed: $result"
echo "Waiting for Apple, submission $id"
result=$(xcrun notarytool wait "$id" "${auth[@]}" --timeout 2h --output-format json) || true
status=$(field status "$result")
if [[ "$status" != Accepted ]]; then
    [[ "$status" == Invalid ]] || die "no verdict yet (${status:-unknown}). Check with: make history"
    xcrun notarytool log "$id" "${auth[@]}" >&2 || true
    die "Apple rejected $submit"
fi
echo "Accepted"

# The ticket can take a moment to be published.
for _ in 1 2 3; do
    if xcrun stapler staple "$staple"; then exit 0; fi
    sleep "${STAPLE_RETRY_SECONDS:-15}"
done
die "accepted, but stapling $staple failed"
