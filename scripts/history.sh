#!/usr/bin/env bash
# List submissions to Apple's notary service, or show the log of one.
# Usage: history.sh [submission id]
set -euo pipefail
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
notary_auth "$work"
if [[ -n "${1:-}" ]]; then
    xcrun notarytool log "$1" "${auth[@]}"
else
    xcrun notarytool history "${auth[@]}"
fi
