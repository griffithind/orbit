#!/bin/sh
# Print the newest version in CHANGELOG.md.
#
# The changelog is the single source of truth for what version this tree
# describes. The README used to carry a pinned VERSION= for its install command
# and two workflows read that; the install script made the pin unnecessary, and
# a check reading a line nobody maintains any more is a check that will one day
# pass by accident.
set -eu

cd "$(dirname "$0")/.."

version=$(sed -n 's/^## v\([0-9][^ ]*\)$/\1/p' CHANGELOG.md | head -1)
if [ -z "$version" ]; then
    echo "CHANGELOG.md has no '## vX.Y.Z' section" >&2
    exit 1
fi
printf '%s\n' "$version"
