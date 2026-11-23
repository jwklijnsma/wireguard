#!/usr/bin/env bash
# Prints the next release tag (vX.Y.Z) for HEAD, or nothing when no release is needed.
#
# BUMP=auto (default) decides from the commits since the last vX.Y.Z tag:
#   - nothing is released when only CI/docs/Renovate config changed
#     (.github/, docs/, *.md, renovate.json, LICENSE) or when HEAD says [skip release]
#   - "type!:" or "BREAKING CHANGE" -> major (minor while still on 0.x)
#   - "feat:" / "feat(scope):"       -> minor
#   - anything else                  -> patch
# BUMP=patch|minor|major forces that bump and always releases.
set -euo pipefail

BUMP="${BUMP:-auto}"
last="$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' HEAD 2>/dev/null || true)"

if [ -n "$last" ]; then
  range="$last..HEAD"
  base="$last"
  if [ "$(git rev-list --count "$range")" = 0 ]; then
    echo "No commits since $last, nothing to release." >&2
    exit 0
  fi
else
  last="v0.0.0"
  range="HEAD"
  base="$(git hash-object -t tree /dev/null)"   # empty tree: everything counts as changed
fi

IFS=. read -r major minor patch <<<"${last#v}"
patch="${patch%%[-+]*}"   # ignore pre-release/build suffixes

if [ "$BUMP" = auto ]; then
  if git log -1 --format=%B HEAD | grep -qiE '\[(skip|no) release\]'; then
    echo "HEAD asks for [skip release]." >&2
    exit 0
  fi

  relevant="$(git diff --name-only "$base" HEAD \
    | grep -vE '^(\.github/|docs/|renovate\.json$|LICENSE|(.*/)?[^/]*\.md$)' || true)"
  if [ -z "$relevant" ]; then
    echo "Only CI/docs changed since $last, nothing to release." >&2
    exit 0
  fi
  echo "Release-relevant changes since $last:" >&2
  sed 's/^/  /' <<<"$relevant" >&2

  # subjects + bodies, so merge commits contribute the PR title in their body
  msgs="$(git log --format='%s%n%b' "$range")"
  if grep -qE '^[a-z]+(\([^)]*\))?!:|BREAKING[ -]CHANGE' <<<"$msgs"; then
    BUMP=major
    [ "$major" = 0 ] && BUMP=minor   # 0.x: breaking changes bump the minor version
  elif grep -qE '^feat(\([^)]*\))?:' <<<"$msgs"; then
    BUMP=minor
  else
    BUMP=patch
  fi
fi

case "$BUMP" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
  *) echo "Unknown BUMP '$BUMP' (use auto, patch, minor or major)" >&2; exit 1 ;;
esac

echo "$last -> v$major.$minor.$patch ($BUMP)" >&2
echo "v$major.$minor.$patch"
