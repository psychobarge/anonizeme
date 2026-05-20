#!/usr/bin/env bash
# Bump semver in package.json, src-tauri/Cargo.toml, and src-tauri/tauri.conf.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"

BUMP="${1:-}"
if [[ -z "$BUMP" || ! "$BUMP" =~ ^(patch|minor|major)$ ]]; then
  echo "Usage: bump-version.sh <patch|minor|major>" >&2
  exit 1
fi

CURRENT="$(node -p "require('./package.json').version")"
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
PATCH="${PATCH:-0}"

case "$BUMP" in
  patch) MAJOR="$MAJOR"; MINOR="$MINOR"; PATCH=$((PATCH + 1)) ;;
  minor) MAJOR="$MAJOR"; MINOR=$((MINOR + 1)); PATCH=0 ;;
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
esac

NEW="${MAJOR}.${MINOR}.${PATCH}"

node -e "
const fs = require('fs');
const p = './package.json';
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
j.version = process.argv[1];
fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
" "$NEW"

# Cargo.toml: version = "x.y.z"
sed -i '' -E "s/^version = \".*\"/version = \"${NEW}\"/" src-tauri/Cargo.toml

# tauri.conf.json: "version": "x.y.z"
node -e "
const fs = require('fs');
const p = './src-tauri/tauri.conf.json';
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
j.version = process.argv[1];
fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
" "$NEW"

echo "${CURRENT} -> ${NEW}"
