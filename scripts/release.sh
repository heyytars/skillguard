#!/usr/bin/env bash
# Release skillguard to GitHub Releases + the heyytars/tap Homebrew formula.
#   usage: scripts/release.sh [patch|minor|major]   (default: patch)
# Needs: gh (logged in), npm, a clean main branch.
set -euo pipefail

bump="${1:-patch}"
repo="heyytars/skillguard"
tap_dir="${TAP_DIR:-$HOME/work/code/GitHub/homebrew-tap}"
cd "$(dirname "$0")/.."

[ -z "$(git status --porcelain)" ] || { echo "Working tree not clean"; exit 1; }
[ "$(git branch --show-current)" = "main" ] || { echo "Not on main"; exit 1; }
[ -f "$tap_dir/Formula/skillguard.rb" ] || { echo "Tap not found at $tap_dir"; exit 1; }

git pull -q --ff-only
npm test --silent
tag=$(npm version "$bump" -m "Release %s")
ver="${tag#v}"
git push -q origin main --follow-tags

tgz=$(npm pack --silent | tail -1)
cp "$tgz" skillguard.tgz
gh release create "$tag" "$tgz" skillguard.tgz -R "$repo" --title "$tag" --latest --generate-notes
sha=$(shasum -a 256 "$tgz" | cut -d' ' -f1)
rm -f "$tgz" skillguard.tgz

# Point the Homebrew formula at the new release.
f="$tap_dir/Formula/skillguard.rb"
sed -i '' -E \
  -e "s#releases/download/v[0-9.]+/skillguard-[0-9.]+\.tgz#releases/download/${tag}/skillguard-${ver}.tgz#" \
  -e "s#sha256 \"[0-9a-f]+\"#sha256 \"${sha}\"#" "$f"
git -C "$tap_dir" commit -qam "skillguard ${ver}"
git -C "$tap_dir" push -q origin main

echo "Released ${tag}"
echo "  npm install -g https://github.com/${repo}/releases/latest/download/skillguard.tgz"
echo "  brew upgrade heyytars/tap/skillguard"
