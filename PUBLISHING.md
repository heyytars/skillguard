# Releasing skillguard

skillguard ships through **GitHub Releases** and the **heyytars/tap** Homebrew tap.
It is not published to the npm registry. `package.json` has `"private": true`, so an
accidental `npm publish` is refused.

## Release

```bash
scripts/release.sh          # patch: 2.0.7 -> 2.0.8
scripts/release.sh minor    # 2.0.7 -> 2.1.0
```

The script:

1. Checks you're on a clean, up-to-date `main`
2. Runs the tests
3. Bumps the version, tags it, pushes
4. Builds the package and attaches it to a GitHub Release
   (as `skillguard-<version>.tgz` and a stable `skillguard.tgz`)
5. Updates the Homebrew formula's URL + checksum in `../homebrew-tap` and pushes it

Needs: `gh` logged in, and the tap cloned at `~/work/code/GitHub/homebrew-tap`
(override with `TAP_DIR=...`).

## Verify

```bash
brew update && brew upgrade heyytars/tap/skillguard && skillguard --version
npm install -g https://github.com/heyytars/skillguard/releases/latest/download/skillguard.tgz
```
