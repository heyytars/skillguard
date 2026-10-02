# Changelog

## 2.0.9 (2026-10-02)

- Fixed: TypeScript files with type annotations were silently skipped. A file
  with `const cmd: string = ...` returned zero findings. TS now goes through a
  real TypeScript parser, and casts like `(exec as any)(cmd)` are seen through.
- Fixed: the dependency check ran `npm install` inside the folder you scanned,
  leaving a new `package-lock.json` behind and reading that folder's `.npmrc`.
  It now works in a private temp copy and leaves your folder untouched.
- Fixed: the logo banner still said v1.0.0, and the "Risk Level" box border was
  misaligned.
- Now needs Node.js 20.19 or newer.
- Docs: README rewritten and fact-checked against the code, with a scan
  screenshot and a how-it-works infographic.

## 2.0.8 (2026-10-02)

- Fixed: `skillguard version` printed v1.0.0. It now shows the real version.
- Docs: accurate claims, a working CI example, an up-to-date project tree.

## 2.0.7 (2026-10-02)

- Fixed: scanning a relative path like `../my-skill` hung forever
  (config lookup never reached the filesystem root).
- Fixed: `--version` and `skillguard version` now report the real version.
- Distribution moved off the npm registry. Install with Homebrew
  (`brew install heyytars/tap/skillguard`) or from GitHub Releases.
- Project moved to `github.com/heyytars/skillguard`.

## 2.0.0 (2026-02-04)

- Multi-language analyzers (JS/TS, Python, Java, Go, Ruby, PHP, C/C++, Rust),
  threat categories, configurable scoring. Last version published to npm.
