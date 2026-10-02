# Changelog

## 2.1.0 (2026-10-02)

- New: SkillGuard now reads `SKILL.md` and other markdown files, the
  instructions an agent actually follows. 28 rules cover the techniques seen in
  real malicious skills (ClawHavoc, Jan 2026; Snyk ToxicSkills, Feb 2026):
  fake "prerequisite" installers, `curl | bash` from paste sites, raw-IP
  payload servers, password-protected archives, base64 decode-and-run, secret
  exfiltration, keychain dumps, "ignore previous instructions", fake system
  messages, telling the agent to hide things from you, Gatekeeper/quarantine
  bypass, writes to agent memory files (`MEMORY.md`, `SOUL.md`, `CLAUDE.md`),
  hidden HTML comments, and invisible Unicode (tag smuggling, zero-width, bidi).
- Injection in the frontmatter `description` is always CRITICAL, because the
  agent loads it in every session.
- Quoted attack phrases ("avoid saying 'ignore previous instructions'") are
  reported as LOW, not as attacks. Chat-template tokens inside code blocks are
  ignored. Detected secrets are redacted in the report.
- Tested on 34 trusted skills (Anthropic, obra/superpowers): 33 have zero
  instruction findings. 28 attack cases and 16 benign look-alikes are in the
  test suite.

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
