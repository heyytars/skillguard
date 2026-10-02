# Benchmark

Two numbers matter for a scanner like this, and this directory measures both:

- **Detection** — does it catch attacks, including attacks dressed up as documentation?
- **False alarms** — does it leave ordinary skills alone?

```bash
python3 bench/run.py             # shipped fixtures, no network, seconds
python3 bench/run.py --corpus    # also scans third-party skill corpora
python3 bench/run.py --json      # machine-readable
python3 bench/run.py --write     # refresh bench/RESULTS.md
```

Exit code is **1 when a number regresses** (an attack is missed, or an ordinary
skill is flagged High/Critical), so it works as a CI gate. Every push runs it.

## What it measures

| Set | What it is | Wanted verdict |
|---|---|---|
| `fixtures/attacks/` (14) | Malicious skills: paste-site installers, decode-and-run, credential exfiltration, keychain dumps, prompt injection, persistence, destructive commands, `eval`+`exec`, `os.system`. | High or Critical |
| `fixtures/disguised/` (9) | The same payloads wearing a disguise: "documentation only", a fake warning, an "example", a "test fixture", a quoted attack followed by the real one. | High or Critical |
| `fixtures/benign/` (9) | Ordinary skills: writing files, `subprocess` with literal args, `fetch`, reading an env var, a page warning *about* `curl \| bash`, credential hygiene, a local server. | Not High/Critical |
| `fixtures/context/` (3) | Borderline, and honestly not scored: a security review that reads the keychain, clearing the quarantine flag off your own build output, a page explaining how ClawHavoc worked. | Shown in the report |

The `context/` set exists because a rule cannot tell *"run this"* from *"here is
how the attack worked"*. All three come out High or Critical. Hiding them in the
benign set would be a lie; scoring them as failures would be pretending the
problem is solved. They are listed in `RESULTS.md` on every run.

## Third-party corpora

`--corpus` clones these at pinned commits into `~/.cache/skillguard-bench` and
scans every skill in them:

| Repo | Pinned commit | Why pinned |
|---|---|---|
| `anthropics/skills` | `8a1541c4` | Reproducible numbers; a moving `main` makes the README a claim about nothing |
| `obra/superpowers` | `8ca22dba` | Same |

**They are fetched, never vendored.** `anthropics/skills` carries no licence
file, so its content is not redistributed here; `obra/superpowers` is MIT but the
same rule keeps this repository small and the pins honest. Bump a pin
deliberately, then re-run `--write`.

## Adding a case

1. Make a directory under the right set: `fixtures/attacks/my-attack/SKILL.md`.
2. Keep it inert and fake — no working payloads, no real domains.
3. `python3 bench/run.py`. A new attack that is not caught exits 1, which is the
   point: write the fixture first, then fix the rule.

Use `context/` only for a case that genuinely needs judgement. If a fixture is
there, name it in `RESULTS.md` and say why.

## Reading the numbers

```
detection   23/23 attacks caught  (14 malicious, 9 disguised)
false alarm 0/9 ordinary skills flagged + 0/34 trusted
```

`0/34 trusted` is the number that matters most for daily use: scanning real
skills from Anthropic and obra/superpowers must not produce High or Critical.
Those tested skills do call `subprocess`, write files and fetch things, so they
come back Low or Medium, which is the intended "review it" band.

## What this benchmark does not measure

- **Reworded attacks.** These fixtures use known techniques. A skill that
  describes the same harm in fresh prose can pass, and does. The rules read
  patterns, not meaning.
- **Vulnerable dependencies.** Needs network and a registry; not covered here.
- **Runtime behaviour.** Only what is on disk before installation.
- **Corpus drift.** The pins are fixed, so the real-world set does not grow by
  itself. Re-pin deliberately, and expect the number to change when you do.

A local model (jev) was measured as a second opinion for the `context/` cases.
It settled the ClawHavoc write-up and missed the keychain review, and on real
attack text it can be argued into "nobody would run this" — which is why it may
only raise a score, never lower one. The numbers are in `docs/jev-spike.md`.
