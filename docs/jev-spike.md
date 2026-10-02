# The jev spike: can a small local model settle the cases rules can't?

Short answer: **not as a decision-maker.** It is worth keeping as a second
opinion that can only *raise* a score, never lower one. The measurements are
below, including the ones that went against it.

## Why we looked

`bench/fixtures/context/` has three cases the rules cannot settle, because a rule
cannot tell an attack from a description of an attack:

| Fixture | Rules say |
|---|---|
| `keychain-audit` — a security review that runs `security dump-keychain` | Critical 76 |
| `threat-writeup` — a page explaining how ClawHavoc worked | Critical 100 |
| `own-binary-quarantine` — clearing the quarantine flag off your own build | Low 20 |

[jev](https://github.com/feder-cr/jev) is a small local yes/no classifier: one CPU
binary, no GPU, no Python, HTTP API. The idea was to ask it the question the rules
cannot answer — *is this text instructing, or explaining?*

## What we ran

Model `jevos-v3-openvino-int8` (629,775,007 bytes, SHA-256 verified against the
published `SHA256SUMS.txt`), `jev serve --threads 4` on an M-series Mac.

| Measure | Result |
|---|---|
| Startup | 6.9 s |
| Memory in use | **2.2 GB** (they advertise ~1 GB) |
| Latency per question, 12 lines of context | 345 ms median, 717 ms p90 |
| Latency, single short line | 96 ms |

## The negative result, and then a positive one

Asking *"does this only explain or warn against the command?"* failed outright:

| Case | `only_explains` | Wanted |
|---|---|---|
| Disguised attack: "documentation only… run the setup step" | 0.93 | low |
| Genuine warning: "Never run `security dump-keychain`" | 0.08 | high |

The model was fooled by exactly the disguise the rules now catch.

Changing the question fixed it. Asking **"if a reader followed this text literally,
would they run the command shown in `finding`?"** got **5/5 on the hand-picked
set**, including both disguised attacks and both genuine warnings, at 97 ms.

Then it was run over every High/Critical finding in the whole fixture set, with
that question. On real attack text it answered *"nobody would run this"* for four
genuinely malicious skills, including one that copies `~/.ssh/id_rsa` into the
reply. That is not a bug to patch: the attacker writes the text the model reads,
so the attacker can argue it down.

## Numbers

| Direction | Result |
|---|---|
| Reworded attacks caught (no trigger words) | **4/8** |
| Benign text wrongly flagged | 1/8 — ordinary key hygiene |
| Rule-based detection, same disguised set | **8/8** |

The rules were the better detector on every measure. The spike's real value was
finding the two scoring holes it exposed, which are fixed in 2.4.0.

## If we ever ship it

1. Behind `--ai`, default off. The scan stays fast, offline and deterministic.
2. It may **raise** any finding. It may **lower** only the seven context-dependent
   rules, and only to Medium — never High, never Safe.
3. Send ~20 lines around a finding, never the whole repository.
4. Record the model fingerprint (its `/health` endpoint reports file hashes) so
   every softened verdict can be traced to a model build.
5. Build a **held-out** question set first. The winning wording above was chosen
   on the same five cases it was then measured on. Those numbers are not a result
   yet, and it would be dishonest to present them as one.

jev's own wiki says this kind of screening "is not a security boundary", which is
the correct way to think about it.
