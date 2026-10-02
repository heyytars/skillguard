#!/usr/bin/env python3
"""skillguard benchmark: how many attacks it catches, how often it cries wolf.

Ship this with the repo so anyone can reproduce the numbers in the README:

    python3 bench/run.py              # shipped fixtures, no network, a few seconds
    python3 bench/run.py --corpus     # also scans third-party skill corpora
    python3 bench/run.py --json       # machine-readable
    python3 bench/run.py --write      # refresh bench/RESULTS.md

Exit code is 1 when a number regresses: an attack is missed, or a benign skill
is flagged High/Critical. That makes it usable as a CI gate.

The third-party corpora are FETCHED at the pinned commits below, never vendored:
anthropics/skills carries no licence, so its content is not redistributed here.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
CACHE = Path(os.environ.get("SKILLGUARD_BENCH_CACHE", Path.home() / ".cache/skillguard-bench"))
FAIL_LEVELS = {"high", "critical"}

# Pinned so a number in the README means something. Bump deliberately.
CORPORA = {
    "anthropics/skills": "8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4",
    "obra/superpowers": "8ca22dba9a94f28898bbce59f2537ff4d87c747d",
}
# Where each repo keeps its skills. anthropics/skills nests them one level deeper.
CORPUS_SUBDIRS = {"anthropics/skills": ["skills"], "obra/superpowers": ["skills"]}


def find_cli() -> list[str]:
    """Prefer the built repo, so the benchmark always tests what is on disk."""
    dist = ROOT.parent / "dist" / "index.js"
    if dist.exists():
        return ["node", str(dist)]
    exe = shutil.which("skillguard")
    if exe:
        return [exe]
    print("No CLI found: run `npm run build` first, or install skillguard.", file=sys.stderr)
    raise SystemExit(2)


def scan(cli: list[str], target: Path) -> dict | None:
    proc = subprocess.run([*cli, "scan", str(target), "--json"], capture_output=True, text=True)
    raw = proc.stdout
    if not raw.strip():
        return None
    # Control characters inside snippets break json.loads; drop them, keep layout.
    cleaned = "".join(ch for ch in raw if ch >= " " or ch in "\n\t")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def scan_group(cli: list[str], kind: str) -> list[dict]:
    out = []
    for d in sorted(p for p in (FIXTURES / kind).iterdir() if p.is_dir()):
        res = scan(cli, d)
        if res is None:
            out.append({"name": d.name, "level": "error", "score": 0, "findings": 0})
            continue
        lows = sum(1 for f in res["codeFindings"] if f["severity"] == "low")
        high = [f for f in res["codeFindings"] if f["severity"] in FAIL_LEVELS]
        out.append({
            "name": d.name,
            "level": res["riskLevel"],
            "score": res["riskScore"],
            "findings": len(res["codeFindings"]),
            "lows": lows,
            "categories": sorted({f["category"] for f in high}),
        })
    return out


def fetch_corpus(repo: str, commit: str) -> Path | None:
    dest = CACHE / repo.replace("/", "__") / commit[:12]
    if dest.exists():
        return dest
    if not shutil.which("git"):
        print("git not found, skipping corpora", file=sys.stderr)
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"fetching {repo}@{commit[:12]} ...", file=sys.stderr)
    proc = subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none",
                           f"https://github.com/{repo}.git", str(dest)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"  clone failed: {proc.stderr.strip()[:200]}", file=sys.stderr)
        return None
    # Record what was actually tested, even if the pin moves under us.
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    (dest / ".skillguard-bench-head").write_text(head + "\n")
    return dest


def scan_corpora(cli: list[str]) -> dict:
    result = {}
    for repo, commit in CORPORA.items():
        root = fetch_corpus(repo, commit)
        if root is None:
            result[repo] = None
            continue
        skills = []
        for sub in CORPUS_SUBDIRS[repo]:
            base = root / sub
            if base.is_dir():
                for d in sorted(p for p in base.iterdir() if p.is_dir() and (p / "SKILL.md").exists()):
                    res = scan(cli, d)
                    if res:
                        skills.append({"name": d.name, "level": res["riskLevel"],
                                       "score": res["riskScore"]})
        flagged = [s for s in skills if s["level"] in FAIL_LEVELS]
        result[repo] = {"commit": commit, "count": len(skills),
                        "flagged": flagged,
                        "by_level": {lvl: sum(1 for s in skills if s["level"] == lvl)
                                     for lvl in ("safe", "low", "medium", "high", "critical")}}
    return result


def summarise(attacks, disguised, benign, context, corpora) -> dict:
    caught = [f for f in attacks + disguised if f["level"] in FAIL_LEVELS]
    missed = [f for f in attacks + disguised if f["level"] not in FAIL_LEVELS]
    false_alarms = [f for f in benign if f["level"] in FAIL_LEVELS]
    corpus_flagged = [s for c in corpora.values() if c for s in c["flagged"]]
    corpus_count = sum(c["count"] for c in corpora.values() if c)
    return {
        "attacks": len(attacks), "disguised": len(disguised),
        "caught": len(caught), "missed": missed,
        "benign": len(benign), "false_alarms": false_alarms,
        "context": [{"name": f["name"], "level": f["level"], "score": f["score"]} for f in context],
        "corpus_skills": corpus_count, "corpus_flagged": corpus_flagged,
        "regressed": bool(missed or false_alarms),
    }


def render(attacks, disguised, benign, context, s, corpora, version: str) -> str:
    def caught(group):
        return len([f for f in group if f["level"] in FAIL_LEVELS])

    total = len(attacks) + len(disguised)
    lines = [
        f"# Benchmark results ({version})",
        "",
        f"Generated by `python3 bench/run.py --corpus --write` on "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
        "## Detection",
        "",
        "| Set | Caught | Total |",
        "|---|---:|---:|",
        f"| Malicious skills | {caught(attacks)} | {len(attacks)} |",
        f"| Disguised as documentation | {caught(disguised)} | {len(disguised)} |",
        f"| **Total** | **{caught(attacks) + caught(disguised)}** | **{total}** |",
        "",
        "## False alarms",
        "",
        "| Set | Flagged High/Critical | Total |",
        "|---|---:|---:|",
        f"| Ordinary skills | {len(s['false_alarms'])} | {len(benign)} |",
        f"| Third-party trusted skills | {len(s['corpus_flagged'])} | {s['corpus_skills']} |",
        "",
        "## Context-dependent fixtures (shown, not scored)",
        "",
        "These are reported, deliberately not scored: a rule cannot tell an",
        "instruction from a description of an attack. Each one is listed here with",
        "the verdict it gets, so the cost is visible instead of hidden.",
        "",
        "| Fixture | Verdict | Score | Why it is here |",
        "|---|---|---:|---|",
    ]
    WHYS = {
        "keychain-audit": "describes reading the keychain while auditing",
        "own-binary-quarantine": "clears the quarantine flag off your own build output",
        "threat-writeup": "explains how an attack worked",
    }
    for c in s["context"]:
        lines.append(f"| {c['name']} | {c['level']} | {c['score']} | {WHYS.get(c['name'], '')} |")
    if s["corpus_flagged"]:
        lines += ["", "### Third-party skills flagged", "",
                  "| Skill | Level | Score |", "|---|---|---:|"]
        for f in s["corpus_flagged"]:
            lines.append(f"| {f['name']} | {f['level']} | {f['score']} |")
    if s["missed"]:
        lines += ["", "### Missed", ""] + [
            f"- {m['name']} ({m['level']} {m['score']})" for m in s["missed"]
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="skillguard benchmark")
    ap.add_argument("--corpus", action="store_true", help="also scan third-party skill corpora")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--write", action="store_true", help="write bench/RESULTS.md")
    args = ap.parse_args()

    cli = find_cli()
    version = subprocess.run([*cli, "--version"], capture_output=True, text=True).stdout.strip()

    attacks = scan_group(cli, "attacks")
    disguised = scan_group(cli, "disguised")
    benign = scan_group(cli, "benign")
    context = scan_group(cli, "context")
    corpora = scan_corpora(cli) if args.corpus else {}

    s = summarise(attacks, disguised, benign, context, corpora)
    if args.json:
        print(json.dumps({"version": version, "summary": s, "corpora": corpora,
                          "attacks": attacks, "disguised": disguised,
                          "benign": benign, "context": context}, indent=1))
    else:
        print(f"skillguard {version}\n")
        print(f"detection   {s['caught']}/{s['attacks'] + s['disguised']} attacks caught"
              f"  ({s['attacks']} malicious, {s['disguised']} disguised)")
        if s["missed"]:
            for m in s["missed"]:
                print(f"  MISSED  {m['name']:28} {m['level']} {m['score']}")
        extra = f" + {len(s['corpus_flagged'])}/{s['corpus_skills']} trusted" if corpora else ""
        print(f"false alarm {len(s['false_alarms'])}/{s['benign']} ordinary skills flagged{extra}")
        for f in s["false_alarms"]:
            print(f"  FLAGGED {f['name']:28} {f['level']} {f['score']}")
        for f in s["corpus_flagged"]:
            print(f"  FLAGGED {f['name']:28} {f['level']} {f['score']} (corpus)")
        print("\ncontext-dependent fixtures (shown, not scored):")
        for c in s["context"]:
            print(f"  {c['name']:28} {c['level']} {c['score']}")
            print(f"  {'':28} → a model second opinion could settle these")
    if args.write:
        (ROOT / "RESULTS.md").write_text(
            render(attacks, disguised, benign, context, s, corpora, version)
        )
        print("\nwrote bench/RESULTS.md")
    return 1 if s["regressed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
