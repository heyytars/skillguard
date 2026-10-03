import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

import { PAYLOAD_PATTERN_NAMES } from '../analyzers/payload';

/**
 * The total rule count is quoted in the README, the infographic and the docs.
 * It drifted three times, so it is checked rather than trusted: add a rule
 * without updating the docs and this fails.
 *
 * Only *total* claims are matched ("341 built-in rules", "with 341 rules",
 * "now 341 rules"). Per-language counts like "40 rules" for PHP are their own
 * numbers and are deliberately left alone.
 */
const TOTAL_CLAIMS = [
  /(\d+) built-in rules/g,
  /with (\d+) rules/g,
  /of (\d+) rules/g,
  /now (\d+) rules/g,
];

function countRules(): number {
  const dir = join(__dirname, '..', 'analyzers');
  let total = 0;
  for (const file of readdirSync(dir)) {
    if (!file.endsWith('.analyzer.ts')) continue;
    const source = readFileSync(join(dir, file), 'utf-8');
    total += source.match(/^\s+name: '[^']+'/gm)?.length ?? 0;
  }
  return total + PAYLOAD_PATTERN_NAMES.length;
}

const ROOT = join(__dirname, '..', '..');

/** Every claim about the TOTAL in a document. */
function totalClaims(file: string): { claim: string; n: number }[] {
  const text = readFileSync(join(ROOT, file), 'utf-8');
  const out: { claim: string; n: number }[] = [];
  for (const pattern of TOTAL_CLAIMS) {
    for (const m of text.matchAll(pattern)) {
      out.push({ claim: m[0], n: Number(m[1]) });
    }
  }
  return out;
}

describe('documented rule count', () => {
  const actual = countRules();

  it('is a plausible number', () => {
    expect(actual).toBeGreaterThan(300);
  });

  it.each(['README.md', 'CONFIGURATION.md', 'docs/images/infographic.html'])(
    'matches every total stated in %s',
    (file) => {
      const claims = totalClaims(file);
      expect(claims.length).toBeGreaterThan(0);
      const wrong = claims.filter((c) => c.n !== actual).map((c) => `${c.claim} (in ${file})`);
      expect(wrong).toEqual([]);
    },
  );

  it('matches the total note in the coverage report', () => {
    const claims = totalClaims('SECURITY_COVERAGE_REPORT.md');
    expect(claims.map((c) => c.n)).toEqual([actual]);
  });
});
