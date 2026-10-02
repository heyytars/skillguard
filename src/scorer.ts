/**
 * SkillGuard Risk Scorer
 *
 * Why the score is not a plain sum
 * --------------------------------
 * A skill that opens five files for writing is not five times riskier than one
 * that opens a single file. Counting every occurrence made ordinary skills
 * (Anthropic's own `pdf` and `docx` tools) score CRITICAL, which teaches people
 * to ignore the tool.
 *
 * So findings are split in two:
 *
 *  - **Capabilities**: what a normal tool does anyway, like running a command,
 *    writing a file, calling an API. Worth knowing, worth reviewing, but not
 *    proof of anything. They add up to CAPABILITY_CEILING at most, so a pile of
 *    them can never fail a scan on its own.
 *  - **Threats**: patterns that only make sense if someone means harm, like
 *    reading credentials and sending them out, prompt injection, hidden
 *    instructions, downloaded-and-run payloads. These score in full.
 *
 *   score = min(100, min(capability total, 30) + threat total)
 *
 * Each category counts once, by its worst finding, and one critical threat is
 * lifted to the "high" band so it can never come out medium or safe.
 */

import { Finding, DependencyFinding, ScanResult } from './types';
import { getConfigLoader } from './config';

/**
 * Capability categories: real, but present in plenty of honest tools.
 * Anything not listed here counts as a threat, so a new category can never
 * slip through quietly.
 */
const CAPABILITIES = new Set([
  'Shell Execution',
  'File System Write',
  'File Operations',
  'File System Delete',
  'File System Modification',
  'File System Permissions',
  'Network Access',
  'Environment Access',
  'Dynamic Import',
  'Server Variables',
  'SQL Operations',
  'Format String',
  'Type Casting',
  'Reflection',
  'Dynamic Method Call',
  'Memory Management',
  'Memory Operations',
  'Unsafe Pointers',
  'Unsafe Code',
  'Buffer Overflow',
  'Deserialization',
  'Credential Handling',
]);

/**
 * Capabilities alone can never score past this. It sits below the "high" band
 * (51), so reviewing capabilities is a decision, not a failed scan.
 */
export const CAPABILITY_CEILING = 30;

export function isCapability(category: string): boolean {
  return CAPABILITIES.has(category);
}

/**
 * Calculate risk score from findings. 0 = safe, 100 = critical.
 */
export function calculateRiskScore(
  codeFindings: Finding[],
  dependencyFindings: DependencyFinding[],
): number {
  const configLoader = getConfigLoader();

  const perCategory = new Map<string, number>();
  const bump = (category: string, points: number): void => {
    if (points > (perCategory.get(category) ?? 0)) perCategory.set(category, points);
  };

  for (const finding of codeFindings) {
    // Points come from severity alone, so how a rule is written decides its
    // weight and a category can never quietly outvote it.
    bump(finding.category, configLoader.getSeverityWeight(finding.severity));
  }

  for (const finding of dependencyFindings) {
    // Grouped by kind of problem, so 30 vulnerable packages don't reach 100 by volume alone.
    const label =
      finding.source === 'npm-audit' || finding.source === 'osv'
        ? 'Vulnerable Dependency'
        : 'Suspicious Dependency';
    bump(label, configLoader.getSeverityWeight(finding.severity));
  }

  let capabilities = 0;
  let threats = 0;
  for (const [category, points] of perCategory) {
    if (isCapability(category)) capabilities += points;
    else threats += points;
  }

  // Capabilities can add detail; only threats can fail a skill.
  let total = Math.min(capabilities, CAPABILITY_CEILING) + threats;

  // A critical threat is never "safe" or "low", whatever the arithmetic says:
  // lift it into the "high" band so the score and the verdict agree.
  const hasCriticalThreat = codeFindings.some(
    (f) => f.severity === 'critical' && !isCapability(f.category),
  );
  if (hasCriticalThreat) {
    total = Math.max(total, configLoader.getThresholds().high ?? 51);
  }

  return Math.min(total, 100);
}

/**
 * Determine risk level from a score.
 *
 * The score already accounts for critical findings (see calculateRiskScore),
 * so this is a plain band lookup.
 */
export function getRiskLevel(score: number): ScanResult['riskLevel'] {
  return getConfigLoader().getRiskLevel(score);
}

/**
 * Get risk statistics for reporting
 */
export function getRiskStats(
  codeFindings: Finding[],
  dependencyFindings: DependencyFinding[],
): {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
} {
  const counts = {
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
  };

  const tally = (severity: Finding['severity']): void => {
    switch (severity) {
      case 'critical':
        counts.criticalCount++;
        break;
      case 'high':
        counts.highCount++;
        break;
      case 'medium':
        counts.mediumCount++;
        break;
      case 'low':
        counts.lowCount++;
        break;
    }
  };

  for (const finding of codeFindings) tally(finding.severity);
  for (const finding of dependencyFindings) tally(finding.severity);

  return counts;
}
