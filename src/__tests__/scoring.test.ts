/**
 * Scoring rules, pinned.
 *
 * These are the cases that were wrong before: ordinary capabilities stacked up
 * to CRITICAL and made honest skills look dangerous. Each test names the
 * behaviour it protects so a future change has to argue with it.
 */
import { calculateRiskScore, getRiskLevel, CAPABILITY_CEILING } from '../scorer';
import { Finding, DependencyFinding } from '../types';

const code = (severity: Finding['severity'], category: string): Finding => ({
  severity,
  category,
  description: 'test',
  file: 'test.js',
  line: 1,
  column: 1,
  codeSnippet: 'test',
  language: 'javascript',
});

describe('scoring: capabilities', () => {
  it('does not let a pile of file writes reach CRITICAL', () => {
    const findings = Array.from({ length: 5 }, () => code('high', 'File System Write'));
    const score = calculateRiskScore(findings, []);
    expect(score).toBeLessThanOrEqual(CAPABILITY_CEILING);
    expect(getRiskLevel(score)).not.toBe('critical');
  });

  it('keeps a skill that only runs commands and writes files at medium or below', () => {
    const findings = [
      code('critical', 'Shell Execution'),
      code('high', 'File System Write'),
      code('high', 'File System Permissions'),
      code('high', 'Network Access'),
    ];
    const score = calculateRiskScore(findings, []);
    expect(score).toBeLessThanOrEqual(50);
    expect(['safe', 'low', 'medium']).toContain(getRiskLevel(score));
  });

  it('scores a lone shell call as worth reviewing, not condemning', () => {
    const score = calculateRiskScore([code('critical', 'Shell Execution')], []);
    expect(getRiskLevel(score)).toBe('medium');
  });

  it('counts a category once by its worst finding', () => {
    const once = calculateRiskScore([code('high', 'Shell Execution')], []);
    const five = calculateRiskScore(
      Array.from({ length: 5 }, () => code('high', 'Shell Execution')),
      [],
    );
    expect(five).toBe(once);
  });
});

describe('scoring: threats', () => {
  it('fails a lone eval() rather than shrugging it off as medium', () => {
    const score = calculateRiskScore([code('critical', 'Code Injection')], []);
    expect(['high', 'critical']).toContain(getRiskLevel(score));
  });

  it('scores eval() plus exec() worse than eval() alone', () => {
    const evalOnly = calculateRiskScore([code('critical', 'Code Injection')], []);
    const both = calculateRiskScore(
      [code('critical', 'Code Injection'), code('critical', 'Shell Execution')],
      [],
    );
    expect(both).toBeGreaterThan(evalOnly);
    expect(getRiskLevel(both)).toBe('critical');
  });

  it('fails a credential exfiltration even with no capabilities', () => {
    const score = calculateRiskScore(
      [code('critical', 'Credential Theft'), code('high', 'Data Exfiltration')],
      [],
    );
    expect(['high', 'critical']).toContain(getRiskLevel(score));
  });

  it('lifts a lone critical threat into the high band', () => {
    const score = calculateRiskScore([code('critical', 'Data Exfiltration')], []);
    expect(score).toBeGreaterThanOrEqual(51);
    expect(['high', 'critical']).toContain(getRiskLevel(score));
  });

  it('treats an unknown category as a threat, not a capability', () => {
    const score = calculateRiskScore([code('critical', 'Some New Category')], []);
    expect(['high', 'critical']).toContain(getRiskLevel(score));
  });
});

describe('scoring: low findings are informational', () => {
  it('does not raise the score for low findings alone', () => {
    const score = calculateRiskScore(
      [code('low', 'File System Write'), code('low', 'Prompt Injection')],
      [],
    );
    expect(score).toBe(0);
    expect(getRiskLevel(score)).toBe('safe');
  });

  it('stays put when lows are added to a medium', () => {
    const medium = calculateRiskScore([code('medium', 'Remote Script')], []);
    const withLows = calculateRiskScore(
      [
        code('medium', 'Remote Script'),
        code('low', 'Prompt Injection'),
        code('low', 'Evasion Technique'),
      ],
      [],
    );
    expect(withLows).toBe(medium);
  });
});

describe('scoring: dependencies', () => {
  it('groups vulnerable packages so volume alone does not reach 100', () => {
    const deps: DependencyFinding[] = Array.from({ length: 30 }, () => ({
      name: 'x',
      severity: 'high' as const,
      reason: 'vulnerable',
      source: 'npm-audit' as const,
    }));
    const score = calculateRiskScore([], deps);
    expect(score).toBeLessThan(100);
  });
});
