/**
 * SkillGuard UI/Reporter
 * Beautiful CLI output with hacker aesthetic
 */

import chalk from 'chalk';
import boxen from 'boxen';
import figlet from 'figlet';
import ora from 'ora';
import * as path from 'path';
import { ScanResult, Finding, DependencyFinding, RiskSeverity } from './types';
import { version } from '../package.json';

/**
 * Color scheme for hacker aesthetic
 */
const colors = {
  primary: chalk.cyan,
  secondary: chalk.gray,
  success: chalk.green,
  warning: chalk.yellow,
  danger: chalk.red,
  critical: chalk.bgRed.white.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  safe: chalk.green,
  accent: chalk.magenta,
  dim: chalk.dim,
  bold: chalk.bold,
};

/**
 * Display ASCII logo
 */
export function showLogo(): void {
  console.log();
  console.log(
    colors.primary(
      figlet.textSync('SKILLGUARD', {
        font: 'ANSI Shadow',
        horizontalLayout: 'default',
      }),
    ),
  );
  const banner = (text: string): string =>
    colors.secondary('  ║') + colors.dim(`  ${text}`.padEnd(58)) + colors.secondary('║');
  console.log(colors.secondary(`  ╔${'═'.repeat(58)}╗`));
  console.log(banner(`AI Agent Skill Security Scanner v${version}`));
  console.log(banner('Detecting security risks before they become threats'));
  console.log(colors.secondary(`  ╚${'═'.repeat(58)}╝`));
  console.log();
}

/**
 * Create a spinner for scanning
 */
export function createSpinner(text: string): ora.Ora {
  return ora({
    text: colors.primary(text),
    spinner: 'dots12',
    color: 'cyan',
  });
}

/**
 * Get color for risk level
 */
function getRiskLevelColor(level: ScanResult['riskLevel']): chalk.Chalk {
  switch (level) {
    case 'safe':
      return colors.success;
    case 'low':
      return colors.low;
    case 'medium':
      return colors.warning;
    case 'high':
      return colors.danger;
    case 'critical':
      return colors.critical;
    default:
      return colors.secondary;
  }
}

/**
 * Format severity badge
 */
function formatSeverityBadge(severity: RiskSeverity): string {
  const badges: Record<RiskSeverity, string> = {
    critical: colors.critical(' CRITICAL '),
    high: colors.high('   HIGH   '),
    medium: colors.medium('  MEDIUM  '),
    low: colors.low('   LOW    '),
  };
  return badges[severity];
}

/**
 * Format file path for display (relative to target)
 */
function formatFilePath(filePath: string, basePath: string): string {
  return path.relative(basePath, filePath);
}

/**
 * Display detailed vulnerability finding
 */
function displayVulnerabilityFinding(finding: DependencyFinding): void {
  console.log();

  // Package name with version if available
  const pkgDisplay = finding.version ? `${finding.name}@${finding.version}` : finding.name;
  console.log(`    ${formatSeverityBadge(finding.severity)} ${colors.bold(pkgDisplay)}`);

  // CVE ID if available
  if (finding.cveId) {
    console.log(`      ${colors.dim('CVE:')} ${colors.danger(finding.cveId)}`);
  }

  // CVSS Score if available
  if (finding.cvssScore !== undefined) {
    const cvssColor =
      finding.cvssScore >= 9.0
        ? colors.critical
        : finding.cvssScore >= 7.0
          ? colors.danger
          : finding.cvssScore >= 4.0
            ? colors.warning
            : colors.low;
    console.log(`      ${colors.dim('CVSS Score:')} ${cvssColor(finding.cvssScore.toFixed(1))}`);
  }

  // Vulnerability description
  console.log(`      ${colors.dim('Issue:')} ${finding.reason}`);

  // Vulnerable version range
  if (finding.vulnerableVersions) {
    console.log(`      ${colors.dim('Affected:')} ${finding.vulnerableVersions}`);
  }

  // Fix available
  if (finding.fixAvailable) {
    console.log(`      ${colors.dim('Fix:')} ${colors.success(finding.fixAvailable)}`);
  }

  // Source
  if (finding.source) {
    const sourceLabel =
      finding.source === 'npm-audit'
        ? 'npm audit'
        : finding.source === 'osv'
          ? 'OSV Database'
          : finding.source;
    console.log(`      ${colors.dim('Source:')} ${colors.secondary(sourceLabel)}`);
  }

  // Reference URL
  if (finding.url) {
    console.log(`      ${colors.dim('More info:')} ${colors.primary(finding.url)}`);
  }
}

/**
 * Display the scan report
 */
export function showReport(result: ScanResult, targetDir: string): void {
  const levelColor = getRiskLevelColor(result.riskLevel);

  // Header with risk level. Every inner line is padded to exactly W columns
  // so the right border lines up whatever the level text is.
  const riskLevelText = result.riskLevel.toUpperCase();
  const W = 62;
  const row = (text: string): string => `  ║${text.padEnd(W)}║`;
  const header = levelColor(
    [
      '',
      `  ╔${'═'.repeat(W)}╗`,
      row(''),
      row(`${' '.repeat(20)}SCAN COMPLETE`),
      row(`${' '.repeat(20)}Risk Level: ${riskLevelText}`),
      row(''),
      `  ╚${'═'.repeat(W)}╝`,
      '',
    ].join('\n'),
  );

  console.log(header);

  // Summary statistics
  console.log(colors.bold('\n  📊 SCAN SUMMARY'));
  console.log(colors.secondary('  ─────────────────────────────────────────'));
  console.log(
    `  ${colors.dim('Files Scanned:')}     ${colors.primary(result.scannedFiles.toString())}`,
  );
  console.log(
    `  ${colors.dim('Scan Duration:')}     ${colors.primary(result.scanDuration + 'ms')}`,
  );
  console.log(
    `  ${colors.dim('Code Issues:')}       ${colors.primary(result.codeFindingsCount.toString())}`,
  );
  console.log(
    `  ${colors.dim('Dependency Issues:')} ${colors.primary(result.dependencyFindingsCount.toString())}`,
  );
  console.log();

  // Code findings section
  if (result.codeFindings.length > 0) {
    console.log(colors.bold('\n  🔍 CODE ANALYSIS FINDINGS'));
    console.log(colors.secondary('  ─────────────────────────────────────────'));

    // Group findings by severity
    const grouped = groupFindingsBySeverity(result.codeFindings);

    for (const severity of ['critical', 'high', 'medium', 'low'] as RiskSeverity[]) {
      const findings = grouped[severity];
      if (findings && findings.length > 0) {
        console.log(
          `\n  ${formatSeverityBadge(severity)} ${colors.bold(`(${findings.length} issue${findings.length > 1 ? 's' : ''})`)}`,
        );

        for (const finding of findings) {
          const relPath = formatFilePath(finding.file, targetDir);
          console.log();
          console.log(
            `    ${colors.accent('►')} ${colors.primary(relPath)}${colors.dim(`:${finding.line}:${finding.column}`)}`,
          );
          console.log(`      ${colors.dim('Category:')} ${finding.category}`);
          console.log(`      ${colors.dim('Issue:')} ${finding.description}`);
          console.log(
            `      ${colors.dim('Code:')} ${colors.secondary(finding.codeSnippet.substring(0, 60))}${finding.codeSnippet.length > 60 ? '...' : ''}`,
          );
        }
      }
    }
  }

  // Dependency findings section
  if (result.dependencyFindings.length > 0) {
    console.log(colors.bold('\n\n  📦 DEPENDENCY VULNERABILITY FINDINGS'));
    console.log(colors.secondary('  ─────────────────────────────────────────'));

    // Group by source for better organization
    const vulnFindings = result.dependencyFindings.filter(
      (f) => f.source === 'npm-audit' || f.source === 'osv',
    );
    const threatDbFindings = result.dependencyFindings.filter(
      (f) => f.source === 'threat-db' || f.source === 'pattern' || !f.source,
    );

    // Show real vulnerabilities first
    if (vulnFindings.length > 0) {
      console.log(colors.accent('\n  ► Known Vulnerabilities (CVE/Advisory)'));
      for (const finding of vulnFindings) {
        displayVulnerabilityFinding(finding);
      }
    }

    // Show threat database matches
    if (threatDbFindings.length > 0) {
      console.log(colors.accent('\n  ► Threat Database Matches'));
      for (const finding of threatDbFindings) {
        console.log();
        console.log(`    ${formatSeverityBadge(finding.severity)} ${colors.bold(finding.name)}`);
        console.log(`      ${colors.dim('Reason:')} ${finding.reason}`);
      }
    }
  }

  // No issues found
  if (result.codeFindings.length === 0 && result.dependencyFindings.length === 0) {
    console.log(colors.success('\n  ✓ No security issues detected!'));
    console.log(colors.dim('    The scanned code appears to be safe.'));
  }

  // Risk score footer
  const scoreColor =
    result.riskScore <= 20
      ? colors.success
      : result.riskScore <= 50
        ? colors.warning
        : colors.danger;

  const scoreBar = createScoreBar(result.riskScore);

  console.log('\n');
  console.log(
    boxen(
      `${colors.bold('RISK SCORE')}\n\n` +
        `${scoreBar}\n\n` +
        `${scoreColor(result.riskScore.toString())} ${colors.dim('/ 100')}\n\n` +
        `${colors.dim('Risk Level:')} ${levelColor(riskLevelText)}`,
      {
        padding: 1,
        margin: { top: 0, bottom: 0, left: 2, right: 2 },
        borderStyle: 'round',
        borderColor: result.riskScore <= 20 ? 'green' : result.riskScore <= 50 ? 'yellow' : 'red',
        title: '[ ASSESSMENT ]',
        titleAlignment: 'center',
      },
    ),
  );

  // Recommendations
  if (result.riskScore > 0) {
    console.log(colors.bold('\n  💡 RECOMMENDATIONS'));
    console.log(colors.secondary('  ─────────────────────────────────────────'));

    if (result.codeFindings.some((f) => f.severity === 'critical')) {
      console.log(
        colors.danger(
          '  ⚠ CRITICAL: Do not install this skill. Review shell execution and eval() usage.',
        ),
      );
    }
    if (
      result.codeFindings.some(
        (f) => f.category === 'File System Write' || f.category === 'File System Delete',
      )
    ) {
      console.log(
        colors.warning('  ⚠ Review file system operations for malicious write/delete actions.'),
      );
    }
    if (result.codeFindings.some((f) => f.category === 'Network Access')) {
      console.log(
        colors.medium('  ⚠ Verify network requests are legitimate and not exfiltrating data.'),
      );
    }
    if (result.dependencyFindings.length > 0) {
      const hasVulns = result.dependencyFindings.some(
        (f) => f.source === 'npm-audit' || f.source === 'osv',
      );
      const hasFixable = result.dependencyFindings.some((f) => f.fixAvailable);
      const hasCriticalVulns = result.dependencyFindings.some(
        (f) => f.severity === 'critical' && (f.source === 'npm-audit' || f.source === 'osv'),
      );

      if (hasCriticalVulns) {
        console.log(
          colors.danger(
            '  ⚠ CRITICAL vulnerabilities found! Update affected packages immediately.',
          ),
        );
      }
      if (hasVulns) {
        console.log(colors.warning('  ⚠ Known vulnerabilities detected in dependencies.'));
      }
      if (hasFixable) {
        console.log(
          colors.success('  ✓ Some vulnerabilities have fixes available. Run: npm audit fix'),
        );
      }
      if (!hasVulns && result.dependencyFindings.length > 0) {
        console.log(colors.warning('  ⚠ Review flagged dependencies before installing.'));
      }
    }
  }

  console.log('\n');
}

/**
 * Create a visual score bar
 */
function createScoreBar(score: number): string {
  const width = 30;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;

  const color = score <= 20 ? colors.success : score <= 50 ? colors.warning : colors.danger;

  const bar = color('█'.repeat(filled)) + colors.dim('░'.repeat(empty));
  return `[${bar}]`;
}

/**
 * Group findings by severity
 */
function groupFindingsBySeverity(findings: Finding[]): Record<RiskSeverity, Finding[]> {
  const grouped: Record<RiskSeverity, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

/**
 * Show error message
 */
export function showError(message: string): void {
  console.log();
  console.log(
    boxen(colors.danger(`✖ ERROR\n\n${message}`), {
      padding: 1,
      margin: { top: 0, bottom: 0, left: 2, right: 2 },
      borderStyle: 'round',
      borderColor: 'red',
    }),
  );
  console.log();
}

/**
 * Show success message
 */
export function showSuccess(message: string): void {
  console.log(colors.success(`\n  ✓ ${message}\n`));
}

/**
 * Show info message
 */
export function showInfo(message: string): void {
  console.log(colors.primary(`\n  ℹ ${message}\n`));
}
