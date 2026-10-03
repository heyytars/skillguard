/**
 * skillguard Dependency Inspector
 * Checks package.json dependencies against a threat database
 * and integrates with npm audit and OSV for real vulnerability detection
 */

import * as fs from 'fs';
import * as path from 'path';
import { DependencyFinding, ThreatEntry, RiskSeverity } from './types';
import { scanVulnerabilities } from './vulnerabilities';

/**
 * Mock Threat Database
 * In production, this would be fetched from a real vulnerability database
 */
const THREAT_DATABASE: ThreatEntry[] = [
  // Known malicious packages
  {
    name: 'evil-package',
    reason: 'Known malicious package - contains cryptocurrency miner',
    severity: 'critical',
  },
  { name: 'crypto-miner', reason: 'Cryptocurrency mining malware', severity: 'critical' },
  {
    name: 'flatmap-stream',
    reason: 'Compromised package - event-stream incident',
    severity: 'critical',
  },
  { name: 'event-stream', reason: 'Compromised package version (historical)', severity: 'high' },
  { name: 'ua-parser-js', reason: 'Previously compromised - check version', severity: 'high' },
  { name: 'coa', reason: 'Previously compromised - check version', severity: 'high' },
  { name: 'rc', reason: 'Previously compromised - check version', severity: 'high' },

  // Typosquatting patterns
  {
    name: 'crossenv',
    reason: 'Typosquatting of cross-env - malicious package',
    severity: 'critical',
  },
  {
    name: 'cross-env.js',
    reason: 'Typosquatting of cross-env - malicious package',
    severity: 'critical',
  },
  {
    name: 'mongose',
    reason: 'Typosquatting of mongoose - malicious package',
    severity: 'critical',
  },
  { name: 'lodahs', reason: 'Typosquatting of lodash - malicious package', severity: 'critical' },
  {
    name: 'expresss',
    reason: 'Typosquatting of express - malicious package',
    severity: 'critical',
  },

  // Suspicious patterns
  { name: 'hack-tool', reason: 'Potentially malicious hacking tool', severity: 'high' },
  {
    name: 'password-stealer',
    reason: 'Suspicious package name - potential credential theft',
    severity: 'critical',
  },
  {
    name: 'keylogger',
    reason: 'Suspicious package name - potential keylogging',
    severity: 'critical',
  },
  {
    name: 'backdoor',
    reason: 'Suspicious package name - potential backdoor',
    severity: 'critical',
  },

  // Deprecated/Risky packages
  {
    name: 'request',
    reason: 'Deprecated package - consider using node-fetch or axios',
    severity: 'low',
  },
  { name: 'node-uuid', reason: 'Deprecated - use uuid package instead', severity: 'low' },
];

/**
 * Suspicious package name patterns
 */
const SUSPICIOUS_PATTERNS: Array<{ pattern: RegExp; reason: string; severity: RiskSeverity }> = [
  {
    pattern: /^npm-/,
    reason: 'Suspicious package prefix - potential typosquatting',
    severity: 'medium',
  },
  { pattern: /stealer|steal/i, reason: 'Suspicious name - potential data theft', severity: 'high' },
  {
    pattern: /keylog|logger.*key/i,
    reason: 'Suspicious name - potential keylogging',
    severity: 'high',
  },
  {
    pattern: /backdoor|rootkit|trojan/i,
    reason: 'Suspicious name - potential malware',
    severity: 'critical',
  },
  {
    pattern: /miner|mining|coin/i,
    reason: 'Suspicious name - potential cryptominer',
    severity: 'medium',
  },
];

/**
 * Interface for package.json structure
 */
interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * Read and parse package.json from directory
 */
export function readPackageJson(targetDir: string): PackageJson | null {
  const packagePath = path.join(targetDir, 'package.json');

  if (!fs.existsSync(packagePath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(packagePath, 'utf-8');
    return JSON.parse(content);
  } catch (_error) {
    return null;
  }
}

/**
 * Get all dependencies from package.json
 */
export function getAllDependencies(packageJson: PackageJson): string[] {
  const deps = new Set<string>();

  const addDeps = (depObj?: Record<string, string>) => {
    if (depObj) {
      Object.keys(depObj).forEach((dep) => deps.add(dep));
    }
  };

  addDeps(packageJson.dependencies);
  addDeps(packageJson.devDependencies);
  addDeps(packageJson.peerDependencies);
  addDeps(packageJson.optionalDependencies);

  return Array.from(deps);
}

/**
 * Check a single dependency against threat database
 */
function checkDependency(depName: string): DependencyFinding | null {
  // Check against known threats
  const threat = THREAT_DATABASE.find((t) => t.name.toLowerCase() === depName.toLowerCase());
  if (threat) {
    return {
      name: depName,
      severity: threat.severity,
      reason: threat.reason,
      source: 'threat-db',
    };
  }

  // Check against suspicious patterns
  for (const { pattern, reason, severity } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(depName)) {
      return {
        name: depName,
        severity,
        reason,
        source: 'pattern',
      };
    }
  }

  return null;
}

/**
 * Inspect all dependencies in a directory (synchronous, threat DB only)
 * Use inspectDependenciesAsync for full vulnerability scanning
 */
export function inspectDependencies(targetDir: string): DependencyFinding[] {
  const findings: DependencyFinding[] = [];

  const packageJson = readPackageJson(targetDir);
  if (!packageJson) {
    return findings;
  }

  const dependencies = getAllDependencies(packageJson);

  for (const dep of dependencies) {
    const finding = checkDependency(dep);
    if (finding) {
      findings.push(finding);
    }
  }

  return sortFindings(findings);
}

/**
 * Full async dependency inspection with real vulnerability scanning
 * Combines threat database checks with npm audit and OSV database queries
 */
export async function inspectDependenciesAsync(targetDir: string): Promise<DependencyFinding[]> {
  const findings: DependencyFinding[] = [];

  const packageJson = readPackageJson(targetDir);
  if (!packageJson) {
    return findings;
  }

  const dependencies = getAllDependencies(packageJson);

  // Check against local threat database first (fast)
  for (const dep of dependencies) {
    const finding = checkDependency(dep);
    if (finding) {
      findings.push(finding);
    }
  }

  // Scan for real vulnerabilities using npm audit and OSV
  try {
    const vulnerabilities = await scanVulnerabilities(targetDir);

    // Add vulnerabilities, avoiding duplicates
    const existingKeys = new Set(findings.map((f) => f.name.toLowerCase()));

    for (const vuln of vulnerabilities) {
      // Don't duplicate if already found by threat DB (but allow multiple vulns per package)
      const key = `${vuln.name.toLowerCase()}:${vuln.cveId || vuln.reason}`;
      if (!existingKeys.has(key)) {
        findings.push(vuln);
        existingKeys.add(key);
      }
    }
  } catch {
    // Vulnerability scanning failed, continue with threat DB results only
    // This can happen due to network issues or missing lock files
  }

  return sortFindings(findings);
}

/**
 * Sort findings by severity
 */
function sortFindings(findings: DependencyFinding[]): DependencyFinding[] {
  const severityOrder: Record<RiskSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  return findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}

/**
 * Get dependency count for reporting
 */
export function getDependencyCount(targetDir: string): number {
  const packageJson = readPackageJson(targetDir);
  if (!packageJson) {
    return 0;
  }
  return getAllDependencies(packageJson).length;
}
