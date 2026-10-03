/**
 * skillguard Vulnerability Scanner
 * Integrates with npm audit and OSV (Open Source Vulnerabilities) database
 * for real-time vulnerability detection in dependencies
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { DependencyFinding, RiskSeverity } from './types';

/**
 * npm audit vulnerability structure
 */
interface NpmAuditVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | NpmAuditVia>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | NpmFixInfo;
}

interface NpmAuditVia {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: string;
  cwe: string[];
  cvss: {
    score: number;
    vectorString: string;
  };
  range: string;
}

interface NpmFixInfo {
  name: string;
  version: string;
  isSemVerMajor: boolean;
}

interface NpmAuditResult {
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
    dependencies: {
      prod: number;
      dev: number;
      optional: number;
      peer: number;
      peerOptional: number;
      total: number;
    };
  };
}

/**
 * OSV (Open Source Vulnerabilities) API structures
 */
interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  aliases: string[];
  modified: string;
  published: string;
  database_specific?: Record<string, unknown>;
  references: Array<{ type: string; url: string }>;
  affected: Array<{
    package: { ecosystem: string; name: string };
    ranges: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
    versions?: string[];
    database_specific?: { severity?: string };
  }>;
  severity?: Array<{ type: string; score: string }>;
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

interface OsvBatchQueryResponse {
  results?: Array<{ vulns?: OsvVulnerability[] }>;
}

/**
 * Map npm severity levels to our RiskSeverity
 */
function mapNpmSeverity(severity: string): RiskSeverity {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
    case 'info':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Map CVSS score to RiskSeverity
 */
function mapCvssToSeverity(score: number): RiskSeverity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

/**
 * Run npm audit to detect vulnerabilities in dependencies
 */
export async function runNpmAudit(targetDir: string): Promise<DependencyFinding[]> {
  const findings: DependencyFinding[] = [];
  const packageLockPath = path.join(targetDir, 'package-lock.json');
  const packageJsonPath = path.join(targetDir, 'package.json');

  // Check if package.json exists
  if (!fs.existsSync(packageJsonPath)) {
    return findings;
  }

  // Never run npm inside the folder being scanned. It is untrusted: npm would
  // read its .npmrc (which can point at any registry), and generating a lock
  // file would leave a new package-lock.json behind in the user's skill.
  // Copy just the manifest + lock file into a private temp dir and work there.
  // The commands below are fixed strings with no scanned input in them.
  // (yarn.lock is not copied: npm audit can't read it, so we generate a lock.)
  let workDir: string;
  try {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-audit-'));
    fs.copyFileSync(packageJsonPath, path.join(workDir, 'package.json'));
    if (fs.existsSync(packageLockPath)) {
      fs.copyFileSync(packageLockPath, path.join(workDir, 'package-lock.json'));
    }
  } catch {
    return findings;
  }

  try {
    return auditInDir(workDir, findings);
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

function auditInDir(workDir: string, findings: DependencyFinding[]): DependencyFinding[] {
  // Point npm at an empty per-project config so nothing from the scanned
  // folder (or a parent of the temp dir) can change the registry.
  const npmEnv = { ...process.env, npm_config_userconfig: path.join(workDir, '.npmrc-none') };

  if (!fs.existsSync(path.join(workDir, 'package-lock.json'))) {
    // Generate package-lock.json without installing anything
    try {
      execSync('npm install --package-lock-only --ignore-scripts --no-audit --no-fund', {
        cwd: workDir,
        env: npmEnv,
        stdio: 'pipe',
        timeout: 60000,
      });
    } catch {
      // If we can't generate a lock file, fall back to OSV queries
      return findings;
    }
  }

  try {
    // Run npm audit with JSON output
    const result = execSync('npm audit --json 2>/dev/null || true', {
      cwd: workDir,
      env: npmEnv,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large projects
      timeout: 120000, // 2 minute timeout
    });

    if (!result || result.trim() === '') {
      return findings;
    }

    const auditResult: NpmAuditResult = JSON.parse(result);

    // Process vulnerabilities
    if (auditResult.vulnerabilities) {
      for (const [pkgName, vuln] of Object.entries(auditResult.vulnerabilities)) {
        // Get detailed vulnerability info from 'via' field
        const viaDetails = vuln.via.find(
          (v): v is NpmAuditVia => typeof v === 'object' && 'title' in v,
        );

        let reason = `Vulnerable package detected`;
        let url: string | undefined;
        let cvssScore: number | undefined;
        let cveId: string | undefined;

        if (viaDetails) {
          reason = viaDetails.title || reason;
          url = viaDetails.url;
          cvssScore = viaDetails.cvss?.score;

          // Extract CVE from CWE or URL
          if (viaDetails.url && viaDetails.url.includes('CVE-')) {
            const cveMatch = viaDetails.url.match(/CVE-\d{4}-\d+/);
            if (cveMatch) cveId = cveMatch[0];
          }
        }

        // Determine fix availability
        let fixAvailable: string | undefined;
        if (typeof vuln.fixAvailable === 'object' && vuln.fixAvailable) {
          fixAvailable = `${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`;
        } else if (vuln.fixAvailable === true) {
          fixAvailable = 'Available (run npm audit fix)';
        }

        findings.push({
          name: pkgName,
          severity: mapNpmSeverity(vuln.severity),
          reason,
          vulnerableVersions: vuln.range,
          cveId,
          cvssScore,
          source: 'npm-audit',
          fixAvailable,
          url,
        });
      }
    }
  } catch (_error) {
    // npm audit failed - could be network issue, private registry, etc.
    // Silently continue as OSV check will be performed separately
  }

  return findings;
}

/**
 * Query OSV (Open Source Vulnerabilities) database for a specific package
 */
async function queryOsv(packageName: string, version: string): Promise<OsvVulnerability[]> {
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        package: {
          name: packageName,
          ecosystem: 'npm',
        },
        version: version,
      }),
    });

    if (!response.ok) {
      return [];
    }

    const data = (await response.json()) as OsvQueryResponse;
    return data.vulns || [];
  } catch {
    // Network error or API unavailable
    return [];
  }
}

/**
 * Query OSV for multiple packages in batch
 */
async function batchQueryOsv(
  packages: Array<{ name: string; version: string }>,
): Promise<Map<string, OsvVulnerability[]>> {
  const results = new Map<string, OsvVulnerability[]>();

  // OSV API supports batch queries
  try {
    const queries = packages.map((pkg) => ({
      package: {
        name: pkg.name,
        ecosystem: 'npm',
      },
      version: pkg.version,
    }));

    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ queries }),
    });

    if (!response.ok) {
      // Fall back to individual queries
      for (const pkg of packages) {
        const vulns = await queryOsv(pkg.name, pkg.version);
        if (vulns.length > 0) {
          results.set(`${pkg.name}@${pkg.version}`, vulns);
        }
      }
      return results;
    }

    const data = (await response.json()) as OsvBatchQueryResponse;

    // Process batch response
    if (data.results) {
      for (let i = 0; i < data.results.length; i++) {
        const pkg = packages[i];
        const vulns = data.results[i].vulns || [];
        if (vulns.length > 0) {
          results.set(`${pkg.name}@${pkg.version}`, vulns);
        }
      }
    }
  } catch {
    // Network error - try individual queries as fallback
    for (const pkg of packages) {
      try {
        const vulns = await queryOsv(pkg.name, pkg.version);
        if (vulns.length > 0) {
          results.set(`${pkg.name}@${pkg.version}`, vulns);
        }
      } catch {
        // Skip this package
      }
    }
  }

  return results;
}

/**
 * Parse package-lock.json to get all dependencies with versions
 */
function parseLockFile(
  targetDir: string,
): Array<{ name: string; version: string; isDev: boolean }> {
  const packages: Array<{ name: string; version: string; isDev: boolean }> = [];
  const packageLockPath = path.join(targetDir, 'package-lock.json');

  if (!fs.existsSync(packageLockPath)) {
    return packages;
  }

  try {
    const lockContent = fs.readFileSync(packageLockPath, 'utf-8');
    const lockData = JSON.parse(lockContent);

    // Handle npm v7+ lockfile format (lockfileVersion >= 2)
    if (lockData.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(lockData.packages)) {
        if (pkgPath === '') continue; // Skip root package

        const info = pkgInfo as { version?: string; dev?: boolean };
        const name = pkgPath.replace(/^node_modules\//, '').replace(/.*node_modules\//, '');

        if (info.version && name) {
          packages.push({
            name,
            version: info.version,
            isDev: info.dev || false,
          });
        }
      }
    }
    // Handle npm v6 lockfile format (lockfileVersion 1)
    else if (lockData.dependencies) {
      const extractDeps = (
        deps: Record<
          string,
          { version: string; dev?: boolean; dependencies?: Record<string, unknown> }
        >,
        isDev: boolean = false,
      ) => {
        for (const [name, info] of Object.entries(deps)) {
          if (info.version) {
            packages.push({
              name,
              version: info.version,
              isDev: info.dev || isDev,
            });
          }
          if (info.dependencies) {
            extractDeps(info.dependencies as typeof deps, info.dev || isDev);
          }
        }
      };
      extractDeps(lockData.dependencies);
    }
  } catch {
    // Failed to parse lock file
  }

  return packages;
}

/**
 * Parse package.json to get direct dependencies with versions
 */
function parsePackageJson(
  targetDir: string,
): Array<{ name: string; version: string; isDev: boolean }> {
  const packages: Array<{ name: string; version: string; isDev: boolean }> = [];
  const packageJsonPath = path.join(targetDir, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return packages;
  }

  try {
    const content = fs.readFileSync(packageJsonPath, 'utf-8');
    const pkgJson = JSON.parse(content);

    const extractDeps = (deps: Record<string, string> | undefined, isDev: boolean) => {
      if (!deps) return;
      for (const [name, versionRange] of Object.entries(deps)) {
        // Clean version string (remove ^, ~, etc. for exact matching)
        const version = versionRange.replace(/^[\^~>=<]*/g, '').split(' ')[0];
        packages.push({ name, version, isDev });
      }
    };

    extractDeps(pkgJson.dependencies, false);
    extractDeps(pkgJson.devDependencies, true);
    extractDeps(pkgJson.peerDependencies, false);
    extractDeps(pkgJson.optionalDependencies, false);
  } catch {
    // Failed to parse package.json
  }

  return packages;
}

/**
 * Scan dependencies using OSV database
 */
export async function scanWithOsv(targetDir: string): Promise<DependencyFinding[]> {
  const findings: DependencyFinding[] = [];

  // Try to get packages from lock file first (includes transitive deps)
  let packages = parseLockFile(targetDir);

  // Fall back to package.json if no lock file
  if (packages.length === 0) {
    packages = parsePackageJson(targetDir);
  }

  if (packages.length === 0) {
    return findings;
  }

  // Batch query OSV (limit to 1000 packages per batch)
  const batchSize = 1000;
  for (let i = 0; i < packages.length; i += batchSize) {
    const batch = packages.slice(i, i + batchSize);
    const vulnerabilities = await batchQueryOsv(batch);

    for (const [pkgKey, vulns] of vulnerabilities) {
      const [pkgName, pkgVersion] = pkgKey.split('@');

      for (const vuln of vulns) {
        // Get CVE ID if available
        const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) || vuln.id;

        // Get severity from CVSS or database_specific
        let severity: RiskSeverity = 'medium';
        let cvssScore: number | undefined;

        if (vuln.severity && vuln.severity.length > 0) {
          const cvss = vuln.severity.find((s) => s.type === 'CVSS_V3');
          if (cvss && cvss.score) {
            // CVSS score might be in format "CVSS:3.1/AV:N/AC:L/..." or just a number
            const scoreMatch = cvss.score.match(/(\d+\.?\d*)/);
            if (scoreMatch) {
              cvssScore = parseFloat(scoreMatch[1]);
              severity = mapCvssToSeverity(cvssScore);
            }
          }
        }

        // Get reference URL
        const url = vuln.references?.find((r) => r.type === 'ADVISORY' || r.type === 'WEB')?.url;

        // Get vulnerable version range
        let vulnerableVersions: string | undefined;
        const affected = vuln.affected?.find((a) => a.package?.name === pkgName);
        if (affected?.ranges) {
          const range = affected.ranges[0];
          if (range?.events) {
            const introduced = range.events.find((e) => e.introduced)?.introduced;
            const fixed = range.events.find((e) => e.fixed)?.fixed;
            if (introduced && fixed) {
              vulnerableVersions = `>=${introduced} <${fixed}`;
            } else if (introduced) {
              vulnerableVersions = `>=${introduced}`;
            }
          }
        }

        findings.push({
          name: pkgName,
          version: pkgVersion,
          severity,
          reason: vuln.summary || `Known vulnerability: ${cveId}`,
          cveId,
          cvssScore,
          vulnerableVersions,
          source: 'osv',
          url,
        });
      }
    }
  }

  return findings;
}

/**
 * Comprehensive vulnerability scan combining npm audit and OSV
 */
export async function scanVulnerabilities(targetDir: string): Promise<DependencyFinding[]> {
  // Run both scans in parallel
  const [npmFindings, osvFindings] = await Promise.all([
    runNpmAudit(targetDir),
    scanWithOsv(targetDir),
  ]);

  // Deduplicate findings (prefer npm audit data as it's usually more accurate)
  const findingMap = new Map<string, DependencyFinding>();

  // Add OSV findings first
  for (const finding of osvFindings) {
    const key = `${finding.name}:${finding.cveId || finding.reason}`;
    findingMap.set(key, finding);
  }

  // Add/override with npm audit findings
  for (const finding of npmFindings) {
    const key = `${finding.name}:${finding.cveId || finding.reason}`;
    findingMap.set(key, finding);
  }

  return Array.from(findingMap.values());
}

/**
 * Get dependency statistics
 */
export function getDependencyStats(targetDir: string): {
  total: number;
  direct: number;
  transitive: number;
  dev: number;
} {
  const lockPackages = parseLockFile(targetDir);
  const directPackages = parsePackageJson(targetDir);

  const directNames = new Set(directPackages.map((p) => p.name));
  const transitiveCount = lockPackages.filter((p) => !directNames.has(p.name)).length;
  const devCount = lockPackages.filter((p) => p.isDev).length;

  return {
    total: lockPackages.length || directPackages.length,
    direct: directPackages.length,
    transitive: transitiveCount,
    dev: devCount,
  };
}
