/**
 * skillguard Scanner
 * Main scanning orchestrator
 */

import * as fs from 'fs';
import * as path from 'path';
import { analyzeDirectory } from './analyzer';
import { inspectDependenciesAsync } from './dependencies';
import { calculateRiskScore, getRiskLevel } from './scorer';
import { ScanResult } from './types';

/**
 * Run a complete security scan on the target directory
 */
export async function scan(targetDir: string): Promise<ScanResult> {
  const startTime = Date.now();

  // Resolve to absolute path
  const absolutePath = path.resolve(targetDir);

  // Verify directory exists
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Directory not found: ${absolutePath}`);
  }

  if (!fs.statSync(absolutePath).isDirectory()) {
    throw new Error(`Not a directory: ${absolutePath}`);
  }

  // Run code analysis
  const { findings: codeFindings, scannedFiles } = await analyzeDirectory(absolutePath);

  // Run dependency analysis with real vulnerability scanning
  const dependencyFindings = await inspectDependenciesAsync(absolutePath);

  // Calculate risk score
  const riskScore = calculateRiskScore(codeFindings, dependencyFindings);
  const riskLevel = getRiskLevel(riskScore);

  const endTime = Date.now();

  return {
    codeFindingsCount: codeFindings.length,
    dependencyFindingsCount: dependencyFindings.length,
    codeFindings,
    dependencyFindings,
    riskScore,
    riskLevel,
    scannedFiles,
    scanDuration: endTime - startTime,
  };
}

/**
 * Quick check if a directory looks like a valid project
 */
export function isValidProject(targetDir: string): boolean {
  const absolutePath = path.resolve(targetDir);

  if (!fs.existsSync(absolutePath)) {
    return false;
  }

  // Check for common project indicators
  const indicators = ['package.json', 'index.js', 'index.ts', 'src', 'lib'];

  for (const indicator of indicators) {
    if (fs.existsSync(path.join(absolutePath, indicator))) {
      return true;
    }
  }

  // Check if there are any JS/TS files
  const entries = fs.readdirSync(absolutePath);
  return entries.some((entry) => /\.(js|ts)$/.test(entry));
}
