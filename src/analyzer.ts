/**
 * SkillGuard Multi-Language Analyzer
 * Analyzes code across multiple programming languages for security risks
 */

import * as fs from 'fs';
import * as path from 'path';
import { Finding } from './types';
import { analyzeFile as analyzeFileWithAnalyzer, getSupportedExtensions } from './analyzers';
import { sweepCodeStrings } from './analyzers/payload';

/**
 * Recursively find all source files in directory
 */
export function findSourceFiles(dir: string, files: string[] = []): string[] {
  if (!fs.existsSync(dir)) {
    return files;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const supportedExtensions = getSupportedExtensions();

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip common build/dependency directories
    if (entry.isDirectory()) {
      if (
        [
          'node_modules',
          'dist',
          'build',
          'target',
          'bin',
          'obj',
          '.git',
          '.next',
          'coverage',
          'vendor',
          '__pycache__',
          '.pytest_cache',
          'venv',
          'env',
        ].includes(entry.name)
      ) {
        continue;
      }
      findSourceFiles(fullPath, files);
    } else if (entry.isFile()) {
      // Check if file has a supported extension
      const hasSupported = supportedExtensions.some((ext) => entry.name.endsWith(ext));
      if (hasSupported && !entry.name.endsWith('.d.ts')) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

/**
 * Analyze a single file for security risks
 */
export async function analyzeFile(filePath: string): Promise<Finding[]> {
  return await analyzeFileWithAnalyzer(filePath);
}

/**
 * Analyze all files in a directory
 */
export async function analyzeDirectory(
  targetDir: string,
): Promise<{ findings: Finding[]; scannedFiles: number }> {
  const files = findSourceFiles(targetDir);
  const allFindings: Finding[] = [];

  for (const file of files) {
    const findings = await analyzeFile(file);
    // Markdown already has these rules; code files need their own sweep, because
    // a payload in a helper script was only showing up as a "capability".
    if (!/\.(?:md|mdx|markdown)$/i.test(file)) {
      const language = findings[0]?.language;
      try {
        const source = fs.readFileSync(file, 'utf-8');
        findings.push(...sweepCodeStrings(source, file, language ?? 'javascript'));
      } catch {
        // Unreadable file: the language analyzers already reported what they could.
      }
    }
    allFindings.push(...findings);
  }

  return {
    findings: allFindings,
    scannedFiles: files.length,
  };
}
