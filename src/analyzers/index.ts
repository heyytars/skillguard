/**
 * Analyzer Registry
 * Central registry for all language analyzers
 */

import { LanguageAnalyzer, Finding } from '../types';
import { JavaScriptAnalyzer } from './javascript.analyzer';
import { PythonAnalyzer } from './python.analyzer';
import { JavaAnalyzer } from './java.analyzer';
import { GoAnalyzer } from './go.analyzer';
import { RubyAnalyzer } from './ruby.analyzer';
import { PHPAnalyzer } from './php.analyzer';
import { CppAnalyzer } from './cpp.analyzer';
import { RustAnalyzer } from './rust.analyzer';
import { MarkdownAnalyzer } from './markdown.analyzer';

// Register all available analyzers
const ANALYZERS: LanguageAnalyzer[] = [
  new JavaScriptAnalyzer(),
  new PythonAnalyzer(),
  new JavaAnalyzer(),
  new GoAnalyzer(),
  new RubyAnalyzer(),
  new PHPAnalyzer(),
  new CppAnalyzer(),
  new RustAnalyzer(),
  new MarkdownAnalyzer(),
];

/**
 * Get the appropriate analyzer for a file
 */
export function getAnalyzerForFile(filePath: string): LanguageAnalyzer | null {
  for (const analyzer of ANALYZERS) {
    if (analyzer.canAnalyze(filePath)) {
      return analyzer;
    }
  }
  return null;
}

/**
 * Get all supported file extensions
 */
export function getSupportedExtensions(): string[] {
  const extensions = new Set<string>();
  for (const analyzer of ANALYZERS) {
    for (const ext of analyzer.fileExtensions) {
      extensions.add(ext);
    }
  }
  return Array.from(extensions);
}

/**
 * Analyze a single file using the appropriate analyzer
 */
export async function analyzeFile(filePath: string): Promise<Finding[]> {
  const analyzer = getAnalyzerForFile(filePath);
  if (!analyzer) {
    return [];
  }

  const result = analyzer.analyzeFile(filePath);
  return result instanceof Promise ? await result : result;
}

/**
 * Get all registered analyzers
 */
export function getAllAnalyzers(): LanguageAnalyzer[] {
  return ANALYZERS;
}

// Export individual analyzers for testing
export {
  JavaScriptAnalyzer,
  PythonAnalyzer,
  JavaAnalyzer,
  GoAnalyzer,
  RubyAnalyzer,
  PHPAnalyzer,
  CppAnalyzer,
  RustAnalyzer,
};
