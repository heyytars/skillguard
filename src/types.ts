/**
 * SkillGuard Type Definitions
 * Core types for security scanning and risk assessment
 */

export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low';

export type Language =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'java'
  | 'go'
  | 'ruby'
  | 'php'
  | 'cpp'
  | 'c'
  | 'rust'
  | 'csharp'
  | 'kotlin'
  | 'swift'
  | 'markdown';

export interface Finding {
  file: string;
  line: number;
  column: number;
  severity: RiskSeverity;
  category: string;
  description: string;
  codeSnippet: string;
  language?: Language;
}

export interface DependencyFinding {
  name: string;
  severity: RiskSeverity;
  reason: string;
  version?: string;
  vulnerableVersions?: string;
  cveId?: string;
  cvssScore?: number;
  source?: 'threat-db' | 'npm-audit' | 'osv' | 'pattern';
  fixAvailable?: string;
  url?: string;
}

export interface ScanResult {
  codeFindingsCount: number;
  dependencyFindingsCount: number;
  codeFindings: Finding[];
  dependencyFindings: DependencyFinding[];
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  scannedFiles: number;
  scanDuration: number;
}

export interface RiskPattern {
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  nodeType: string;
  matcher: (node: any, ancestors?: any[]) => boolean;
}

export interface LanguageAnalyzer {
  readonly language: Language;
  readonly fileExtensions: string[];
  analyzeFile(filePath: string): Promise<Finding[]> | Finding[];
  canAnalyze(filePath: string): boolean;
}

export interface ThreatEntry {
  name: string;
  reason: string;
  severity: RiskSeverity;
}
