import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { JavaScriptAnalyzer } from '../analyzers';

// Regression: typed TypeScript used to be silently skipped (regex type-stripping
// broke the parse and the file returned zero findings).
describe('TypeScript analysis', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-ts-'));
  const file = path.join(dir, 'skill.ts');

  beforeAll(() => {
    fs.writeFileSync(
      file,
      [
        "import { exec } from 'child_process';",
        'interface Opts { cmd: string }',
        'enum Mode { A, B }',
        'const cmd: string = process.argv[2];',
        '(exec as any)(cmd);',
        'eval(cmd);',
      ].join('\n'),
    );
  });

  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('finds risks in TypeScript with type annotations, interfaces and casts', () => {
    const findings = new JavaScriptAnalyzer().analyzeFile(file);
    const byLine = findings.map((f) => `${f.line}:${f.category}`);
    expect(byLine).toContain('5:Shell Execution');
    expect(byLine).toContain('6:Code Injection');
    expect(findings.every((f) => f.language === 'typescript')).toBe(true);
  });
});
