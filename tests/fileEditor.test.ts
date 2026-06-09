import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FileEditor } from '../src/agent/FileEditor';
import { FixManager } from '../src/agent/FixManager';
import { makeFinding } from '../src/utils/finding';

function tmpProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'er-edit-'));
  return dir;
}

describe('FileEditor', () => {
  it('replaces a line range and writes a backup', async () => {
    const root = tmpProject();
    fs.writeFileSync(path.join(root, 'a.js'), 'line1\nline2\nline3\n');
    const editor = new FileEditor(root);
    const backup = await editor.replaceLines('a.js', 2, 2, 'LINE2-FIXED');
    expect(fs.readFileSync(path.join(root, 'a.js'), 'utf8')).toBe('line1\nLINE2-FIXED\nline3\n');
    expect(fs.existsSync(backup)).toBe(true);
    expect(fs.readFileSync(backup, 'utf8')).toContain('line2');
  });

  it('refuses to write outside the project root', async () => {
    const editor = new FileEditor(tmpProject());
    await expect(editor.replaceLines('../escape.js', 1, 1, 'x')).rejects.toThrow(/outside project/);
  });

  it('extracts a snippet with surrounding context', async () => {
    const root = tmpProject();
    fs.writeFileSync(path.join(root, 'b.js'), 'a\nb\nc\nd\ne\n');
    const snip = await new FileEditor(root).snippet('b.js', 3, 1);
    expect(snip.text).toBe('b\nc\nd');
    expect(snip.startLine).toBe(2);
    expect(snip.endLine).toBe(4);
  });
});

describe('FixManager.autoFix', () => {
  it('adds .env to .gitignore for the env-not-ignored rule', async () => {
    const root = tmpProject();
    fs.writeFileSync(path.join(root, '.env'), 'SECRET=x');
    const finding = makeFinding({
      rule: 'env-not-ignored', title: 't', severity: 'critical', category: 'security',
      source: 'static', description: '', recommendation: '', file: '.env',
    });
    const res = await FixManager.autoFix(finding, new FileEditor(root));
    expect(res.message).toMatch(/Added/);
    expect(fs.readFileSync(path.join(root, '.gitignore'), 'utf8')).toContain('.env');
  });

  it('applies a deterministic line fix (weak-hash) to the finding line, with backup', async () => {
    const root = tmpProject();
    fs.writeFileSync(path.join(root, 'crypto.js'), "const a=1;\nconst h = createHash('md5');\nconst b=2;\n");
    const finding = makeFinding({
      rule: 'weak-hash', title: 't', severity: 'warning', category: 'security',
      source: 'static', description: '', recommendation: '', file: 'crypto.js', line: 2,
    });
    expect(FixManager.autoFixable(finding)).toBe(true);
    const res = await FixManager.autoFix(finding, new FileEditor(root));
    expect(fs.readFileSync(path.join(root, 'crypto.js'), 'utf8')).toBe(
      "const a=1;\nconst h = createHash('sha256');\nconst b=2;\n",
    );
    expect(res.backup).toBeTruthy();
    expect(fs.existsSync(res.backup as string)).toBe(true);
  });

  it('throws (so the caller can fall back) when the line does not match the fixable shape', async () => {
    const root = tmpProject();
    fs.writeFileSync(path.join(root, 'tls.js'), "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';\n");
    const finding = makeFinding({
      rule: 'tls-verification-disabled', title: 't', severity: 'critical', category: 'security',
      source: 'static', description: '', recommendation: '', file: 'tls.js', line: 1,
    });
    await expect(FixManager.autoFix(finding, new FileEditor(root))).rejects.toThrow();
    // file left untouched
    expect(fs.readFileSync(path.join(root, 'tls.js'), 'utf8')).toBe(
      "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';\n",
    );
  });
});
