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
});
