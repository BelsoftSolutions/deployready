import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FileEditor } from '../src/agent/FileEditor';
import type { Snippet } from '../src/agent/FileEditor';
import { FixManager } from '../src/agent/FixManager';
import { makeFinding } from '../src/utils/finding';

function project(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'er-fix-'));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
  return root;
}

function finding(file: string, line = 1) {
  return makeFinding({
    rule: 'weak-hash', title: 't', severity: 'warning', category: 'security',
    source: 'static', description: '', recommendation: '', file, line,
  });
}

const snip = (startLine: number, endLine: number): Snippet => ({ text: '', startLine, endLine });
const backups = (root: string) => fs.readdirSync(root).filter((f) => f.includes('.bak.'));
const read = (root: string, name: string) => fs.readFileSync(path.join(root, name), 'utf8');

describe('FixManager.applySuggestion', () => {
  describe('JS/TS syntax validation', () => {
    const src = "const crypto = require('crypto');\nconst h = crypto.createHash('md5');\nmodule.exports = h;\n";

    it('applies a fix whose result parses, with a backup', async () => {
      const root = project({ 'a.js': src });
      const res = await FixManager.applySuggestion(
        finding('a.js', 2), snip(2, 2), "const h = crypto.createHash('sha256');", new FileEditor(root),
      );
      expect(res.applied).toBe(true);
      expect(read(root, 'a.js')).toBe(src.replace('md5', 'sha256'));
      expect(res.backup && fs.readFileSync(res.backup, 'utf8')).toBe(src);
      expect(res.message).not.toMatch(/not syntax-checked/i);
    });

    it('rejects a fix that introduces a syntax error, leaving the file and directory untouched', async () => {
      const root = project({ 'a.js': src });
      const res = await FixManager.applySuggestion(
        finding('a.js', 2), snip(2, 2), "const h = crypto.createHash('sha256';", new FileEditor(root),
      );
      expect(res.applied).toBe(false);
      expect(res.backup).toBeNull();
      expect(res.message).toMatch(/syntax error/i);
      expect(read(root, 'a.js')).toBe(src);
      expect(backups(root)).toEqual([]);
    });

    it.each(['a.ts', 'a.tsx', 'a.jsx', 'a.mjs', 'a.cjs'])('checks %s files too', async (name) => {
      const root = project({ [name]: 'const a = 1;\nconst b = 2;\n' });
      const bad = await FixManager.applySuggestion(finding(name, 2), snip(2, 2), 'const b = ;', new FileEditor(root));
      expect(bad.applied).toBe(false);
      expect(read(root, name)).toBe('const a = 1;\nconst b = 2;\n');
      const good = await FixManager.applySuggestion(finding(name, 2), snip(2, 2), 'const b = 3;', new FileEditor(root));
      expect(good.applied).toBe(true);
      expect(read(root, name)).toBe('const a = 1;\nconst b = 3;\n');
    });

    it('validates TypeScript syntax (type annotations are fine)', async () => {
      const root = project({ 'a.ts': 'const a = 1;\n' });
      const res = await FixManager.applySuggestion(
        finding('a.ts', 1), snip(1, 1), 'const a: number = 2;', new FileEditor(root),
      );
      expect(res.applied).toBe(true);
    });

    it('does not block when the original file already fails to parse', async () => {
      const broken = 'const a = ;\nconst h = createHash("md5");\n';
      const root = project({ 'a.js': broken });
      const res = await FixManager.applySuggestion(
        finding('a.js', 2), snip(2, 2), 'const h = createHash("sha256");', new FileEditor(root),
      );
      expect(res.applied).toBe(true);
      expect(res.message).toMatch(/not syntax-checked/i);
      expect(read(root, 'a.js')).toBe('const a = ;\nconst h = createHash("sha256");\n');
    });

    it('keeps CRLF line endings when applying a valid fix', async () => {
      const root = project({ 'a.js': 'const a = 1;\r\nconst b = 2;\r\n' });
      const res = await FixManager.applySuggestion(
        finding('a.js', 2), snip(2, 2), 'const b = 3;\nconst c = 4;', new FileEditor(root),
      );
      expect(res.applied).toBe(true);
      expect(read(root, 'a.js')).toBe('const a = 1;\r\nconst b = 3;\r\nconst c = 4;\r\n');
    });
  });

  describe('languages without a parser', () => {
    it('applies a python fix and says it was not syntax-checked', async () => {
      const root = project({ 'app.py': 'import hashlib\nh = hashlib.md5(b"x")\n' });
      const res = await FixManager.applySuggestion(
        finding('app.py', 2), snip(2, 2), 'h = hashlib.sha256(b"x")', new FileEditor(root),
      );
      expect(res.applied).toBe(true);
      expect(res.message).toMatch(/not syntax-checked/i);
      expect(read(root, 'app.py')).toBe('import hashlib\nh = hashlib.sha256(b"x")\n');
      expect(res.backup && fs.existsSync(res.backup)).toBe(true);
    });

    it('does not apply JS syntax checking to non-JS extensions', async () => {
      const root = project({ 'q.sql': 'select 1;\n' });
      const res = await FixManager.applySuggestion(finding('q.sql', 1), snip(1, 1), 'select (;', new FileEditor(root));
      expect(res.applied).toBe(true);
      expect(res.message).toMatch(/not syntax-checked/i);
    });
  });

  describe('range and content checks', () => {
    const body = 'one\ntwo\nthree\n';
    it.each([
      ['start beyond the end of the file', 4, 4],
      ['end beyond the end of the file', 2, 9],
      ['start after end', 3, 2],
      ['start below 1', 0, 1],
      ['non-integer bounds', 1.5, 2],
    ])('rejects %s', async (_label, start, end) => {
      const root = project({ 'a.txt': body });
      const res = await FixManager.applySuggestion(finding('a.txt', 1), snip(start, end), 'X', new FileEditor(root));
      expect(res.applied).toBe(false);
      expect(res.backup).toBeNull();
      expect(res.message).toMatch(/line range/i);
      expect(read(root, 'a.txt')).toBe(body);
      expect(backups(root)).toEqual([]);
    });

    it('accepts the last real line of a file with a trailing newline', async () => {
      const root = project({ 'a.txt': body });
      const res = await FixManager.applySuggestion(finding('a.txt', 3), snip(3, 3), 'THREE', new FileEditor(root));
      expect(res.applied).toBe(true);
      expect(read(root, 'a.txt')).toBe('one\ntwo\nTHREE\n');
    });

    it.each(['', '   ', '\n\n  \n'])('rejects an empty or whitespace-only replacement %j for real code', async (empty) => {
      const root = project({ 'a.js': 'const a = 1;\nconst b = 2;\n', 'a.py': 'a = 1\nb = 2\n' });
      for (const name of ['a.js', 'a.py']) {
        const before = read(root, name);
        const res = await FixManager.applySuggestion(finding(name, 2), snip(2, 2), empty, new FileEditor(root));
        expect(res.applied).toBe(false);
        expect(res.message).toMatch(/empty/i);
        expect(read(root, name)).toBe(before);
      }
      expect(backups(root)).toEqual([]);
    });

    it('allows replacing a blank range with blank text', async () => {
      const root = project({ 'a.py': 'a = 1\n\nb = 2\n' });
      const res = await FixManager.applySuggestion(finding('a.py', 2), snip(2, 2), '', new FileEditor(root));
      expect(res.applied).toBe(true);
    });

    it('refuses (without throwing) a path outside the project', async () => {
      const root = project({});
      const outside = project({ 'x.js': 'const a = 1;\n' });
      const rel = path.relative(root, path.join(outside, 'x.js'));
      const res = await FixManager.applySuggestion(finding(rel, 1), snip(1, 1), 'const a = 2;', new FileEditor(root));
      expect(res.applied).toBe(false);
      expect(res.message).toMatch(/outside project/);
      expect(read(outside, 'x.js')).toBe('const a = 1;\n');
    });
  });
});

describe('FileEditor.replaceLines bounds', () => {
  it('rejects an invalid range before writing anything', async () => {
    const root = project({ 'a.txt': 'a\nb\n' });
    const editor = new FileEditor(root);
    await expect(editor.replaceLines('a.txt', 3, 3, 'x')).rejects.toThrow(/line range/i);
    await expect(editor.replaceLines('a.txt', 2, 1, 'x')).rejects.toThrow(/line range/i);
    expect(read(root, 'a.txt')).toBe('a\nb\n');
    expect(backups(root)).toEqual([]);
  });

  it('previewReplaceLines returns the would-be content and writes nothing', async () => {
    const root = project({ 'a.txt': 'a\r\nb\r\n' });
    const prev = await new FileEditor(root).previewReplaceLines('a.txt', 2, 2, 'B');
    expect(prev).toEqual({ original: 'a\r\nb\r\n', updated: 'a\r\nB\r\n', replaced: 'b' });
    expect(read(root, 'a.txt')).toBe('a\r\nb\r\n');
    expect(backups(root)).toEqual([]);
  });
});
