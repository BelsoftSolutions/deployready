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

function trySymlink(target: string, link: string, type: 'file' | 'dir' | 'junction'): boolean {
  try {
    fs.symlinkSync(target, link, type);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EPERM' || code === 'EACCES' || code === 'ENOSYS') return false;
    throw err;
  }
}

describe('FileEditor path confinement', () => {
  let root: string;
  let outside: string;
  beforeEach(() => {
    root = tmpProject();
    outside = tmpProject();
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside-secret\n');
  });

  it('rejects a symlinked directory inside the project that points outside it', async () => {
    if (!trySymlink(outside, path.join(root, 'link'), process.platform === 'win32' ? 'junction' : 'dir')) return;
    const editor = new FileEditor(root);
    await expect(editor.read('link/secret.txt')).rejects.toThrow(/outside project/);
    await expect(editor.replaceLines('link/secret.txt', 1, 1, 'x')).rejects.toThrow(/outside project/);
    await expect(editor.appendLine('link/new.txt', 'x')).rejects.toThrow(/outside project/);
    expect(fs.readFileSync(path.join(outside, 'secret.txt'), 'utf8')).toBe('outside-secret\n');
    expect(fs.existsSync(path.join(outside, 'new.txt'))).toBe(false);
    expect(editor.fileExists('link/secret.txt')).toBe(false);
  });

  it('rejects a symlinked file inside the project that points outside it', async () => {
    if (!trySymlink(path.join(outside, 'secret.txt'), path.join(root, 'leak.txt'), 'file')) return;
    const editor = new FileEditor(root);
    await expect(editor.read('leak.txt')).rejects.toThrow(/outside project/);
    await expect(editor.appendLine('leak.txt', 'x')).rejects.toThrow(/outside project/);
    expect(fs.readFileSync(path.join(outside, 'secret.txt'), 'utf8')).toBe('outside-secret\n');
  });

  it('rejects a dangling symlink whose target is outside the project', async () => {
    const missing = path.join(outside, 'not-created.txt');
    if (!trySymlink(missing, path.join(root, 'dangling.txt'), 'file')) return;
    await expect(new FileEditor(root).appendLine('dangling.txt', 'x')).rejects.toThrow(/dangling symlink/);
    expect(fs.existsSync(missing)).toBe(false);
  });

  it('still allows a symlink that stays inside the project', async () => {
    fs.mkdirSync(path.join(root, 'real'));
    fs.writeFileSync(path.join(root, 'real', 'f.js'), 'a\nb\n');
    if (!trySymlink(path.join(root, 'real'), path.join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir')) return;
    const editor = new FileEditor(root);
    expect(await editor.read('alias/f.js')).toBe('a\nb\n');
    await editor.replaceLines('alias/f.js', 1, 1, 'A');
    expect(fs.readFileSync(path.join(root, 'real', 'f.js'), 'utf8')).toBe('A\nb\n');
  });

  it('allows a file that does not exist yet inside the project', async () => {
    const editor = new FileEditor(root);
    expect(editor.fileExists('new.txt')).toBe(false);
    expect(await editor.appendLine('new.txt', 'x')).toBeNull();
    expect(fs.readFileSync(path.join(root, 'new.txt'), 'utf8')).toBe('x\n');
  });

  it('rejects NUL bytes in the path', async () => {
    const editor = new FileEditor(root);
    await expect(editor.read('a\0.js')).rejects.toThrow(/NUL/);
    await expect(editor.appendLine('.gitignore\0x', 'x')).rejects.toThrow(/NUL/);
  });

  it('fileExists returns false instead of throwing for unsafe paths', () => {
    const editor = new FileEditor(root);
    expect(editor.fileExists('../secret.txt')).toBe(false);
    expect(editor.fileExists('a\0.js')).toBe(false);
  });

  it('does not treat names that merely start with ".." as traversal', async () => {
    fs.writeFileSync(path.join(root, '..env'), 'k=v\n');
    expect(await new FileEditor(root).read('..env')).toBe('k=v\n');
  });
});

describe('FileEditor line endings', () => {
  const write = (root: string, name: string, content: string | Buffer): string => {
    const abs = path.join(root, name);
    fs.writeFileSync(abs, content);
    return abs;
  };

  it('keeps a CRLF file pure CRLF after replaceLines, normalising the replacement', async () => {
    const root = tmpProject();
    const abs = write(root, 'a.js', 'one\r\ntwo\r\nthree\r\n');
    const backup = await new FileEditor(root).replaceLines('a.js', 2, 2, 'TWO-a\nTWO-b');
    expect(fs.readFileSync(abs, 'utf8')).toBe('one\r\nTWO-a\r\nTWO-b\r\nthree\r\n');
    expect(fs.readFileSync(backup).equals(Buffer.from('one\r\ntwo\r\nthree\r\n'))).toBe(true);
  });

  it('keeps a CRLF file pure CRLF after appendLine', async () => {
    const root = tmpProject();
    const abs = write(root, '.gitignore', 'node_modules\r\ndist\r\n');
    const backup = await new FileEditor(root).appendLine('.gitignore', '.env');
    expect(fs.readFileSync(abs, 'utf8')).toBe('node_modules\r\ndist\r\n.env\r\n');
    expect(fs.readFileSync(backup as string, 'utf8')).toBe('node_modules\r\ndist\r\n');
  });

  it('appendLine adds the separator in the file EOL when there is no trailing newline', async () => {
    const root = tmpProject();
    const crlf = write(root, 'crlf.txt', 'a\r\nb');
    const lf = write(root, 'lf.txt', 'a\nb');
    const editor = new FileEditor(root);
    await editor.appendLine('crlf.txt', 'c');
    await editor.appendLine('lf.txt', 'c');
    expect(fs.readFileSync(crlf, 'utf8')).toBe('a\r\nb\r\nc\r\n');
    expect(fs.readFileSync(lf, 'utf8')).toBe('a\nb\nc\n');
  });

  it('keeps an LF file pure LF, even if the replacement contains CRLF', async () => {
    const root = tmpProject();
    const abs = write(root, 'a.js', 'one\ntwo\nthree\n');
    await new FileEditor(root).replaceLines('a.js', 2, 2, 'X\r\nY');
    expect(fs.readFileSync(abs, 'utf8')).toBe('one\nX\nY\nthree\n');
  });

  it('uses the dominant style for a mixed file', async () => {
    const root = tmpProject();
    const crlfMajor = write(root, 'm1.js', 'a\r\nb\r\nc\nd\r\n');
    const lfMajor = write(root, 'm2.js', 'a\nb\nc\r\nd\n');
    const editor = new FileEditor(root);
    await editor.replaceLines('m1.js', 2, 2, 'B');
    await editor.replaceLines('m2.js', 2, 2, 'B');
    expect(fs.readFileSync(crlfMajor, 'utf8')).toBe('a\r\nB\r\nc\r\nd\r\n');
    expect(fs.readFileSync(lfMajor, 'utf8')).toBe('a\nB\nc\nd\n');
  });

  it('preserves the presence or absence of a trailing newline', async () => {
    const root = tmpProject();
    const withNl = write(root, 'with.js', 'a\r\nb\r\n');
    const withoutNl = write(root, 'without.js', 'a\r\nb');
    const editor = new FileEditor(root);
    await editor.replaceLines('with.js', 2, 2, 'B');
    await editor.replaceLines('without.js', 2, 2, 'B');
    expect(fs.readFileSync(withNl, 'utf8')).toBe('a\r\nB\r\n');
    expect(fs.readFileSync(withoutNl, 'utf8')).toBe('a\r\nB');
  });

  it('preserves a UTF-8 BOM and backs the original up byte-for-byte', async () => {
    const root = tmpProject();
    const original = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('a\r\nb\r\n')]);
    const abs = write(root, 'bom.js', original);
    const editor = new FileEditor(root);
    const backup = await editor.replaceLines('bom.js', 2, 2, 'B');
    expect(fs.readFileSync(abs).equals(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('a\r\nB\r\n')]))).toBe(true);
    expect(fs.readFileSync(backup).equals(original)).toBe(true);

    const bomGitignore = write(root, '.gitignore', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('x\r\n')]));
    await editor.appendLine('.gitignore', '.env');
    const out = fs.readFileSync(bomGitignore);
    expect(out.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(true);
    expect(out.subarray(3).toString('utf8')).toBe('x\r\n.env\r\n');
  });

  it('snippets contain no CR and do not include the phantom line after a trailing newline', async () => {
    const root = tmpProject();
    write(root, 'c.js', 'a\r\nb\r\nc\r\nd\r\ne\r\n');
    const editor = new FileEditor(root);
    const mid = await editor.snippet('c.js', 3, 1);
    expect(mid.text).toBe('b\nc\nd');
    expect(mid.text).not.toContain('\r');
    const tail = await editor.snippet('c.js', 5, 3);
    expect(tail.text).toBe('b\nc\nd\ne');
    expect(tail.endLine).toBe(5);
  });

  it('strips the BOM from the first snippet line', async () => {
    const root = tmpProject();
    write(root, 'bom.js', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('a\nb\n')]));
    const snip = await new FileEditor(root).snippet('bom.js', 1, 1);
    expect(snip.text).toBe('a\nb');
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

  it('keeps a CRLF file pure CRLF when applying a deterministic line fix', async () => {
    const root = tmpProject();
    fs.writeFileSync(path.join(root, 'crypto.js'), "const a=1;\r\nconst h = createHash('md5');\r\nconst b=2;\r\n");
    const finding = makeFinding({
      rule: 'weak-hash', title: 't', severity: 'warning', category: 'security',
      source: 'static', description: '', recommendation: '', file: 'crypto.js', line: 2,
    });
    await FixManager.autoFix(finding, new FileEditor(root));
    expect(fs.readFileSync(path.join(root, 'crypto.js'), 'utf8')).toBe(
      "const a=1;\r\nconst h = createHash('sha256');\r\nconst b=2;\r\n",
    );
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
