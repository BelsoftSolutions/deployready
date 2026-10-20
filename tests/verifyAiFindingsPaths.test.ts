import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { verifyAiFindings, droppedNote } from '../src/ai/verifyAiFindings';
import { makeFinding } from '../src/utils/finding';
import type { Finding } from '../src/types';

function ai(file: string | undefined, over: Partial<Omit<Finding, 'id'>> = {}): Finding {
  return makeFinding({
    rule: `ai-${file ?? 'none'}`, title: 'AI idea', severity: 'critical', category: 'security', source: 'ai',
    description: 'something', recommendation: 'check it', file, ...over,
  } as Omit<Finding, 'id'>);
}

describe('verifyAiFindings path containment', () => {
  let root: string;
  let outside: string;
  beforeEach(() => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-vaf-'));
    root = path.join(base, 'project');
    outside = path.join(base, 'outside');
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(root, 'ok.js'), '//');
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'x');
  });
  afterEach(() => fs.rmSync(path.dirname(root), { recursive: true, force: true }));

  it('drops a file path containing a NUL byte', async () => {
    const r = await verifyAiFindings([ai('ok.js\0.png'), ai('ok.js')], root);
    expect(r.dropped).toBe(1);
    expect(r.findings.map((f) => f.file)).toEqual(['ok.js']);
  });

  it('drops every file-bound finding when the project root does not exist, but keeps file-less ones', async () => {
    const r = await verifyAiFindings([ai('ok.js'), ai(undefined)], path.join(root, 'missing-root'));
    expect(r.dropped).toBe(1);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.file).toBeUndefined();
  });

  it('drops a symlink inside the project that points outside it', async () => {
    const link = path.join(root, 'link.txt');
    try {
      fs.symlinkSync(path.join(outside, 'secret.txt'), link);
    } catch {
      return; // symlink creation not permitted on this OS/user; nothing to assert
    }
    const r = await verifyAiFindings([ai('link.txt'), ai('ok.js')], root);
    expect(r.dropped).toBe(1);
    expect(r.findings.map((f) => f.file)).toEqual(['ok.js']);
  });

  it('normalises ./ and .. segments in a relative path to a clean forward-slash path', async () => {
    fs.mkdirSync(path.join(root, 'a'));
    fs.writeFileSync(path.join(root, 'a', 'b.js'), '//');
    const r = await verifyAiFindings([ai('./a/../a/b.js')], root);
    expect(r.findings.map((f) => f.file)).toEqual(['a/b.js']);
  });

  it('marks kept findings unverified at info severity and records the suggested severity', async () => {
    const r = await verifyAiFindings([ai('ok.js', { severity: 'warning', description: 'maybe' })], root);
    expect(r.findings[0]).toMatchObject({ severity: 'info', unverified: true, source: 'ai' });
    expect(r.findings[0]!.description).toBe('AI-suggested severity: warning. maybe');
  });

  it('droppedNote states the count', () => {
    expect(droppedNote(3)).toBe('3 AI finding(s) dropped: referenced file not found');
  });
});
