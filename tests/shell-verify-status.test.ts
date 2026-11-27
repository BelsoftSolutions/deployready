import { PassThrough, Writable } from 'stream';
import { InteractiveShell } from '../src/cli/InteractiveShell';
import { Verifier } from '../src/core/Verifier';
import { makeFinding } from '../src/utils/finding';
import type { Finding } from '../src/types';

type ShellInternals = {
  verifyAndMark: (f: Finding, applied: boolean) => Promise<void>;
  markFinding: (f: Finding, s: string) => void;
  printScore: () => void;
  show: (arg?: string) => void;
  findingAt: (arg?: string) => Finding | undefined;
};

function shell(): ShellInternals {
  const s = new InteractiveShell('.', { input: new PassThrough(), output: new Writable({ write: (_c, _e, cb) => cb() }) });
  const i = s as unknown as ShellInternals;
  jest.spyOn(i, 'printScore').mockImplementation(() => undefined);
  return i;
}

const f = (source: Finding['source']) =>
  makeFinding({ rule: 'auth-bypass', title: 't', severity: 'critical', category: 'security', source, endpoint: '/a', description: 'd', recommendation: 'r' });

let logs: string[];
beforeEach(() => {
  logs = [];
  for (const m of ['log', 'warn', 'error', 'info'] as const) {
    jest.spyOn(console, m).mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));
  }
});
afterEach(() => jest.restoreAllMocks());

describe('InteractiveShell verify status handling', () => {
  it('an inconclusive LIVE re-check after a change leaves the finding open', async () => {
    const s = shell();
    const mark = jest.spyOn(s, 'markFinding').mockImplementation(() => undefined);
    jest.spyOn(Verifier, 'verify').mockResolvedValue({ status: 'inconclusive', detail: 'no control' });
    await s.verifyAndMark(f('dynamic'), true);
    expect(mark).not.toHaveBeenCalled();
    expect(logs.join('\n')).toMatch(/only marked fixed with proof/);
  });

  it('an inconclusive STATIC re-check after a change is marked fixed-but-unverified (unchanged)', async () => {
    const s = shell();
    const mark = jest.spyOn(s, 'markFinding').mockImplementation(() => undefined);
    jest.spyOn(Verifier, 'verify').mockResolvedValue({ status: 'inconclusive', detail: 'x' });
    await s.verifyAndMark(f('static'), true);
    expect(mark).toHaveBeenCalledWith(expect.anything(), 'fixed');
  });

  it('a thrown re-check becomes inconclusive, never fixed, for a standalone verify', async () => {
    const s = shell();
    const mark = jest.spyOn(s, 'markFinding').mockImplementation(() => undefined);
    jest.spyOn(Verifier, 'verify').mockRejectedValue(new Error('boom'));
    await s.verifyAndMark(f('dynamic'), false);
    expect(mark).not.toHaveBeenCalled();
  });

  it('still-present prints the fresh proof', async () => {
    const s = shell();
    jest.spyOn(Verifier, 'verify').mockResolvedValue({ status: 'still-present', detail: 'still', proof: { request: "curl -i 'http://localhost/a'", status: 200 } });
    await s.verifyAndMark(f('dynamic'), false);
    expect(logs.join('\n')).toContain("proof: curl -i 'http://localhost/a'");
  });

  it('`show` prints the proof', () => {
    const s = shell();
    jest.spyOn(s, 'findingAt').mockReturnValue({ ...f('dynamic'), proof: { request: "curl -i 'http://localhost/a'", status: 200, control: 'ctl' } });
    s.show('1');
    const out = logs.join('\n');
    expect(out).toContain("proof: curl -i 'http://localhost/a'");
    expect(out).toContain('control: ctl');
  });
});
