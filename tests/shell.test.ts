import { PassThrough, Writable } from 'stream';
import * as path from 'path';
import { InteractiveShell } from '../src/cli/InteractiveShell';

const SAMPLE = path.join(__dirname, 'sample-app');

/**
 * Run a scripted shell session and return the captured console output
 * (ANSI-stripped). Uses jest.spyOn on console (logger routes through it) and a
 * sink for readline's prompt output, so it's robust across the full suite.
 */
async function runSession(target: string, commands: string[]): Promise<string> {
  const input = new PassThrough();
  const sink = new Writable({ write: (_c, _e, cb) => cb() });
  const logs: string[] = [];
  const methods = ['log', 'warn', 'error', 'info'] as const;
  const spies = methods.map((m) =>
    jest.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      logs.push(args.map((a) => String(a)).join(' '));
    }),
  );
  try {
    const shell = new InteractiveShell(target, { input, output: sink });
    const done = shell.start();
    for (const cmd of commands) input.write(cmd + '\n');
    input.end();
    await done;
  } finally {
    spies.forEach((s) => s.mockRestore());
  }
  return logs.join('\n').replace(/\x1B\[[0-9;]*[A-Za-z]/g, '');
}

describe('InteractiveShell (scripted session)', () => {
  it('shows the guided menu, scans, lists, marks fixed (score moves), and exits', async () => {
    const out = await runSession(SAMPLE, ['parse', 'issues critical', 'done 1', 'score', 'exit']);

    expect(out).toMatch(/What would you like to do\?/); // guided menu rendered
    expect(out).toMatch(/Score/); // score line printed
    expect(out).toMatch(/Marked .* as fixed/); // `done 1` worked
    expect(out).toContain('Bye'); // clean exit
  }, 20000);

  it('warns on an unknown command and on out-of-range finding numbers', async () => {
    const out = await runSession(SAMPLE, ['4', 'flibble', 'show 999', 'exit']);
    expect(out).toMatch(/Unknown command/);
    expect(out).toMatch(/finding number/);
  }, 20000);
});
