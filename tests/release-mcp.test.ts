import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DeployReadyTools } from '../src/mcp/tools';
import { SCORE_DISCLAIMER } from '../src/core/releaseState';

function project(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-release-mcp-'));
  fs.writeFileSync(path.join(root, 'app.js'), "const crypto = require('crypto');\ncrypto.createHash('md5');\nconst r = eval(input);\n");
  return root;
}

describe('MCP score: release state, coverage and verification status', () => {
  it('reports release + coverage + the score note, and splits fixed into verified / unverified', async () => {
    const root = project();
    const tools = new DeployReadyTools(root);
    const first = await tools.score();
    expect(first.release?.state).toBe('not-ready');
    expect(first.releaseLine).toMatch(/^Release: NOT READY/);
    expect(first.scoreNote).toBe(SCORE_DISCLAIMER);
    expect(first.coverage?.find((a) => a.kind === 'dynamic')?.state).toBe('untested');
    expect(first.release?.verification).toEqual({ fixedVerified: 0, fixedUnverified: 0, open: first.release?.verification.open });

    const scan = await tools.scan();
    const md5 = scan.findings.find((f) => /md5|hash/i.test(f.rule));
    const evalF = scan.findings.find((f) => /eval/.test(f.rule));
    expect(md5 && evalF).toBeTruthy();

    // Fix both by hand; verify only one of them.
    fs.writeFileSync(path.join(root, 'app.js'), "const crypto = require('crypto');\ncrypto.createHash('sha256');\nconst r = JSON.parse(input);\n");
    const v = await tools.verify({ id: evalF!.id });
    expect(v.status).toBe('fixed');
    const after = await tools.score();
    expect(after.release?.verification.fixedVerified).toBe(1);
    expect(after.release?.verification.fixedUnverified).toBeGreaterThanOrEqual(1);
  });
});

describe('analyze --fix: fixes re-checked by the re-scan are fixed-verified', () => {
  it('counts them in release.verification', async () => {
    const { buildProgram } = await import('../src/cli/Commands');
    const root = project();
    const chunks: string[] = [];
    jest.spyOn(process.stdout, 'write').mockImplementation(((s: string) => (chunks.push(String(s)), true)) as never);
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      await buildProgram().parseAsync(['node', 'deployready', 'analyze', root, '--no-ai', '--no-dynamic', '--json', '--fix']);
    } finally {
      jest.restoreAllMocks();
      process.exitCode = 0;
    }
    const json = JSON.parse(chunks.join(''));
    expect(json.fix.applied.length).toBeGreaterThanOrEqual(1);
    expect(json.release.verification.fixedVerified).toBe(json.fix.applied.length);
  });
});
