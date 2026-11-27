import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DeployReadyTools } from '../src/mcp/tools';
import { buildMcpServer } from '../src/mcp/server';
import { Verifier } from '../src/core/Verifier';

function project(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-mcp-'));
  fs.writeFileSync(path.join(root, '.env'), 'PORT=3000\n');
  fs.writeFileSync(
    path.join(root, 'app.js'),
    "const crypto = require('crypto');\nconst h = crypto.createHash('md5');\nmodule.exports = h;\n",
  );
  fs.writeFileSync(path.join(root, 'client.js'), "const https = require('https');\nmodule.exports = new https.Agent({ rejectUnauthorized: false });\n");
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x","dependencies":{"express":"4.0.0"}}');
  return root;
}

afterEach(() => jest.restoreAllMocks());

describe('MCP tool handlers', () => {
  it('scan returns findings and a not-ready verdict while a critical is open', async () => {
    const t = new DeployReadyTools(project());
    const r = await t.scan();
    expect(r.findings.some((f) => f.rule === 'tls-verification-disabled' && f.severity === 'critical')).toBe(true);
    expect(r.findings.every((f) => f.id && f.rule && f.severity && f.title)).toBe(true);
    expect(r.ready).toBe(false);
    expect(r.verdict).toMatch(/^NOT READY/);
    expect(r.score).toBeLessThan(100);
  });

  it('get_finding returns guidance and the whole file with the line marked', async () => {
    const t = new DeployReadyTools(project());
    const { findings } = await t.scan();
    const weak = findings.find((f) => f.rule === 'weak-hash');
    expect(weak).toBeDefined();
    const d = (await t.getFinding({ id: weak!.id })) as Record<string, any>;
    expect(d.fix.recommendation).toBeTruthy();
    expect(d.fix.deterministicFixAvailable).toBe(true);
    const lines = (d.file_content as string).split('\n');
    expect(lines).toHaveLength(4); // 3 lines + trailing newline: the WHOLE file
    expect(lines[1]).toMatch(/^> 2 \| const h = crypto\.createHash\('md5'\)/);
    expect(lines[0]).toMatch(/^ {2}1 \| /);
  });

  it('get_finding errors clearly before a scan and for unknown ids', async () => {
    const t = new DeployReadyTools(project());
    await expect(t.getFinding({ id: 'nope' })).rejects.toThrow(/Call scan first/);
    await t.scan();
    await expect(t.getFinding({ id: 'nope' })).rejects.toThrow(/Unknown finding id/);
  });

  it('apply_safe_fixes applies, reports backups, and makes the project ready', async () => {
    const root = project();
    const t = new DeployReadyTools(root);
    const before = await t.scan();
    const res = await t.applySafeFixes();
    expect(res.applied.length).toBeGreaterThanOrEqual(2);
    for (const a of res.applied) expect(a.backup === null || fs.existsSync(a.backup)).toBe(true);
    expect(fs.readFileSync(path.join(root, '.gitignore'), 'utf8')).toContain('.env');
    expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toContain("createHash('sha256')");
    expect(res.score).toBeGreaterThan(before.score);
    expect(res.ready).toBe(true);
  });

  it('verify passes the Verifier status through unchanged', async () => {
    const t = new DeployReadyTools(project());
    const { findings } = await t.scan();
    const id = findings[0]!.id;
    const spy = jest.spyOn(Verifier, 'verify').mockResolvedValue({ status: 'inconclusive' as never, detail: 'why' });
    expect(await t.verify({ id })).toEqual({ id, status: 'inconclusive', detail: 'why' });
    spy.mockResolvedValue({ status: 'still-present' });
    expect((await t.verify({ id })).status).toBe('still-present');
  });

  it('verify reports still-present before and fixed after the code is changed', async () => {
    const root = project();
    const t = new DeployReadyTools(root);
    const { findings } = await t.scan();
    const weak = findings.find((f) => f.rule === 'weak-hash')!;
    expect((await t.verify({ id: weak.id })).status).toBe('still-present');
    fs.writeFileSync(path.join(root, 'app.js'), "const crypto = require('crypto');\nmodule.exports = crypto;\n");
    expect((await t.verify({ id: weak.id })).status).toBe('fixed');
  });

  it('score re-scans and defines ready as no open critical findings', async () => {
    const root = project();
    const t = new DeployReadyTools(root);
    await t.scan();
    const bad = await t.score();
    expect(bad.ready).toBe(false);
    expect(bad.openCritical.map((f) => f.rule)).toContain('tls-verification-disabled');
    fs.writeFileSync(path.join(root, 'client.js'), "module.exports = {};\n");
    const good = await t.score();
    expect(good.openCritical).toEqual([]);
    expect(good.ready).toBe(true);
    expect(good.verdict).toMatch(/^READY/);
  });

  it('never writes to stdout while handling tools', async () => {
    const write = jest.spyOn(process.stdout, 'write');
    const log = jest.spyOn(console, 'log');
    const t = new DeployReadyTools(project());
    await t.scan();
    await t.applySafeFixes();
    await t.score();
    expect(write).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it('registers the five tools with loop guidance in their descriptions', () => {
    const server = buildMcpServer(new DeployReadyTools('.')) as unknown as {
      _registeredTools: Record<string, { description?: string }>;
    };
    expect(Object.keys(server._registeredTools).sort()).toEqual([
      'apply_safe_fixes',
      'get_finding',
      'scan',
      'score',
      'supabase_check',
      'verify',
    ]);
    for (const [name, tool] of Object.entries(server._registeredTools)) {
      if (name !== 'supabase_check') expect(tool.description).toMatch(/scan -> apply_safe_fixes/);
    }
  });
});
