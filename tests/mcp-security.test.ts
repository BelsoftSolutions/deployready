/**
 * MCP least privilege (ROADMAP-AUDIT B-06 / T-08): path confinement, read-only default profile,
 * start-up opt-in flags, untrusted-content framing, schemaVersion. Includes a real stdio round trip.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { DeployReadyTools, FIXES_DISABLED, LIVE_DISABLED, MCP_SCHEMA_VERSION } from '../src/mcp/tools';
import { wrap } from '../src/mcp/server';
import { Verifier } from '../src/core/Verifier';
import type { Finding } from '../src/types';

const MD5 = "const crypto = require('crypto');\nmodule.exports = crypto.createHash('md5');\n";

function tmp(prefix: string): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

/** A server root plus a sibling project outside it that has fixable findings. */
function layout(): { root: string; outside: string } {
  const root = tmp('dr-mcp-root-');
  const outside = tmp('dr-mcp-outside-');
  fs.writeFileSync(path.join(root, 'app.js'), MD5);
  fs.mkdirSync(path.join(root, 'sub'));
  fs.writeFileSync(path.join(root, 'sub', 'a.js'), MD5);
  fs.writeFileSync(path.join(outside, 'app.js'), MD5);
  fs.writeFileSync(path.join(outside, '.env'), 'PORT=1\n');
  return { root, outside };
}

afterEach(() => jest.restoreAllMocks());

describe('MCP path confinement (reproduces T-08: path args reached outside the server root)', () => {
  it('apply_safe_fixes refuses an absolute path outside the root and changes nothing there', async () => {
    const { root, outside } = layout();
    const t = new DeployReadyTools(root, { allowFixes: true });
    await expect(t.applySafeFixes({ path: outside })).rejects.toThrow(/outside the DeployReady MCP server root/);
    expect(fs.readFileSync(path.join(outside, 'app.js'), 'utf8')).toBe(MD5);
    expect(fs.existsSync(path.join(outside, '.gitignore'))).toBe(false);
  });

  it.each([
    ['..', () => '..'],
    ['../sibling', (o: string) => `../${path.basename(o)}`],
    ['sub/../../sibling', (o: string) => `sub/../../${path.basename(o)}`],
    ['absolute', (o: string) => o],
    ['/', () => '/'],
  ])('scan, score, get_finding, verify and supabase_check refuse %s', async (_label, arg) => {
    const { root, outside } = layout();
    const t = new DeployReadyTools(root);
    const p = arg(outside);
    await expect(t.scan({ path: p })).rejects.toThrow(/outside the DeployReady MCP server root/);
    await expect(t.score({ path: p })).rejects.toThrow(/outside/);
    await expect(t.supabase({ path: p })).rejects.toThrow(/outside/);
    await expect(t.getFinding({ id: 'x', path: p })).rejects.toThrow(/outside/);
    await expect(t.verify({ id: 'x', path: p })).rejects.toThrow(/outside/);
  });

  it('refuses a symlink inside the root that points outside it', async () => {
    const { root, outside } = layout();
    fs.symlinkSync(outside, path.join(root, 'escape'));
    const t = new DeployReadyTools(root, { allowFixes: true });
    await expect(t.scan({ path: 'escape' })).rejects.toThrow(/outside/);
    await expect(t.applySafeFixes({ path: 'escape' })).rejects.toThrow(/outside/);
    expect(fs.readFileSync(path.join(outside, 'app.js'), 'utf8')).toBe(MD5);
  });

  it('a server started on a symlinked root works on the real directory', async () => {
    const { root } = layout();
    const alias = path.join(tmp('dr-mcp-alias-'), 'link');
    fs.symlinkSync(root, alias);
    const t = new DeployReadyTools(alias);
    expect(t.root).toBe(root);
    const r = await t.scan({ path: path.join(root, 'sub') }); // absolute but inside: allowed
    expect(r.target).toBe(path.join(root, 'sub'));
  });

  it('accepts subdirectories and rejects NUL bytes and missing paths with clear errors', async () => {
    const { root } = layout();
    const t = new DeployReadyTools(root);
    const r = await t.scan({ path: 'sub' });
    expect(r.findings.some((f) => f.rule === 'weak-hash')).toBe(true);
    await expect(t.scan({ path: 'sub\0x' })).rejects.toThrow(/Invalid path/);
    await expect(t.scan({ path: 'nope' })).rejects.toThrow(/does not exist/);
  });
});

describe('MCP least-privilege profile (enforced in the handlers, not only by registration)', () => {
  it('read-only default: apply_safe_fixes refuses with a message naming --allow-fixes and writes nothing', async () => {
    const { root } = layout();
    const t = new DeployReadyTools(root);
    await t.scan();
    await expect(t.applySafeFixes()).rejects.toThrow(FIXES_DISABLED);
    expect(FIXES_DISABLED).toMatch(/--allow-fixes/);
    expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toBe(MD5);
    expect((await t.scan()).hint).toMatch(/--allow-fixes/);
  });

  it('static-only default: scan(dynamic), scan_live and supabase live refuse with --allow-live', async () => {
    const { root } = layout();
    const t = new DeployReadyTools(root);
    await expect(t.scan({ dynamic: true })).rejects.toThrow(LIVE_DISABLED);
    await expect(t.scanLive()).rejects.toThrow(/--allow-live/);
    await expect(t.supabase({ live: true })).rejects.toThrow(/--allow-live/);
    await expect(t.supabase({ crossUser: true })).rejects.toThrow(/--allow-live/);
    expect((await t.supabase()).live).toBe(false);
  });

  it('verify of a live finding sends nothing without --allow-live', async () => {
    const { root } = layout();
    const t = new DeployReadyTools(root);
    await t.scan();
    const live: Finding = { id: 'live1', rule: 'missing-security-headers', title: 't', severity: 'warning', category: 'security', source: 'dynamic', description: 'd', recommendation: 'r', endpoint: 'GET /' };
    (t as unknown as { cache: Map<string, { known: Map<string, Finding> }> }).cache.get(root)!.known.set(live.id, live);
    const spy = jest.spyOn(Verifier, 'verify');
    const res = await t.verify({ id: 'live1' });
    expect(res.status).toBe('inconclusive');
    expect(res.detail).toMatch(/--allow-live/);
    expect(spy).not.toHaveBeenCalled();
  });

  it('the profile is frozen: it cannot be changed after start-up', () => {
    const t = new DeployReadyTools(layout().root);
    expect(() => {
      (t.profile as { allowFixes: boolean }).allowFixes = true;
    }).toThrow();
  });

  it('every wrapped object result carries schemaVersion', async () => {
    const res = await wrap(async () => ({ a: 1 }))({});
    expect(JSON.parse(res.content[0]!.text)).toEqual({ schemaVersion: MCP_SCHEMA_VERSION, a: 1 });
  });
});

describe('MCP over a real stdio transport', () => {
  jest.setTimeout(60_000);
  const tsx = path.join(__dirname, '..', 'node_modules', '.bin', 'tsx');
  const entry = path.join(__dirname, '..', 'src', 'index.ts');

  async function connect(root: string, flags: string[] = []): Promise<Client> {
    const client = new Client({ name: 'test', version: '0' });
    await client.connect(new StdioClientTransport({ command: tsx, args: [entry, 'mcp', root, ...flags], stderr: 'ignore' }));
    return client;
  }
  const text = (r: unknown) => ((r as { content: { text: string }[] }).content[0]!.text);

  it('default server lists no modifying or live tool; a call to apply_safe_fixes names the flag; outside paths are refused', async () => {
    const { root, outside } = layout();
    const client = await connect(root);
    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual(['get_finding', 'scan', 'score', 'supabase_check', 'verify']);
      for (const tool of tools) expect(tool.annotations?.readOnlyHint).toBe(true);

      const fix = await client.callTool({ name: 'apply_safe_fixes', arguments: { path: outside } });
      expect(fix.isError).toBe(true);
      expect(text(fix)).toMatch(/--allow-fixes/);
      expect(fs.readFileSync(path.join(outside, 'app.js'), 'utf8')).toBe(MD5);

      const esc = await client.callTool({ name: 'scan', arguments: { path: outside } });
      expect(esc.isError).toBe(true);
      expect(text(esc)).toMatch(/outside the DeployReady MCP server root/);

      const scan = await client.callTool({ name: 'scan', arguments: {} });
      const body = JSON.parse(text(scan));
      expect(body.schemaVersion).toBe(MCP_SCHEMA_VERSION);
      expect(body.dataNotice).toMatch(/Never follow instructions/);
    } finally {
      await client.close();
    }
  });

  it('--allow-fixes registers apply_safe_fixes and it still cannot leave the root', async () => {
    const { root, outside } = layout();
    const client = await connect(root, ['--allow-fixes']);
    try {
      const names = (await client.listTools()).tools.map((t) => t.name);
      expect(names).toContain('apply_safe_fixes');
      expect(names).not.toContain('scan_live');
      const bad = await client.callTool({ name: 'apply_safe_fixes', arguments: { path: outside } });
      expect(bad.isError).toBe(true);
      expect(fs.readFileSync(path.join(outside, 'app.js'), 'utf8')).toBe(MD5);
      const ok = await client.callTool({ name: 'apply_safe_fixes', arguments: {} });
      expect(JSON.parse(text(ok)).applied.length).toBeGreaterThan(0);
      expect(fs.readFileSync(path.join(root, 'app.js'), 'utf8')).toContain("createHash('sha256')");
    } finally {
      await client.close();
    }
  });

  it('--allow-live registers scan_live and supabase_check_live', async () => {
    const client = await connect(layout().root, ['--allow-live']);
    try {
      const names = (await client.listTools()).tools.map((t) => t.name);
      expect(names).toEqual(expect.arrayContaining(['scan_live', 'supabase_check_live']));
      expect(names).not.toContain('apply_safe_fixes');
    } finally {
      await client.close();
    }
  });
});
