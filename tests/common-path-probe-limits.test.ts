import axios from 'axios';
import { runCommonPathProbe, capRequester, ProbeCapError, MAX_PROBE_REQUESTS } from '../src/dynamic/commonPaths/prober';
import type { ProbeResponse } from '../src/dynamic/commonPaths/evidence';
import { PROBE_PATHS, SIGNATURES, capSeverity } from '../src/dynamic/commonPaths/signatures';
import { setVerbose } from '../src/utils/logger';
import { html, json, PLAIN_404, probeRoutes, send, text, withServer } from './helpers/probeServer';

const TABLE = PROBE_PATHS.map((p) => p.path);
const CONTROL = /^\/__deployready_probe_[0-9a-f]{12}$/;

describe('request limits', () => {
  it('sends one control then exactly the table paths in order, GET only, never more than 20', async () => {
    const { seen, report } = await probeRoutes({});
    expect(seen).toHaveLength(17);
    expect(seen.length).toBeLessThanOrEqual(MAX_PROBE_REQUESTS);
    expect(seen[0]?.path).toMatch(CONTROL);
    expect(seen.slice(1).map((r) => r.path)).toEqual(TABLE);
    expect(seen.every((r) => r.method === 'GET')).toBe(true);
    expect(report.control.path).toBe(seen[0]?.path);
    expect(report.control.status).toBe(404);
    expect(report.cap).toBe(20);
    expect(report.probed.map((p) => p.path)).toEqual(TABLE);
  });

  it('sends no cookies or authorization, only the scanner User-Agent', async () => {
    const { seen } = await probeRoutes({});
    for (const r of seen) {
      expect(r.headers.cookie).toBeUndefined();
      expect(r.headers.authorization).toBeUndefined();
      expect(r.headers['user-agent']).toMatch(/^DeployReady-Scanner/);
    }
  });

  it('the requester wrapper throws on the 21st request and never forwards it', async () => {
    const calls: string[] = [];
    const ok: ProbeResponse = { status: 200, contentType: '', location: '', body: Buffer.alloc(0) };
    const wrapped = capRequester(async (p) => {
      calls.push(p);
      return ok;
    });
    for (let i = 0; i < 20; i++) await wrapped(`/p${i}`);
    expect(() => wrapped('/p20')).toThrow(ProbeCapError);
    expect(calls).toHaveLength(20);
  });

  it('the cap is 20 and the table plus control fits under it', () => {
    expect(MAX_PROBE_REQUESTS).toBe(20);
    expect(PROBE_PATHS).toHaveLength(16);
  });

  it('aborts after 3 consecutive network errors and records it', async () => {
    const { seen, report, findings } = await withServer(
      (req, res) => {
        if (/^\/__deployready_probe_/.test(req.url ?? '') ) return send(res, PLAIN_404);
        req.socket.destroy();
      },
      async (baseUrl, seen) => ({ ...(await runCommonPathProbe(baseUrl, { exclude: [], delayMs: 0 })), seen }),
    );
    expect(findings).toEqual([]);
    expect(seen).toHaveLength(4);
    expect(report.probed).toHaveLength(3);
    expect(report.probed.every((p) => p.outcome === 'error')).toBe(true);
    expect(report.aborted).toMatch(/3 consecutive network errors/);
  });

  it('non-consecutive errors do not abort', async () => {
    const failing = new Set(TABLE.filter((_, i) => i % 3 === 0));
    const { seen, report } = await withServer(
      (req, res) => {
        if (failing.has(req.url ?? '')) return req.socket.destroy();
        send(res, PLAIN_404);
      },
      async (baseUrl, seen) => ({ ...(await runCommonPathProbe(baseUrl, { exclude: [], delayMs: 0 })), seen }),
    );
    expect(seen).toHaveLength(17);
    expect(report.aborted).toBeUndefined();
    expect(report.probed.filter((p) => p.outcome === 'error')).toHaveLength(failing.size);
  });

  it('a non-loopback base URL throws before any request is made', async () => {
    const create = jest.spyOn(axios, 'create');
    const get = jest.spyOn(axios, 'get');
    try {
      await expect(runCommonPathProbe('http://example.com', { exclude: [], delayMs: 0 })).rejects.toThrow(/non-loopback/);
      await expect(runCommonPathProbe('http://192.0.2.10:8080', { exclude: [], delayMs: 0 })).rejects.toThrow(/non-loopback/);
      expect(create).not.toHaveBeenCalled();
      expect(get).not.toHaveBeenCalled();
    } finally {
      create.mockRestore();
      get.mockRestore();
    }
  });

  it('honours exclude: excluded paths get zero requests and are reported as covered', async () => {
    const exclude = ['/admin', '/.env', '/debug/pprof', '/Metrics?x=1'];
    const { seen, report } = await probeRoutes({}, { exclude });
    const requested = seen.map((r) => r.path);
    for (const p of ['/admin', '/.env', '/debug/pprof/', '/metrics']) expect(requested).not.toContain(p);
    expect(requested.slice(1)).toEqual(TABLE.filter((p) => !['/admin', '/.env', '/debug/pprof/', '/metrics'].includes(p)));
    expect(report.covered).toEqual(['/.env', '/metrics', '/debug/pprof/', '/admin']);
    expect(report.probed.map((p) => p.path)).not.toContain('/admin');
  });

  it('excluding every path still sends only the control and no finding', async () => {
    const { seen, findings, report } = await probeRoutes({}, { exclude: TABLE });
    expect(seen).toHaveLength(1);
    expect(findings).toEqual([]);
    expect(report.probed).toEqual([]);
  });

  it('waits between requests when a delay is given', async () => {
    const start = Date.now();
    await probeRoutes({}, { delayMs: 15, exclude: TABLE.slice(4) });
    // control + 4 paths = 5 requests, 4 gaps
    expect(Date.now() - start).toBeGreaterThanOrEqual(4 * 15 - 5);
  });

  it('reads at most 256 KB of a body and still answers', async () => {
    const big = 'A=1\n'.repeat(200_000);
    const { findings, report } = await probeRoutes({ '/.env': text(big) });
    expect(findings).toEqual([]);
    expect(report.probed.find((p) => p.path === '/.env')?.outcome).toBe('not-proven');
  });

  it('keeps userinfo out of the target and sends no credentials', async () => {
    const userinfo = ['probeuser', 'probepass9'];
    const { report, seen } = await withServer(
      (_req, res) => send(res, PLAIN_404),
      async (baseUrl, seen) => {
        const withCreds = baseUrl.replace('http://', `http://${userinfo[0]}:${userinfo[1]}@`);
        return { ...(await runCommonPathProbe(withCreds, { exclude: [], delayMs: 0 })), seen };
      },
    );
    expect(JSON.stringify(report)).not.toContain(userinfo[1]);
    expect(JSON.stringify(report)).not.toContain(userinfo[0]);
    expect(seen.every((r) => r.headers.authorization === undefined)).toBe(true);
  });
});

describe('redaction', () => {
  const awsShape = (): string => ['AKIA', 'QWERTYUIOPASDFGH'].join('');
  const secretValue = (): string => ['zq81', 'kd7f', 'h2xw'].join('');

  it('never puts values in findings, evidence, report or verbose log output', async () => {
    const aws = awsShape();
    const secret = secretValue();
    const dbUrl = ['postgres://', 'dbuser', ':', 'dbpass91x', '@db.internal/app'].join('');
    const body = `AWS_ACCESS_KEY_ID=${aws}\nSESSION_SECRET=${secret}\nDATABASE_URL=${dbUrl}\nPORT=3000\n`;
    const lines: string[] = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      lines.push(a.map(String).join(' '));
    });
    setVerbose(true);
    try {
      const { findings, report } = await probeRoutes({ '/.env': text(body) });
      expect(findings).toHaveLength(1);
      const f = findings[0]!;
      expect(f.severity).toBe('critical');
      const dump = JSON.stringify({ findings, report }) + lines.join('\n');
      for (const v of [aws, secret, 'dbpass91x', 'dbuser', 'db.internal']) expect(dump).not.toContain(v);
      expect(f.evidence).toContain('AWS_ACCESS_KEY_ID');
      expect(f.evidence).toContain('SESSION_SECRET');
      expect(f.evidence).toMatch(/4 KEY=VALUE lines/);
      expect(f.evidence).toMatch(/values not shown/);
      expect(lines.length).toBeGreaterThan(0);
    } finally {
      setVerbose(false);
      spy.mockRestore();
    }
  });

  it('never echoes a git remote URL, an npm token or an actuator secret', async () => {
    const aws = awsShape();
    const token = ['npm', 'tok', 'abcd1234efgh'].join('');
    const gitUrl = ['https://', 'gituser', ':', 'gitpass77z', '@example.com/r.git'].join('');
    const { findings, report } = await probeRoutes({
      '/.git/config': text(`[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = ${gitUrl}\n`),
      '/.npmrc': text(`//registry.example.org/:_authToken=${token}\n`),
      '/actuator/env': json({ activeProfiles: ['prod'], propertySources: [{ properties: { key: { value: aws } } }] }),
    });
    expect(findings).toHaveLength(3);
    const dump = JSON.stringify({ findings, report });
    for (const v of [aws, token, 'gitpass77z', 'gituser']) expect(dump).not.toContain(v);
    expect(findings.find((f) => f.endpoint === '/actuator/env')?.severity).toBe('critical');
  });

  it('logs one debug line per request in the documented format', async () => {
    const lines: string[] = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      lines.push(a.map(String).join(' '));
    });
    setVerbose(true);
    try {
      await probeRoutes({ '/admin': html('<html><head><title>Admin</title></head></html>') });
      const probeLines = lines.filter((l) => l.includes('[probe-common]'));
      expect(probeLines).toHaveLength(17);
      expect(probeLines.some((l) => /\[probe-common\] GET \/admin -> 200 found: matched/.test(l))).toBe(true);
      expect(probeLines.some((l) => /\[probe-common\] GET \/\.env -> 404 not-found: HTTP 404/.test(l))).toBe(true);
      expect(probeLines.some((l) => /\[probe-common\] GET \/__deployready_probe_[0-9a-f]{12} -> 404 control/.test(l))).toBe(true);
    } finally {
      setVerbose(false);
      spy.mockRestore();
    }
  });
});

describe('severity', () => {
  const awsShape = (): string => ['AKIA', 'QWERTYUIOPASDFGH'].join('');
  const sevOf = async (body: string) => (await probeRoutes({ '/.env': text(body) })).findings[0]?.severity;

  it('.env with only benign values is a warning', async () => {
    expect(await sevOf('NODE_ENV=production\nPORT=3000\nLOG_LEVEL=debug\nAPP_NAME=demo\n')).toBe('warning');
  });

  it('.env with a secret-named placeholder or empty value stays a warning', async () => {
    const body = 'API_KEY=changeme\nSECRET_TOKEN=your_token_here\nDB_PASSWORD=<password>\nSTRIPE_KEY=${STRIPE}\nCREDENTIAL=\nPORT=1\n';
    expect(await sevOf(body)).toBe('warning');
  });

  it('.env with a secret-named non-placeholder value is critical', async () => {
    expect(await sevOf('PORT=3000\nSESSION_SECRET=zq81kd7fh2xw\n')).toBe('critical');
    expect(await sevOf('PORT=3000\nexport DATABASE_URL="sqlite:///local.db"\n')).toBe('critical');
  });

  it('.env with a high-confidence secret under a harmless key name is critical', async () => {
    expect(await sevOf(`PORT=3000\nSOMETHING=${awsShape()}\n`)).toBe('critical');
  });

  it('/actuator/env without an unmasked secret is a warning', async () => {
    const r = await probeRoutes({ '/actuator/env': json({ activeProfiles: ['dev'], propertySources: [{ properties: { a: { value: '******' } } }] }) });
    expect(r.findings[0]?.severity).toBe('warning');
  });

  it('non-conclusive rows never exceed their ceiling even with secret-shaped content', async () => {
    const aws = awsShape();
    const r = await probeRoutes({
      '/actuator': json({ _links: { self: { href: 'x' }, env: { href: 'y' } }, note: aws }),
      '/metrics': text(`# HELP a_total ${aws}\n# TYPE a_total counter\n`),
      '/phpinfo.php': html(`<title>phpinfo()</title> ${aws}`),
      '/admin': html(`<html><head><title>Admin</title></head><body>${aws}</body></html>`),
      '/server-status': html(`Apache Server Status for x ${aws}`),
      '/debug/pprof/': html(`Types of profiles available ${aws}`),
    });
    const sev = Object.fromEntries(r.findings.map((f) => [f.endpoint, f.severity]));
    expect(sev).toEqual({
      '/actuator': 'info',
      '/metrics': 'info',
      '/phpinfo.php': 'warning',
      '/server-status': 'warning',
      '/debug/pprof/': 'warning',
      '/admin': 'warning',
    });
  });

  it('only conclusive rows may have a critical ceiling', () => {
    for (const s of SIGNATURES) {
      if (s.ceiling === 'critical') expect(s.conclusive).toBe(true);
      if (!s.conclusive) expect(s.ceiling).not.toBe('critical');
    }
  });

  it('capSeverity returns the lower severity', () => {
    expect(capSeverity('critical', 'warning')).toBe('warning');
    expect(capSeverity('critical', 'info')).toBe('info');
    expect(capSeverity('info', 'critical')).toBe('info');
    expect(capSeverity('warning', 'warning')).toBe('warning');
  });
});
