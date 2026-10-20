import { PROBE_PATHS, SIGNATURES } from '../src/dynamic/commonPaths/signatures';
import { html, json, probeRoutes, text } from './helpers/probeServer';
import type { Reply } from './helpers/probeServer';

const SQLITE = Buffer.concat([Buffer.from('SQLite format 3\0', 'latin1'), Buffer.alloc(100)]);

interface Row {
  id: string;
  paths: string[];
  positive: Reply;
  /** Plausible 200 responses that must NOT be a finding. */
  negatives: Record<string, Reply>;
}

const ENV_OK = 'NODE_ENV=production\nPORT=3000\nLOG_LEVEL=debug\n';

const ROWS: Row[] = [
  {
    id: 'env',
    paths: ['/.env', '/.env.local', '/.env.production'],
    positive: text(ENV_OK),
    negatives: {
      prose: text('This file is not here.\nPlease look elsewhere, thanks for asking.\nA=B is an example.\n'),
      'mostly prose': text('A=1\nthis is not a pair\nanother sentence\nmore words\n'),
      html: html('<html><body>A=B\nC=D\n</body></html>'),
      empty: text(''),
      'only comments': text('# a comment\n# another\n'),
      'too large': text(`A=1\n${'B'.repeat(70_000)}\n`),
    },
  },
  {
    id: 'git-config',
    paths: ['/.git/config'],
    positive: text('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.com/r.git\n'),
    negatives: {
      'core only': text('[core]\n\teditor = vim\n'),
      'no core': text('[remote "origin"]\n\turl = x\n'),
      html: html('<html>[core]\nrepositoryformatversion</html>'),
    },
  },
  {
    id: 'npmrc',
    paths: ['/.npmrc'],
    positive: text('//registry.example.org/:_authToken=abcd1234efgh\n'),
    negatives: {
      'registry only': text('registry=https://registry.example.org/\nsave-exact=true\n'),
      'empty token': text('_authToken=\n'),
      html: html('<html>_authToken=abc</html>'),
    },
  },
  {
    id: 'sql-dump',
    paths: ['/backup.sql', '/dump.sql'],
    positive: text('-- MySQL dump 10.13\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n'),
    negatives: {
      prose: text('Please contact us to request a backup of your data.\n'),
      'single statement, no header': text('CREATE TABLE users (id int);\nsome text\n'),
      html: html('<html>-- MySQL dump</html>'),
    },
  },
  {
    id: 'sqlite',
    paths: ['/db.sqlite3'],
    positive: { type: 'application/octet-stream', body: SQLITE },
    negatives: {
      text: text('not a database'),
      'wrong magic': { type: 'application/octet-stream', body: Buffer.from('SQLite format 4\0 and more') },
    },
  },
  {
    id: 'actuator-env',
    paths: ['/actuator/env'],
    positive: json({ activeProfiles: ['prod'], propertySources: [{ name: 'systemEnvironment', properties: {} }] }),
    negatives: {
      'wrong json': json({ status: 'ok' }),
      'not an array': json({ activeProfiles: 'prod' }),
      html: html('<html>{"propertySources":[]}</html>'),
    },
  },
  {
    id: 'actuator',
    paths: ['/actuator'],
    positive: json({ _links: { self: { href: 'http://localhost/actuator' }, health: { href: 'http://localhost/actuator/health' } } }),
    negatives: {
      'self only': json({ _links: { self: { href: 'http://localhost/actuator' } } }),
      'no href': json({ _links: { self: { href: 'x' }, health: {} } }),
      'no self': json({ _links: { health: { href: 'x' } } }),
      'wrong json': json({ ok: true }),
    },
  },
  {
    id: 'phpinfo',
    paths: ['/phpinfo.php'],
    positive: html('<html><head><title>phpinfo()</title></head><body>PHP Version 8.2</body></html>'),
    negatives: {
      'other page': html('<html><head><title>Hello</title></head><body>welcome</body></html>'),
      'only one marker': html('<html><body>PHP Version 8.2</body></html>'),
    },
  },
  {
    id: 'metrics',
    paths: ['/metrics'],
    positive: text('# HELP http_requests_total Total requests.\n# TYPE http_requests_total counter\nhttp_requests_total 5\n'),
    negatives: {
      'help only': text('# HELP http_requests_total Total requests.\n'),
      'different names': text('# HELP a_total x\n# TYPE b_total counter\n'),
      'bad type': text('# HELP a_total x\n# TYPE a_total weird\n'),
      html: html('<html># HELP a x\n# TYPE a counter\n</html>'),
    },
  },
  {
    id: 'pprof',
    paths: ['/debug/pprof/'],
    positive: html('<html><body><h1>/debug/pprof/</h1>Types of profiles available:</body></html>'),
    negatives: { 'other page': html('<html><body>nothing here</body></html>') },
  },
  {
    id: 'server-status',
    paths: ['/server-status'],
    positive: html('<html><body><h1>Apache Server Status for localhost</h1></body></html>'),
    negatives: { 'other page': html('<html><body>Server status: fine</body></html>') },
  },
  {
    id: 'console',
    paths: ['/console'],
    positive: html('<html><body>Werkzeug <h1>Interactive Console</h1></body></html>'),
    negatives: {
      'no werkzeug': html('<html><body><h1>Interactive Console</h1> of my game</body></html>'),
      'werkzeug only': html('<html><body>Werkzeug is a library</body></html>'),
    },
  },
  {
    id: 'admin',
    paths: ['/admin'],
    positive: html('<html><head><title>Admin Panel</title></head><body><p>users</p></body></html>'),
    negatives: {
      'plain page': html('<html><head><title>Welcome</title></head><body><h1>Hello</h1></body></html>'),
      'json': json({ admin: true, users: [] }),
      'word only in body': html('<html><head><title>Home</title></head><body><p>admin contact</p></body></html>'),
      'login form': html('<html><head><title>Admin login</title></head><body><input type="password"></body></html>'),
    },
  },
];

describe('fixed path table', () => {
  it('has exactly the 16 design paths in order', () => {
    expect(PROBE_PATHS.map((p) => p.path)).toEqual([
      '/.env', '/.env.local', '/.env.production', '/.git/config', '/.npmrc', '/backup.sql', '/dump.sql',
      '/db.sqlite3', '/actuator/env', '/actuator', '/phpinfo.php', '/metrics', '/debug/pprof/',
      '/server-status', '/console', '/admin',
    ]);
  });

  it('has a test fixture for every table row', () => {
    expect(ROWS.map((r) => r.id)).toEqual(SIGNATURES.map((s) => s.id));
    expect(ROWS.flatMap((r) => r.paths)).toEqual(PROBE_PATHS.map((p) => p.path));
  });
});

describe.each(ROWS)('row $id', (row) => {
  it.each(row.paths)('positive: %s is a guessed-path finding', async (path) => {
    const { findings, report } = await probeRoutes({ [path]: row.positive });
    expect(findings.map((f) => f.endpoint)).toEqual([path]);
    const f = findings[0]!;
    expect(f.rule).toBe('common-path-exposure');
    expect(f.guessed).toBe(true);
    expect(f.source).toBe('dynamic');
    expect(f.category).toBe('security');
    expect(f.title.endsWith('(guessed path, lower confidence)')).toBe(true);
    expect(report.probed.find((p) => p.path === path)).toMatchObject({ status: 200, outcome: 'found' });
    expect(report.probed.filter((p) => p.outcome === 'found')).toHaveLength(1);
  });

  it.each(Object.keys(row.negatives))('negative: %s yields no finding', async (name) => {
    const routes = Object.fromEntries(row.paths.map((p) => [p, row.negatives[name]!]));
    const { findings, report } = await probeRoutes(routes);
    expect(findings).toEqual([]);
    for (const path of row.paths) {
      expect(report.probed.find((p) => p.path === path)).toMatchObject({ status: 200, outcome: 'not-proven' });
    }
  });

  it('a 404 for every path yields no finding', async () => {
    const { findings, report } = await probeRoutes({});
    expect(findings).toEqual([]);
    expect(report.probed.every((p) => p.outcome === 'not-found')).toBe(true);
  });
});

describe('row severities (table values)', () => {
  const sev = async (path: string, reply: Reply) => (await probeRoutes({ [path]: reply })).findings[0]?.severity;

  it('matches the design table', async () => {
    expect(await sev('/.git/config', ROWS[1]!.positive)).toBe('critical');
    expect(await sev('/.npmrc', ROWS[2]!.positive)).toBe('critical');
    expect(await sev('/backup.sql', ROWS[3]!.positive)).toBe('critical');
    expect(await sev('/db.sqlite3', ROWS[4]!.positive)).toBe('critical');
    expect(await sev('/actuator/env', ROWS[5]!.positive)).toBe('warning');
    expect(await sev('/actuator', ROWS[6]!.positive)).toBe('info');
    expect(await sev('/phpinfo.php', ROWS[7]!.positive)).toBe('warning');
    expect(await sev('/metrics', ROWS[8]!.positive)).toBe('info');
    expect(await sev('/debug/pprof/', ROWS[9]!.positive)).toBe('warning');
    expect(await sev('/server-status', ROWS[10]!.positive)).toBe('warning');
    expect(await sev('/console', ROWS[11]!.positive)).toBe('critical');
    expect(await sev('/admin', ROWS[12]!.positive)).toBe('warning');
  });

  it('a locked Werkzeug console is a warning, an unlocked one critical', async () => {
    const locked = html('<html><body>Werkzeug debugger. <h1>Console Locked</h1> Interactive Console PIN</body></html>');
    expect(await sev('/console', locked)).toBe('warning');
    expect(await sev('/console', ROWS[11]!.positive)).toBe('critical');
  });
});
