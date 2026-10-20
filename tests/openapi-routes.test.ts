import { CodeParser } from '../src/parser/CodeParser';
import { parseYaml, YamlFlow, YamlUnsupported } from '../src/parser/miniYaml';
import { EndpointMapper } from '../src/dynamic/EndpointMapper';
import type { CodeGraph, Route } from '../src/types';
import { expressProject, writeProject } from './helpers/dummyApp';

const brief = (g: CodeGraph) => g.routes.map((r) => `${r.method} ${r.path}`).sort();
const find = (g: CodeGraph, method: string, p: string): Route | undefined => g.routes.find((r) => r.method === method && r.path === p);
const spec = (o: unknown) => JSON.stringify(o, null, 2);

const JSON_SPEC = {
  openapi: '3.0.3',
  info: { title: 'Dummy', version: '1.0.0' },
  paths: {
    '/ping': { get: { responses: { '200': { description: 'ok' } } } },
    '/items': { get: {}, post: {}, parameters: [{ name: 'q', in: 'query' }] },
    '/items/{id}': { get: {}, delete: {} },
    'x-not-a-path': { get: {} },
  },
};

describe('OpenAPI JSON on disk', () => {
  it('turns every method + path into an openapi route, relative to the spec file', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': spec(JSON_SPEC) }));
    expect(brief(g)).toEqual(['DELETE /items/{id}', 'GET /items', 'GET /items/{id}', 'GET /ping', 'POST /items']);
    for (const r of g.routes) {
      expect(r.source).toBe('openapi');
      expect(r.file).toBe('openapi.json');
      expect(r.guarded).toBe(false);
    }
    expect(g.specFiles).toEqual(['openapi.json']);
    expect(g.discoveryNotes).toBeUndefined();
  });

  it('finds swagger.json and nested spec files too', async () => {
    const g = await CodeParser.analyze(writeProject({ 'docs/api/swagger.json': spec({ ...JSON_SPEC, paths: { '/a': { get: {} } } }) }));
    expect(find(g, 'GET', '/a')?.file).toBe('docs/api/swagger.json');
  });

  it('parameterised paths and non-GET stay discovered but are never requested', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': spec(JSON_SPEC) }));
    const plan = EndpointMapper.plan(g.routes);
    expect(plan.targets.map((t) => t.path).sort()).toEqual(['/items', '/ping']);
    expect(plan.targets.every((t) => t.method === 'GET')).toBe(true);
    expect(plan.skipped.map((s) => `${s.method} ${s.path}`).sort()).toEqual(['DELETE /items/{id}', 'GET /items/{id}', 'POST /items']);
    expect(plan.targets[0]!.why[0]).toBe('declared in OpenAPI/Swagger file openapi.json');
  });

  it('a JSON file without an openapi/swagger field or without paths is skipped with a note', async () => {
    const g = await CodeParser.analyze(
      writeProject({ 'openapi.json': spec({ paths: { '/x': { get: {} } } }), 'swagger.json': spec({ swagger: '2.0', info: {} }) }),
    );
    expect(g.routes).toEqual([]);
    expect(g.discoveryNotes).toHaveLength(2);
    expect(g.discoveryNotes!.join('\n')).toMatch(/openapi\.json not used: .*no "openapi" or "swagger"/);
  });

  it('invalid JSON is skipped with a note', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': '{ not json' }));
    expect(g.routes).toEqual([]);
    expect(g.discoveryNotes![0]).toMatch(/not valid JSON/);
  });
});

const YAML_SPEC = `# dummy API
openapi: 3.0.0
info:
  title: "Dummy: API"   # trailing comment
  description: |
    Multi-line text with a colon: and a # hash
    paths:
      - /not/real
paths:
  /ping:
    get:
      summary: Ping
      description: >-
        folded
        text
      responses:
        '200':
          description: ok
  "/quoted":
    get:
      responses:
        200:
          description: fine
  /items/{id}:
    parameters:
      - name: id
        in: path
        required: true
    get:
      tags: []
    put: {}
`;

describe('OpenAPI YAML on disk', () => {
  it('reads a block-style spec (comments, quoted keys, block scalars) with no dependency', async () => {
    const dir = writeProject({ 'openapi.yaml': YAML_SPEC });
    const g = await CodeParser.analyze(dir);
    expect(brief(g)).toEqual(['GET /items/{id}', 'GET /ping', 'GET /quoted', 'PUT /items/{id}']);
    expect(g.routes.every((r) => r.source === 'openapi' && r.file === 'openapi.yaml')).toBe(true);
    expect(g.discoveryNotes).toBeUndefined();
  });

  it('reads .yml as well', async () => {
    const g = await CodeParser.analyze(writeProject({ 'swagger.yml': 'swagger: "2.0"\npaths:\n  /y:\n    get:\n      summary: y\n' }));
    expect(brief(g)).toEqual(['GET /y']);
  });

  it('flow-style YAML it cannot read is skipped with a visible info line and nothing is guessed', async () => {
    const flowPaths = 'openapi: 3.0.0\npaths: {"/a": {get: {}}, "/b": {get: {}}}\n';
    const flowPathItem = 'openapi: 3.0.0\npaths:\n  /a: {get: {summary: x}}\n';
    const flowOperation = 'openapi: 3.0.0\npaths:\n  /a:\n    get: {summary: x}\n';
    for (const [name, body] of [['paths', flowPaths], ['path item', flowPathItem], ['operation', flowOperation]] as const) {
      const g = await CodeParser.analyze(writeProject({ 'openapi.yaml': body }));
      expect({ name, routes: g.routes }).toEqual({ name, routes: [] });
      expect(g.discoveryNotes).toHaveLength(1);
      expect(g.discoveryNotes![0]).toMatch(/openapi\.yaml not used: .*flow-style YAML/);
      expect(g.discoveryNotes![0]).toMatch(/No routes were guessed/);
      expect(g.specFiles).toBeUndefined();
    }
  });

  it('anchors, aliases, tags, merge keys and multiple documents are skipped, never guessed', async () => {
    const bodies = [
      'openapi: 3.0.0\nx-base: &base\n  a: 1\npaths:\n  /a:\n    get: *base\n',
      'openapi: 3.0.0\npaths:\n  /a:\n    get:\n      <<: *x\n',
      'openapi: 3.0.0\npaths: !!map\n  /a:\n    get: {}\n',
      'openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n---\nopenapi: 3.0.0\n',
      'openapi: 3.0.0\npaths:\n\t/a:\n\t\tget: {}\n',
    ];
    for (const body of bodies) {
      const g = await CodeParser.analyze(writeProject({ 'openapi.yml': body }));
      expect(g.routes).toEqual([]);
      expect(g.discoveryNotes?.[0]).toMatch(/not used: .*(YAML that DeployReady's small reader does not support)/);
    }
  });

  it('flow-style values in parts the scan does not need (schemas, examples) do not block the file', async () => {
    const body = `openapi: 3.0.0
paths:
  /a:
    get:
      responses:
        '200':
          content:
            application/json:
              schema: {type: object, required: [id]}
              example: [1, 2,
                3]
`;
    const g = await CodeParser.analyze(writeProject({ 'openapi.yaml': body }));
    expect(brief(g)).toEqual(['GET /a']);
  });
});

describe('miniYaml', () => {
  it('parses nested maps, sequences of maps and scalars', () => {
    const v = parseYaml('a: 1\nb:\n  - x: 1\n    y: two words\n  - plain\nc:\n- k\n- l\n') as Record<string, unknown>;
    expect(v.a).toBe('1');
    expect(v.b).toEqual([{ x: '1', y: 'two words' }, 'plain']);
    expect(v.c).toEqual(['k', 'l']);
  });

  it('keeps flow collections opaque and reads empty ones', () => {
    const v = parseYaml('a: {}\nb: []\nc: [1, 2]\n') as Record<string, unknown>;
    expect(v.a).toEqual({});
    expect(v.b).toEqual([]);
    expect(v.c).toBeInstanceOf(YamlFlow);
  });

  it('throws YamlUnsupported for what it cannot read', () => {
    expect(() => parseYaml('a: &x 1\n')).toThrow(YamlUnsupported);
    expect(() => parseYaml('a: "unterminated\n')).toThrow(YamlUnsupported);
    expect(() => parseYaml('? complex\n: key\n')).toThrow(YamlUnsupported);
  });
});

describe('base path rules', () => {
  const one = { '/ping': { get: {} } };

  it('Swagger 2 basePath is applied as a prefix (JSON and YAML)', async () => {
    const j = await CodeParser.analyze(writeProject({ 'swagger.json': spec({ swagger: '2.0', basePath: '/v1', paths: one }) }));
    expect(brief(j)).toEqual(['GET /v1/ping']);
    const y = await CodeParser.analyze(writeProject({ 'swagger.yaml': 'swagger: "2.0"\nbasePath: /api/v2/\npaths:\n  /ping:\n    get: {}\n' }));
    expect(brief(y)).toEqual(['GET /api/v2/ping']);
    const root = await CodeParser.analyze(writeProject({ 'swagger.json': spec({ swagger: '2.0', basePath: '/', paths: one }) }));
    expect(brief(root)).toEqual(['GET /ping']);
  });

  it('Swagger 2 host is never used', async () => {
    const g = await CodeParser.analyze(writeProject({ 'swagger.json': spec({ swagger: '2.0', host: 'api.example.com', paths: one }) }));
    expect(brief(g)).toEqual(['GET /ping']);
  });

  it('OpenAPI 3 relative server URL is a prefix', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': spec({ openapi: '3.0.0', servers: [{ url: '/api/v3' }], paths: one }) }));
    expect(brief(g)).toEqual(['GET /api/v3/ping']);
  });

  it('OpenAPI 3 loopback server URL path is a prefix', async () => {
    const g = await CodeParser.analyze(
      writeProject({ 'openapi.json': spec({ openapi: '3.0.0', servers: [{ url: 'http://localhost:3000/svc' }], paths: one }) }),
    );
    expect(brief(g)).toEqual(['GET /svc/ping']);
    const g2 = await CodeParser.analyze(
      writeProject({ 'openapi.yaml': 'openapi: 3.0.0\nservers:\n  - url: http://127.0.0.1:8080/svc2\npaths:\n  /ping:\n    get: {}\n' }),
    );
    expect(brief(g2)).toEqual(['GET /svc2/ping']);
  });

  it('a production hostname server: its path is NOT used as the local prefix', async () => {
    const g = await CodeParser.analyze(
      writeProject({ 'openapi.json': spec({ openapi: '3.0.0', servers: [{ url: 'https://api.example.com/prod/v9' }, { url: '/second' }], paths: one }) }),
    );
    expect(brief(g)).toEqual(['GET /ping']);
  });

  it('only servers[0] counts, and a server variable uses its declared default', async () => {
    const withVar = spec({
      openapi: '3.0.0',
      servers: [{ url: '/{ver}', variables: { ver: { default: 'v4' } } }],
      paths: one,
    });
    expect(brief(await CodeParser.analyze(writeProject({ 'openapi.json': withVar })))).toEqual(['GET /v4/ping']);
    const noDefault = spec({ openapi: '3.0.0', servers: [{ url: '/{ver}' }], paths: one });
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': noDefault }));
    expect(g.routes).toEqual([]);
    expect(g.discoveryNotes![0]).toMatch(/variable \{ver\} without a default/);
  });
});

describe('guarded from security', () => {
  const doc = (global: unknown, ops: Record<string, unknown>) =>
    spec({
      openapi: '3.0.0',
      ...(global === undefined ? {} : { security: global }),
      paths: Object.fromEntries(Object.entries(ops).map(([p, sec]) => [p, { get: sec === undefined ? {} : { security: sec } }])),
    });
  const bearer = [{ bearerAuth: [] }];

  it('global security guards every operation without its own', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': doc(bearer, { '/a': undefined, '/b': undefined }) }));
    expect(g.routes.map((r) => r.guarded)).toEqual([true, true]);
  });

  it('per-operation security guards only that operation', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': doc(undefined, { '/open': undefined, '/locked': bearer }) }));
    expect(find(g, 'GET', '/open')!.guarded).toBe(false);
    expect(find(g, 'GET', '/locked')!.guarded).toBe(true);
  });

  it('security: [] on an operation overrides global security (explicitly public)', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': doc(bearer, { '/login': [], '/me': undefined, '/x': bearer }) }));
    expect(find(g, 'GET', '/login')!.guarded).toBe(false);
    expect(find(g, 'GET', '/me')!.guarded).toBe(true);
    expect(find(g, 'GET', '/x')!.guarded).toBe(true);
  });

  it('an anonymous alternative ({}) means the route is not guarded; a per-operation list beats an empty global one', async () => {
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': doc([], { '/opt': [{}, { bearerAuth: [] }], '/req': bearer }) }));
    expect(find(g, 'GET', '/opt')!.guarded).toBe(false);
    expect(find(g, 'GET', '/req')!.guarded).toBe(true);
  });

  it('YAML: global, per-operation and empty security', async () => {
    const y = `openapi: 3.0.0
security:
  - apiKey: []
paths:
  /a:
    get:
      summary: inherits
  /b:
    get:
      security: []
  /c:
    get:
      security:
        - oauth: [read]
  /d:
    get:
      security: [{token: []}]
  /e:
    get:
      security: []
`;
    const g = await CodeParser.analyze(writeProject({ 'openapi.yaml': y }));
    const guarded = Object.fromEntries(g.routes.map((r) => [r.path, r.guarded]));
    expect(guarded).toEqual({ '/a': true, '/b': false, '/c': true, '/d': true, '/e': false });
  });

  it('YAML flow security it cannot interpret skips the file instead of guessing', async () => {
    const y = 'openapi: 3.0.0\npaths:\n  /a:\n    get:\n      security: [some, thing]\n';
    const g = await CodeParser.analyze(writeProject({ 'openapi.yaml': y }));
    expect(g.routes).toEqual([]);
    expect(g.discoveryNotes![0]).toMatch(/security/);
  });
});

describe('which files are read', () => {
  it('ignores specs under node_modules and in .gitignore d paths', async () => {
    const dir = writeProject({
      '.gitignore': 'node_modules\ngenerated/\n',
      'node_modules/pkg/openapi.json': spec({ openapi: '3.0.0', paths: { '/from-node-modules': { get: {} } } }),
      'generated/openapi.json': spec({ openapi: '3.0.0', paths: { '/from-ignored': { get: {} } } }),
      'api/swagger.yaml': 'swagger: "2.0"\npaths:\n  /real:\n    get: {}\n',
    });
    const g = await CodeParser.analyze(dir);
    expect(brief(g)).toEqual(['GET /real']);
    expect(g.gitignoreSkipped).toBeGreaterThanOrEqual(1);
  });

  it('skips a file over 2 MB with a visible info line', async () => {
    const big = spec({ openapi: '3.0.0', paths: { '/big': { get: {} } }, 'x-pad': 'a'.repeat(2 * 1024 * 1024 + 10) });
    const g = await CodeParser.analyze(writeProject({ 'openapi.json': big, 'swagger.yaml': 'swagger: "2.0"\npaths:\n  /small:\n    get: {}\n' }));
    expect(brief(g)).toEqual(['GET /small']);
    expect(g.discoveryNotes).toHaveLength(1);
    expect(g.discoveryNotes![0]).toMatch(/openapi\.json not used: larger than 2 MB/);
  });

  it('reads at most 5 files (shallowest first) and says so', async () => {
    const files: Record<string, string> = {};
    for (let n = 1; n <= 7; n++) files[`d${n}/openapi.json`] = spec({ openapi: '3.0.0', paths: { [`/p${n}`]: { get: {} } } });
    files['openapi.json'] = spec({ openapi: '3.0.0', paths: { '/root': { get: {} } } });
    const g = await CodeParser.analyze(writeProject(files));
    expect(g.specFiles).toHaveLength(5);
    expect(g.specFiles![0]).toBe('openapi.json');
    expect(brief(g)).toHaveLength(5);
    expect(g.discoveryNotes!.join('\n')).toMatch(/Found 8 OpenAPI\/Swagger files; reading the first 5/);
  });

  it('the same operation in two spec files appears once, with both as evidence', async () => {
    const g = await CodeParser.analyze(
      writeProject({
        'openapi.json': spec({ openapi: '3.0.0', paths: { '/same': { get: {} } } }),
        'v2/swagger.json': spec({ swagger: '2.0', paths: { '/same': { get: {} } } }),
      }),
    );
    expect(g.routes).toHaveLength(1);
    expect(g.routes[0]!.file).toBe('openapi.json');
    expect(g.routes[0]!.specFiles).toEqual(['v2/swagger.json']);
  });

  it('spec files are not handed to the source scanners', async () => {
    const { FileWalker } = await import('../src/utils/FileWalker');
    const dir = writeProject({ 'openapi.json': spec(JSON_SPEC) });
    expect((await FileWalker.walk(dir)).map((f) => f.relPath)).not.toContain('openapi.json');
  });
});

describe('deduplication against code routes', () => {
  it('keeps the code route and adds the spec as extra evidence; spec-only routes are added', async () => {
    const dir = expressProject(
      ['app.get("/items", (req, res) => res.send("ok"));', 'app.get("/users/:id", (req, res) => res.send("ok"));'],
      {
        'openapi.yaml': [
          'openapi: 3.0.0',
          'security:',
          '  - bearerAuth: []',
          'paths:',
          '  /items:',
          '    get: {}',
          '    post: {}',
          '  /users/{userId}:',
          '    get: {}',
          '  /spec-only:',
          '    get: {}',
          '',
        ].join('\n'),
      },
    );
    const g = await CodeParser.analyze(dir);
    expect(brief(g)).toEqual(['GET /items', 'GET /spec-only', 'GET /users/:id', 'POST /items']);

    const items = find(g, 'GET', '/items')!;
    expect(items.file).toBe('server.js');
    expect(items.source).toBeUndefined();
    expect(items.guarded).toBe(false);
    expect(items.specFiles).toEqual(['openapi.yaml']);

    expect(find(g, 'GET', '/users/:id')!.specFiles).toEqual(['openapi.yaml']);
    expect(find(g, 'GET', '/spec-only')!.source).toBe('openapi');
    expect(find(g, 'POST', '/items')!.source).toBe('openapi');

    const why = EndpointMapper.plan(g.routes).targets.find((t) => t.path === '/items')!.why;
    expect(why[0]).toMatch(/^discovered at server\.js/);
    expect(why).toContain('also declared in openapi.yaml');
  });
});

describe('a project with a spec and no parser adapter', () => {
  it('still gets its routes from the spec (any stack)', async () => {
    const dir = writeProject({
      'openapi.yaml': 'openapi: 3.0.0\nservers:\n  - url: /api\npaths:\n  /health:\n    get: {}\n  /admin/stats:\n    get:\n      security:\n        - bearer: []\n',
      'main.go': 'package main\nfunc main() {}\n',
      'README.md': '# go service\n',
    });
    const g = await CodeParser.analyze(dir);
    expect(g.fileCount).toBe(0);
    expect(g.stack.stack).toBe('unknown');
    expect(brief(g)).toEqual(['GET /api/admin/stats', 'GET /api/health']);
    expect(find(g, 'GET', '/api/admin/stats')!.guarded).toBe(true);
    expect(find(g, 'GET', '/api/health')!.guarded).toBe(false);
  });
});
