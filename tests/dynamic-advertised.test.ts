import { DynamicTester } from '../src/dynamic/DynamicTester';
import {
  MAX_ADVERTISED,
  advertisedSkipReason,
  extractHrefs,
  linkHeaderTargets,
  toLocalPath,
} from '../src/dynamic/advertised';
import type { Route } from '../src/types';
import { CONTROL_PATH, send, withApp, writeProject, type Handler } from './helpers/dummyApp';

const route = (path: string, method = 'GET'): Route => ({ method, path, file: 'src/app.js', line: 1, guarded: false });
const page = (links: string): string => `<!doctype html><html><head><title>t</title></head><body>${links}</body></html>`;

/** Serves `pages` (path -> html); everything else is a plain 404. */
const site =
  (pages: Record<string, string | { body: string; type?: string; headers?: Record<string, string> }>): Handler =>
  (req, res) => {
    const p = (req.url ?? '/').split('?')[0] ?? '/';
    const hit = pages[p];
    if (hit === undefined) return send(res, 404, 'not found', 'text/plain');
    if (typeof hit === 'string') return send(res, 200, hit);
    send(res, 200, hit.body, hit.type ?? 'text/html', hit.headers ?? {});
  };

const uniquePaths = (paths: string[]): string[] => [...new Set(paths.filter((p) => !CONTROL_PATH.test(p)))];

describe('advertised links: pages the app serves point at more routes', () => {
  it('a same-origin <a> and <link> is requested and listed with its why-line, once in the probed list', async () => {
    await withApp(
      site({
        '/': page('<a href="/about">About</a> <a href="/about">again</a> <link rel="alternate" href="/feed"><a href=\'/pricing\'>p</a>'),
        '/about': '<h1>About</h1>',
        '/feed': { body: '<rss></rss>', type: 'application/rss+xml' },
        '/pricing': '<h1>Pricing</h1>',
      }),
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(r.probed.map((p) => p.path)).toEqual(['/', '/about', '/feed', '/pricing']);
        expect(r.probed.find((p) => p.path === '/about')!.why).toEqual(['advertised by GET / (link)']);
        expect(r.probed[0]!.why).toEqual(['discovered at src/app.js:1', 'unguarded in code']);
        expect(uniquePaths(app.paths())).toEqual(['/', '/about', '/feed', '/pricing']);
        // Same request budget as a discovered route: security, performance and API checks.
        const count = (p: string): number => app.paths().filter((x) => x === p).length;
        expect(count('/about')).toBe(count('/'));
        expect(count('/about')).toBeLessThanOrEqual(3);
        expect(r.endpoints.map((e) => e.path)).toContain('/about');
      },
    );
  });

  it('an absolute link to the exact base URL is the same origin', async () => {
    await withApp(
      (req, res) => {
        const base = `http://${req.headers.host}`;
        send(res, req.url === '/' ? 200 : 404, req.url === '/' ? page(`<a href="${base}/abs">x</a>`) : 'nope');
      },
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(r.probed.map((p) => p.path)).toEqual(['/', '/abs']);
      },
    );
  });

  it('never requests other hosts, mailto/javascript/#, form actions, assets, state-changing or query links', async () => {
    const links = [
      '<a href="http://example.test/elsewhere">x</a>',
      '<a href="https://127.0.0.1:9/other-port">x</a>',
      '<a href="//example.test/protocol-relative">x</a>',
      '<a href="mailto:ops@example.test">x</a>',
      '<a href="javascript:void(0)">x</a>',
      '<a href="#section">x</a>',
      '<form method="get" action="/form-action"><input name="q"></form>',
      '<a href="/logout">x</a>',
      '<a href="/sign-out">x</a>',
      '<a href="/signout">x</a>',
      '<a href="/account/delete">x</a>',
      '<a href="/items/remove-all">x</a>',
      '<a href="/destroy_session">x</a>',
      '<a href="/unsubscribe">x</a>',
      '<a href="/tokens/revoke">x</a>',
      '<a href="/password/reset">x</a>',
      '<a href="/order/cancel">x</a>',
      '<a href="/deleteAccount">x</a>',
      '<link rel="stylesheet" href="/site.css">',
      '<link rel="icon" href="/favicon.ico">',
      '<a href="/report.pdf">x</a>',
      '<a href="/app.map">x</a>',
      '<a href="/search?q=1">x</a>',
      '<a href="/users/:id">x</a>',
      '<a href="/keep-me">ok</a>',
    ].join('\n');
    await withApp(site({ '/': page(links), '/keep-me': 'ok' }), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, [route('/')]);
      expect(uniquePaths(app.paths())).toEqual(['/', '/keep-me']);
      expect(r.probed.map((p) => p.path)).toEqual(['/', '/keep-me']);
    });
  });

  it('keeps words that merely contain a state-changing word (whole words only)', async () => {
    await withApp(
      site({ '/': page('<a href="/undeleted-items">a</a><a href="/removal-policy">b</a><a href="/cancellation">c</a>') }),
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(uniquePaths(app.paths())).toEqual(['/', '/undeleted-items', '/removal-policy', '/cancellation']);
      },
    );
  });

  it('requests at most 25 new paths; the rest are not requested', async () => {
    const links = Array.from({ length: 40 }, (_, i) => `<a href="/p${i}">p</a>`).join('');
    await withApp(site({ '/': page(links) }), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, [route('/')]);
      expect(MAX_ADVERTISED).toBe(25);
      const advertised = r.probed.filter((p) => p.why[0]!.startsWith('advertised'));
      expect(advertised).toHaveLength(25);
      expect(advertised.map((p) => p.path)).toEqual(Array.from({ length: 25 }, (_, i) => `/p${i}`));
      const requested = uniquePaths(app.paths());
      expect(requested).toHaveLength(26);
      expect(requested).not.toContain('/p25');
      expect(requested).not.toContain('/p39');
    });
  });

  it('depth 1: a link on an advertised page is not followed', async () => {
    await withApp(
      site({ '/': page('<a href="/a">a</a>'), '/a': page('<a href="/b">b</a>'), '/b': page('<a href="/c">c</a>') }),
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(uniquePaths(app.paths())).toEqual(['/', '/a']);
        expect(r.probed.map((p) => p.path)).toEqual(['/', '/a']);
      },
    );
  });

  it('only 2xx pages are read for links', async () => {
    await withApp(
      (req, res) =>
        req.url === '/' ? send(res, 404, page('<a href="/from-404">x</a>')) : send(res, 404, 'nope', 'text/plain'),
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(uniquePaths(app.paths())).toEqual(['/']);
      },
    );
  });

  it('a JSON response is not scanned for links', async () => {
    await withApp(
      site({ '/api': { body: '{"html":"<a href=\\"/hidden\\">x</a>"}', type: 'application/json' } }),
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/api')]);
        expect(uniquePaths(app.paths())).toEqual(['/api']);
      },
    );
  });

  it('an advertised admin-looking path goes through the same checks, with the lazy catch-all control', async () => {
    await withApp(
      site({ '/': page('<a href="/admin">Admin</a>'), '/admin': '<h1>Admin dashboard</h1>' }),
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')]);
        const f = r.findings.find((x) => x.rule === 'exposed-admin-route');
        expect(f?.endpoint).toBe('/admin');
        expect(r.probed.find((p) => p.path === '/admin')!.why[0]).toBe('advertised by GET / (link)');
        expect(app.paths().filter((p) => CONTROL_PATH.test(p))).toHaveLength(1);
      },
    );
    await withApp(
      (_req, res) => send(res, 200, page('<a href="/admin">Admin</a>')),
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(r.findings.find((x) => x.rule === 'exposed-admin-route')).toBeUndefined();
      },
    );
  });
});

describe('advertised links: robots.txt and sitemap.xml only when they are evidence', () => {
  const SITEMAP = (base: string, paths: string[]): string =>
    `<?xml version="1.0"?><urlset>${paths.map((p) => `<url><loc>${base}${p}</loc></url>`).join('')}</urlset>`;

  it.each(['public', 'static', 'www', 'dist', ''])('robots.txt in %p/ is read and its Sitemap line used', async (dir) => {
    const project = writeProject({ [`${dir ? `${dir}/` : ''}robots.txt`]: 'User-agent: *\nDisallow:\n' });
    await withApp(
      (req, res) => {
        const base = `http://${req.headers.host}`;
        const p = req.url ?? '/';
        if (p === '/') return send(res, 200, page('home'));
        if (p === '/robots.txt') return send(res, 200, `User-agent: *\nSitemap: ${base}/map.xml\n`, 'text/plain');
        if (p === '/map.xml') return send(res, 200, SITEMAP(base, ['/docs', '/team']), 'application/xml');
        if (p === '/docs' || p === '/team') return send(res, 200, `<h1>${p}</h1>`);
        send(res, 404, 'nope', 'text/plain');
      },
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')], { projectPath: project });
        expect(uniquePaths(app.paths())).toEqual(['/', '/robots.txt', '/map.xml', '/docs', '/team']);
        const why = (p: string): string[] => r.probed.find((x) => x.path === p)!.why;
        expect(why('/robots.txt')[0]).toMatch(/^robots\.txt exists in the project \(/);
        expect(why('/map.xml')).toEqual(['advertised by GET /robots.txt (Sitemap line)']);
        expect(why('/docs')).toEqual(['advertised by GET /map.xml (sitemap entry)']);
      },
    );
  });

  it('sitemap.xml in public/ is read and its <loc> entries used (no robots.txt anywhere)', async () => {
    const project = writeProject({ 'public/sitemap.xml': '<urlset/>' });
    await withApp(
      (req, res) => {
        const base = `http://${req.headers.host}`;
        const p = req.url ?? '/';
        if (p === '/') return send(res, 200, page('home'));
        if (p === '/sitemap.xml') {
          return send(res, 200, `${SITEMAP(base, ['/docs'])}`.replace('</urlset>', `<url><loc>http://example.test/prod-only</loc></url></urlset>`), 'application/xml');
        }
        if (p === '/docs') return send(res, 200, '<h1>docs</h1>');
        send(res, 404, 'nope', 'text/plain');
      },
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/')], { projectPath: project });
        expect(uniquePaths(app.paths())).toEqual(['/', '/sitemap.xml', '/docs']);
      },
    );
  });

  it('robots.txt absent from the project: never requested, however many pages exist (and sitemap.xml neither)', async () => {
    const project = writeProject({ 'public/index.html': '<h1>x</h1>', 'package.json': '{}' });
    await withApp(
      (req, res) => {
        const p = req.url ?? '/';
        if (p === '/robots.txt') return send(res, 200, `Sitemap: http://${req.headers.host}/sitemap.xml\n`, 'text/plain');
        if (p === '/sitemap.xml') return send(res, 200, '<urlset><url><loc>/x</loc></url></urlset>', 'application/xml');
        send(res, p === '/' ? 200 : 404, p === '/' ? page('<a href="/a">a</a>') : 'nope', 'text/html');
      },
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/'), route('/other')], { projectPath: project });
        expect(app.paths()).not.toContain('/robots.txt');
        expect(app.paths()).not.toContain('/sitemap.xml');
        expect(uniquePaths(app.paths())).toEqual(['/', '/other', '/a']);
      },
    );
  });

  it('without a projectPath at all, robots.txt and sitemap.xml are never requested', async () => {
    await withApp(site({ '/': page('x') }), async (app) => {
      await DynamicTester.run(app.baseUrl, [route('/')]);
      expect(uniquePaths(app.paths())).toEqual(['/']);
    });
  });

  it('a discovered /robots.txt route is evidence: its Sitemap line is used', async () => {
    await withApp(
      (req, res) => {
        const p = req.url ?? '/';
        if (p === '/robots.txt') return send(res, 200, `Sitemap: http://${req.headers.host}/pages.xml\n`, 'text/plain');
        if (p === '/pages.xml') return send(res, 200, `<urlset><url><loc>http://${req.headers.host}/guide</loc></url></urlset>`, 'application/xml');
        send(res, p === '/guide' ? 200 : 404, 'x', 'text/html');
      },
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/robots.txt')]);
        expect(uniquePaths(app.paths())).toEqual(['/robots.txt', '/pages.xml', '/guide']);
      },
    );
  });

  it('a page that links to /robots.txt makes it evidence', async () => {
    await withApp(
      (req, res) => {
        const p = req.url ?? '/';
        if (p === '/') return send(res, 200, page('<a href="/robots.txt">robots</a>'));
        if (p === '/robots.txt') return send(res, 200, `Sitemap: http://${req.headers.host}/pages.xml\n`, 'text/plain');
        if (p === '/pages.xml') return send(res, 200, `<urlset><url><loc>http://${req.headers.host}/guide</loc></url></urlset>`, 'application/xml');
        send(res, p === '/guide' ? 200 : 404, 'x', 'text/html');
      },
      async (app) => {
        await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(uniquePaths(app.paths())).toEqual(['/', '/robots.txt', '/pages.xml', '/guide']);
      },
    );
  });

  it('a Link: rel=sitemap header on a fetched response advertises a sitemap whose <loc> entries are used', async () => {
    await withApp(
      (req, res) => {
        const p = req.url ?? '/';
        if (p === '/') return send(res, 200, page('x'), 'text/html', { Link: '</feeds/map.xml>; rel="sitemap"' });
        if (p === '/feeds/map.xml') return send(res, 200, `<urlset><url><loc>http://${req.headers.host}/blog</loc></url></urlset>`, 'application/xml');
        send(res, p === '/blog' ? 200 : 404, 'x', 'text/html');
      },
      async (app) => {
        const r = await DynamicTester.run(app.baseUrl, [route('/')]);
        expect(uniquePaths(app.paths())).toEqual(['/', '/feeds/map.xml', '/blog']);
        expect(r.probed.find((p) => p.path === '/feeds/map.xml')!.why).toEqual(['advertised by GET / (Link header rel=sitemap)']);
      },
    );
  });
});

describe('advertised links: an advertised OpenAPI/Swagger document contributes its paths', () => {
  const SPEC = JSON.stringify({
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/v1/items': { get: { responses: {} }, post: { responses: {} } },
      '/v1/items/{id}': { get: { responses: {} } },
      '/v1/secure': { get: { security: [{ key: [] }], responses: {} } },
      '/v1/logout': { get: { responses: {} } },
    },
  });

  const specApp = (linkOnHome: string, headers: Record<string, string> = {}): Handler =>
    site({
      '/': { body: page(linkOnHome), headers },
      '/docs/spec.json': { body: SPEC, type: 'application/json' },
      '/v1/items': { body: '{"items":[]}', type: 'application/json' },
      '/v1/secure': { body: '{"s":1}', type: 'application/json' },
    });

  it('spec URL advertised by a link: its GET paths are requested, parameterised/non-GET/state-changing ones are not', async () => {
    await withApp(specApp('<a href="/docs/spec.json">API</a>'), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, [route('/')]);
      expect(uniquePaths(app.paths())).toEqual(['/', '/docs/spec.json', '/v1/items', '/v1/secure']);
      expect(r.probed.find((p) => p.path === '/v1/items')!.why).toEqual([
        'advertised by GET /docs/spec.json (OpenAPI/Swagger paths)',
        'no auth required per the spec',
      ]);
      expect(r.probed.find((p) => p.path === '/v1/secure')!.why[1]).toBe('requires auth per the spec');
    });
  });

  it('spec URL advertised by a Link: rel="service-desc" header', async () => {
    await withApp(specApp('home', { Link: '</docs/spec.json>; rel="service-desc"; type="application/json"' }), async (app) => {
      await DynamicTester.run(app.baseUrl, [route('/')]);
      expect(uniquePaths(app.paths())).toEqual(['/', '/docs/spec.json', '/v1/items', '/v1/secure']);
    });
  });

  it('a spec served by a discovered route is read the same way', async () => {
    await withApp(specApp('home'), async (app) => {
      await DynamicTester.run(app.baseUrl, [route('/docs/spec.json')]);
      expect(uniquePaths(app.paths())).toEqual(['/docs/spec.json', '/v1/items', '/v1/secure']);
    });
  });

  it('JSON that merely has a paths key is not a spec', async () => {
    await withApp(site({ '/data': { body: '{"paths":{"/secret":{"get":{}}}}', type: 'application/json' } }), async (app) => {
      await DynamicTester.run(app.baseUrl, [route('/data')]);
      expect(uniquePaths(app.paths())).toEqual(['/data']);
    });
  });
});

describe('advertised links: nothing is requested without a page to read', () => {
  it('zero discovered routes: zero requests, even with robots.txt/sitemap.xml in the project', async () => {
    const project = writeProject({ 'public/robots.txt': 'Sitemap: /sitemap.xml\n', 'public/sitemap.xml': '<urlset/>' });
    await withApp(site({ '/': page('<a href="/a">a</a>'), '/robots.txt': 'x' }), async (app) => {
      const r = await DynamicTester.run(app.baseUrl, [], { aggressive: true, projectPath: project });
      expect(app.requests).toEqual([]);
      expect(r.probed).toEqual([]);
      expect(r.findings.map((f) => f.rule)).toContain('dynamic-skipped');
    });
  });

  it('only non-requestable routes (POST, path parameters): zero requests', async () => {
    const project = writeProject({ 'public/robots.txt': 'x' });
    await withApp(site({ '/': page('<a href="/a">a</a>') }), async (app) => {
      await DynamicTester.run(app.baseUrl, [route('/login', 'POST'), route('/users/:id')], { projectPath: project });
      expect(app.requests).toEqual([]);
    });
  });
});

describe('advertised links: parsing helpers', () => {
  it('toLocalPath keeps same-origin plain paths only', () => {
    const base = 'http://127.0.0.1:3000';
    expect(toLocalPath('/a/b', '/', base)).toBe('/a/b');
    expect(toLocalPath('c', '/a/b', base)).toBe('/a/c');
    expect(toLocalPath('../c', '/a/b/d', base)).toBe('/a/c');
    expect(toLocalPath('http://127.0.0.1:3000/x#frag', '/', base)).toBe('/x');
    expect(toLocalPath('http://127.0.0.1:3001/x', '/', base)).toBeNull();
    expect(toLocalPath('http://localhost:3000/x', '/', base)).toBeNull();
    expect(toLocalPath('//evil.test/x', '/', base)).toBeNull();
    expect(toLocalPath('mailto:a@b.test', '/', base)).toBeNull();
    expect(toLocalPath('tel:123', '/', base)).toBeNull();
    expect(toLocalPath('javascript:alert(1)', '/', base)).toBeNull();
    expect(toLocalPath('data:text/html,x', '/', base)).toBeNull();
    expect(toLocalPath('#top', '/', base)).toBeNull();
    expect(toLocalPath('/x?y=1', '/', base)).toBeNull();
    expect(toLocalPath('', '/', base)).toBeNull();
  });

  it('extractHrefs reads <a> and <link> hrefs in any quote style, and not forms or scripts', () => {
    const html = `<A HREF="/one">1</A><a class=x href='/two'>2</a><link rel=icon href=/three><form action="/four"></form><script src="/five.js"></script><a name="x">no href</a><a href="/s?a=1&amp;b=2">q</a>`;
    expect(extractHrefs(html)).toEqual(['/one', '/two', '/three', '/s?a=1&b=2']);
  });

  it('linkHeaderTargets keeps only sitemap, service-desc and describedby', () => {
    const h = '</a>; rel="next", </sm.xml>; rel="sitemap", </spec.json>; rel="service-desc"; type="application/json", </meta>; rel=describedby, </style.css>; rel="stylesheet preload"';
    expect(linkHeaderTargets(h)).toEqual([
      { url: '/sm.xml', rel: 'sitemap' },
      { url: '/spec.json', rel: 'service-desc' },
      { url: '/meta', rel: 'describedby' },
    ]);
    expect(linkHeaderTargets(undefined)).toEqual([]);
  });

  it('advertisedSkipReason', () => {
    for (const p of ['/logout', '/Logout', '/auth/sign-out', '/signout', '/log-out', '/a/delete', '/a/deleteAll', '/x/remove_item', '/destroy', '/unsubscribe', '/revoke', '/reset', '/cancel', '/a.js', '/a.CSS', '/b.png', '/b.jpeg', '/f.woff2', '/m.js.map', '/doc.pdf', '/z.zip', '/u/:id', '/w/*']) {
      expect(advertisedSkipReason(p)).not.toBeNull();
    }
    for (const p of ['/', '/about', '/docs/', '/api/v1/items', '/undeleted', '/resettlement', '/cancellation', '/sitemap.xml', '/robots.txt', '/feed.xml']) {
      expect(advertisedSkipReason(p)).toBeNull();
    }
  });
});
