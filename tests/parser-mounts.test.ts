/**
 * Mount/prefix styles and Express route styles.
 * Each style has a positive test and a negative one: when the prefix or path is
 * not a string literal or same-file constant the route is skipped, never guessed.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import { BabelAdapter } from '../src/parser/adapters/BabelAdapter';
import { PythonAdapter } from '../src/parser/adapters/PythonAdapter';

async function routesOf(files: Record<string, string>): Promise<string[]> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-mounts-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    const graph = await CodeParser.analyze(dir);
    return graph.routes.map((r) => `${r.method} ${r.path}`).sort();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const babel = new BabelAdapter();
const python = new PythonAdapter();
const jsRoutes = (src: string) =>
  babel
    .parse('app.js', src)
    .routes.map((r) => `${r.method} ${r.path}`)
    .sort();
const pyRoutes = (src: string) =>
  python
    .parse('app.py', src)
    .routes.map((r) => `${r.method} ${r.path}`)
    .sort();

const EXPRESS_ROUTER = `const express = require('express');
const router = express.Router();
router.get('/items', (req, res) => res.json([]));
module.exports = router;
`;

describe('Fastify register(plugin, { prefix })', () => {
  const plugin = `module.exports = async function (fastify) {
  fastify.get('/items', async () => []);
};
`;

  it('applies a literal prefix', async () => {
    const out = await routesOf({
      'server.js': `const fastify = require('fastify')();
fastify.register(require('./items'), { prefix: '/api' });
`,
      'items.js': plugin,
    });
    expect(out).toEqual(['GET /api/items']);
  });

  it('applies a same-file constant prefix', async () => {
    const out = await routesOf({
      'server.js': `const fastify = require('fastify')();
const PREFIX = '/api';
fastify.register(require('./items'), { prefix: PREFIX });
`,
      'items.js': plugin,
    });
    expect(out).toEqual(['GET /api/items']);
  });

  it('skips the plugin routes when the prefix is not a literal', async () => {
    const out = await routesOf({
      'server.js': `const fastify = require('fastify')();
fastify.register(require('./items'), { prefix: process.env.API_PREFIX });
`,
      'items.js': plugin,
    });
    expect(out).toEqual([]);
  });

  it('adds up nested register prefixes across files', async () => {
    const out = await routesOf({
      'server.js': `const fastify = require('fastify')();
fastify.register(require('./v1'), { prefix: '/v1' });
`,
      'v1.js': `module.exports = async function (fastify) {
  fastify.register(require('./items'), { prefix: '/items' });
};
`,
      'items.js': `module.exports = async function (fastify) {
  fastify.get('/', async () => []);
};
`,
    });
    expect(out).toEqual(['GET /v1/items']);
  });

  it('skips only the branch below a non-literal nested prefix', async () => {
    const out = await routesOf({
      'server.js': `const fastify = require('fastify')();
fastify.register(require('./v1'), { prefix: '/v1' });
`,
      'v1.js': `module.exports = async function (fastify) {
  fastify.get('/ping', async () => 'pong');
  fastify.register(require('./items'), { prefix: fastify.prefixFor('items') });
};
`,
      'items.js': plugin,
    });
    expect(out).toEqual(['GET /v1/ping']);
  });

  it('applies the prefix to an inline plugin function', () => {
    const out = jsRoutes(`const fastify = require('fastify')();
fastify.register(async function (app) {
  app.get('/items', async () => []);
}, { prefix: '/api' });
`);
    expect(out).toEqual(['GET /api/items']);
  });

  it('skips an inline plugin function with a non-literal prefix', () => {
    const out = jsRoutes(`const fastify = require('fastify')();
fastify.register(async function (app) {
  app.get('/items', async () => []);
}, { prefix: getPrefix() });
`);
    expect(out).toEqual([]);
  });

  it('does not use a shadowed constant as a prefix', () => {
    const out = jsRoutes(`const fastify = require('fastify')();
const P = '/outer';
function setup() {
  const P = computeIt();
  fastify.register(async function (app) {
    app.get('/items', async () => []);
  }, { prefix: P });
}
`);
    expect(out).toEqual([]);
  });
});

describe('Koa new Router({ prefix })', () => {
  it('applies a literal prefix', () => {
    const out = jsRoutes(`const Router = require('@koa/router');
const router = new Router({ prefix: '/v1' });
router.get('/ping', (ctx) => { ctx.body = 'pong'; });
`);
    expect(out).toEqual(['GET /v1/ping']);
  });

  it('applies a same-file constant prefix', () => {
    const out = jsRoutes(`const Router = require('koa-router');
const BASE = '/v2';
const router = new Router({ prefix: BASE });
router.get('/ping', (ctx) => { ctx.body = 'pong'; });
`);
    expect(out).toEqual(['GET /v2/ping']);
  });

  it('skips routes when the prefix is not a literal', () => {
    const out = jsRoutes(`const Router = require('@koa/router');
const config = require('./config');
const router = new Router({ prefix: config.prefix });
router.get('/ping', (ctx) => { ctx.body = 'pong'; });
`);
    expect(out).toEqual([]);
  });

  it('skips routes of a router whose prefix is changed with .prefix()', () => {
    const out = jsRoutes(`const Router = require('@koa/router');
const router = new Router();
router.prefix(process.env.BASE);
router.get('/ping', (ctx) => { ctx.body = 'pong'; });
`);
    expect(out).toEqual([]);
  });

  it('keeps an unprefixed router as written', () => {
    const out = jsRoutes(`const Router = require('@koa/router');
const router = new Router();
router.get('/ping', (ctx) => { ctx.body = 'pong'; });
`);
    expect(out).toEqual(['GET /ping']);
  });
});

describe('Flask register_blueprint / Blueprint url_prefix', () => {
  const bp = (prefix = '') => `from flask import Blueprint, jsonify

items_bp = Blueprint("items", __name__${prefix})


@items_bp.route("/items")
def list_items():
    return jsonify([])
`;

  it('applies the registration url_prefix across files', async () => {
    const out = await routesOf({
      'app.py': `from flask import Flask
from items import items_bp

app = Flask(__name__)
app.register_blueprint(items_bp, url_prefix="/api")
`,
      'items.py': bp(),
    });
    expect(out).toEqual(['ALL /api/items']);
  });

  it('applies the Blueprint(..., url_prefix=) of an unreplaced blueprint', async () => {
    const out = await routesOf({
      'app.py': `from flask import Flask
from items import items_bp

app = Flask(__name__)
app.register_blueprint(items_bp)
`,
      'items.py': bp(', url_prefix="/own"'),
    });
    expect(out).toEqual(['ALL /own/items']);
  });

  it('lets the registration url_prefix replace the blueprint url_prefix', async () => {
    const out = await routesOf({
      'app.py': `from flask import Flask
from items import items_bp

app = Flask(__name__)
app.register_blueprint(items_bp, url_prefix="/api")
`,
      'items.py': bp(', url_prefix="/own"'),
    });
    expect(out).toEqual([]);
  });

  it('skips the blueprint routes when the url_prefix is not a literal', async () => {
    const out = await routesOf({
      'app.py': `from flask import Flask
from config import settings
from items import items_bp

app = Flask(__name__)
app.register_blueprint(items_bp, url_prefix=settings.PREFIX)
`,
      'items.py': bp(),
    });
    expect(out).toEqual([]);
  });

  it('skips the routes of a blueprint with an f-string url_prefix', () => {
    const out = pyRoutes(`from flask import Blueprint
bp = Blueprint("x", __name__, url_prefix=f"/{VERSION}")

@bp.route("/items")
def items():
    return ""
`);
    expect(out).toEqual([]);
  });

  it('adds up nested blueprint registrations in one file', () => {
    const out = pyRoutes(`from flask import Blueprint, Flask
app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")
items = Blueprint("items", __name__)

@items.route("/")
def list_items():
    return ""

api.register_blueprint(items, url_prefix="/items")
app.register_blueprint(api)
`);
    expect(out).toEqual(['ALL /api/items']);
  });

  it('resolves a same-file constant url_prefix, also across lines', () => {
    const out = pyRoutes(`from flask import Blueprint, Flask
PREFIX = "/api"
app = Flask(__name__)
bp = Blueprint("b", __name__)

@bp.route("/items")
def items():
    return ""

app.register_blueprint(
    bp,
    url_prefix=PREFIX,
)
`);
    expect(out).toEqual(['ALL /api/items']);
  });

  it('skips nested blueprint routes when the outer prefix is dynamic', () => {
    const out = pyRoutes(`from flask import Blueprint, Flask
app = Flask(__name__)
api = Blueprint("api", __name__)
items = Blueprint("items", __name__)

@items.route("/")
def list_items():
    return ""

api.register_blueprint(items, url_prefix="/items")
app.register_blueprint(api, url_prefix=os.environ["P"])
`);
    expect(out).toEqual([]);
  });
});

describe('FastAPI APIRouter(prefix) / include_router(prefix)', () => {
  const items = (own = '') => `from fastapi import APIRouter

router = APIRouter(${own})


@router.get("/items")
def list_items():
    return []
`;

  it('applies the include_router prefix across files', async () => {
    const out = await routesOf({
      'main.py': `from fastapi import FastAPI
from items import router

app = FastAPI()
app.include_router(router, prefix="/api")
`,
      'items.py': items(),
    });
    expect(out).toEqual(['GET /api/items']);
  });

  it('applies APIRouter(prefix=) on top of the include_router prefix', async () => {
    const out = await routesOf({
      'main.py': `from fastapi import FastAPI
from items import router

app = FastAPI()
app.include_router(router, prefix="/api")
`,
      'items.py': items('prefix="/v1"'),
    });
    expect(out).toEqual(['GET /api/v1/items']);
  });

  it('skips the routes when the include_router prefix is not a literal', async () => {
    const out = await routesOf({
      'main.py': `from fastapi import FastAPI
from config import settings
from items import router

app = FastAPI()
app.include_router(router, prefix=settings.API_PREFIX)
`,
      'items.py': items(),
    });
    expect(out).toEqual([]);
  });

  it('skips the routes of an APIRouter whose prefix is dynamic', () => {
    const out = pyRoutes(`from fastapi import APIRouter
router = APIRouter(prefix=settings.PREFIX)

@router.get("/items")
def list_items():
    return []
`);
    expect(out).toEqual([]);
  });

  it('applies APIRouter(prefix=) in the same file', () => {
    const out = pyRoutes(`from fastapi import APIRouter
router = APIRouter(prefix="/items", tags=["items"])

@router.get("/")
def list_items():
    return []
`);
    expect(out).toEqual(['GET /items']);
  });

  it('adds up nested routers across three files', async () => {
    const out = await routesOf({
      'main.py': `from fastapi import FastAPI
from routers import api

app = FastAPI()
app.include_router(api.router, prefix="/api")
`,
      'routers/__init__.py': '',
      'routers/api.py': `from fastapi import APIRouter
from routers import items

router = APIRouter(prefix="/v1")
router.include_router(items.router)
`,
      'routers/items.py': `from fastapi import APIRouter

router = APIRouter(prefix="/items")


@router.get("/")
def list_items():
    return []
`,
    });
    expect(out).toEqual(['GET /api/v1/items']);
  });

  it('skips a nested router below a dynamic include_router prefix', async () => {
    const out = await routesOf({
      'main.py': `from fastapi import FastAPI
from routers import api

app = FastAPI()
app.include_router(api.router, prefix=settings.PREFIX)
`,
      'routers/__init__.py': '',
      'routers/api.py': `from fastapi import APIRouter
from routers import items

router = APIRouter(prefix="/v1")
router.include_router(items.router)
`,
      'routers/items.py': `from fastapi import APIRouter

router = APIRouter(prefix="/items")


@router.get("/")
def list_items():
    return []
`,
    });
    expect(out).toEqual([]);
  });
});

describe('Hono app.route(path, sub)', () => {
  it('applies a literal mount path across files', async () => {
    const out = await routesOf({
      'app.js': `import { Hono } from 'hono';
import items from './items.js';
const app = new Hono();
app.route('/api', items);
export default app;
`,
      'items.js': `import { Hono } from 'hono';
const items = new Hono();
items.get('/items', (c) => c.json([]));
export default items;
`,
    });
    expect(out).toEqual(['GET /api/items']);
  });

  it('nests same-file sub-apps and basePath()', () => {
    const out = jsRoutes(`import { Hono } from 'hono';
const app = new Hono();
const v1 = new Hono().basePath('/v1');
const reports = new Hono();
reports.get('/daily', (c) => c.json({}));
v1.route('/reports', reports);
app.route('/api', v1);
`);
    expect(out).toEqual(['GET /api/v1/reports/daily']);
  });

  it('skips the sub-app routes when the mount path is not a literal', async () => {
    const out = await routesOf({
      'app.js': `import { Hono } from 'hono';
import items from './items.js';
import { BASE } from './config.js';
const app = new Hono();
app.route(BASE, items);
export default app;
`,
      'items.js': `import { Hono } from 'hono';
const items = new Hono();
items.get('/items', (c) => c.json([]));
export default items;
`,
    });
    expect(out).toEqual([]);
  });
});

describe('Express app.use(CONST, router)', () => {
  it('applies a same-file constant prefix', async () => {
    const out = await routesOf({
      'app.js': `const express = require('express');
const items = require('./items');
const app = express();
const API = '/api';
app.use(API, items);
`,
      'items.js': EXPRESS_ROUTER,
    });
    expect(out).toEqual(['GET /api/items']);
  });

  it('applies a template literal prefix with a same-file constant', async () => {
    const out = await routesOf({
      'app.js': `const express = require('express');
const items = require('./items');
const app = express();
const VERSION = 'v1';
app.use(\`/api/\${VERSION}\`, items);
`,
      'items.js': EXPRESS_ROUTER,
    });
    expect(out).toEqual(['GET /api/v1/items']);
  });

  it('skips the router routes when the prefix is not a literal', async () => {
    const out = await routesOf({
      'app.js': `const express = require('express');
const items = require('./items');
const app = express();
app.use(process.env.API_PREFIX, items);
`,
      'items.js': EXPRESS_ROUTER,
    });
    expect(out).toEqual([]);
  });

  it('skips the router routes when the prefix constant is reassigned', async () => {
    const out = await routesOf({
      'app.js': `const express = require('express');
const items = require('./items');
const app = express();
let API = '/api';
API = loadPrefix();
app.use(API, items);
`,
      'items.js': EXPRESS_ROUTER,
    });
    expect(out).toEqual([]);
  });

  it('still treats app.use(middleware, router) as an unprefixed mount', async () => {
    const out = await routesOf({
      'app.js': `const express = require('express');
const items = require('./items');
const app = express();
function logger(req, res, next) { next(); }
app.use(logger, items);
`,
      'items.js': EXPRESS_ROUTER,
    });
    expect(out).toEqual(['GET /items']);
  });

  it('adds up nested same-file router mounts', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
const outer = express.Router();
const inner = express.Router();
inner.get('/ping', (req, res) => res.end());
outer.use('/inner', inner);
app.use('/outer', outer);
`);
    expect(out).toEqual(['GET /outer/inner/ping']);
  });

  it('applies a path array as one mount per prefix', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
const r = express.Router();
r.get('/x', (req, res) => res.end());
app.use(['/a', '/b'], r);
`);
    expect(out).toEqual(['GET /a/x', 'GET /b/x']);
  });
});

describe('Express route styles', () => {
  it('reads app.route(path).get().post() chains', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
app.route('/books')
  .get((req, res) => res.json([]))
  .post((req, res) => res.status(201).end());
`);
    expect(out).toEqual(['GET /books', 'POST /books']);
  });

  it('skips a route chain with a non-literal path', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
app.route(getBase())
  .get((req, res) => res.json([]))
  .post((req, res) => res.status(201).end());
`);
    expect(out).toEqual([]);
  });

  it('reads router.route(path) chains', () => {
    const out = jsRoutes(`const express = require('express');
const router = express.Router();
router.route('/books/:id').get((req, res) => res.end()).delete((req, res) => res.end());
module.exports = router;
`);
    expect(out).toEqual(['DELETE /books/:id', 'GET /books/:id']);
  });

  it('skips router.route(path) with an imported path', () => {
    const out = jsRoutes(`const express = require('express');
const { BOOKS } = require('./paths');
const router = express.Router();
router.route(BOOKS).get((req, res) => res.end());
`);
    expect(out).toEqual([]);
  });

  it('resolves same-file constant paths, also in chains', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
const USERS = '/users';
const BOOKS = '/books';
app.get(USERS, (req, res) => res.json([]));
app.route(BOOKS).post((req, res) => res.end());
`);
    expect(out).toEqual(['GET /users', 'POST /books']);
  });

  it('skips imported or call-built paths', () => {
    const out = jsRoutes(`const express = require('express');
const { USERS } = require('./paths');
const app = express();
app.get(USERS, (req, res) => res.json([]));
app.get(buildPath('health'), (req, res) => res.json({}));
`);
    expect(out).toEqual([]);
  });

  it('reads a plain template literal path', () => {
    const out = jsRoutes('const express = require("express");\nconst app = express();\napp.get(`/health`, (req, res) => res.end());\n');
    expect(out).toEqual(['GET /health']);
  });

  it('interpolates a same-file constant in a template literal path', () => {
    const out = jsRoutes(
      'const express = require("express");\nconst app = express();\nconst V = "v1";\napp.get(`/api/${V}/status`, (req, res) => res.end());\n',
    );
    expect(out).toEqual(['GET /api/v1/status']);
  });

  it('skips a template literal with an unresolvable interpolation', () => {
    const out = jsRoutes(
      'const express = require("express");\nconst app = express();\napp.get(`${process.env.BASE}/status`, (req, res) => res.end());\n',
    );
    expect(out).toEqual([]);
  });

  it('reads a path array as one route per entry', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
app.get(['/a', '/b'], (req, res) => res.end());
`);
    expect(out).toEqual(['GET /a', 'GET /b']);
  });

  it('keeps only the literal entries of a path array that has a non-literal entry', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
app.get(['/a', dynamicPath()], (req, res) => res.end());
`);
    expect(out).toEqual(['GET /a']);
  });

  it('does not turn map.get(KEY) into a route', () => {
    const out = jsRoutes(`const express = require('express');
const app = express();
const cache = new Map();
const v = cache.get(KEY);
app.get('/ok', (req, res) => res.end());
`);
    expect(out).toEqual(['GET /ok']);
  });
});
