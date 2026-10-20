/**
 * Next.js file routes, NestJS decorators, FastAPI/Flask guard evidence.
 * Every feature has a positive and a negative test. Guard evidence only ever turns a
 * route into a guarded one; unknown guards leave the route open.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import { BabelAdapter } from '../src/parser/adapters/BabelAdapter';
import { PythonAdapter } from '../src/parser/adapters/PythonAdapter';
import { exportedMethods } from '../src/parser/nextRoutes';
import { EndpointMapper } from '../src/dynamic/EndpointMapper';
import { isNestGuardName, isPyAuthDependency, isPyGuardDecorator } from '../src/parser/adapters/authMiddleware';

async function analyze(files: Record<string, string>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-nextjs-nest-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return await CodeParser.analyze(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function routesOf(files: Record<string, string>): Promise<string[]> {
  const graph = await analyze(files);
  return graph.routes.map((r) => `${r.method} ${r.path}${r.guarded ? ' guarded' : ''}`).sort();
}

const babel = new BabelAdapter();
const python = new PythonAdapter();
const tsRoutes = (src: string) =>
  babel
    .parse('x.controller.ts', src)
    .routes.map((r) => `${r.method} ${r.path}${r.guarded ? ' guarded' : ''}`)
    .sort();
const pyRoutes = (src: string) =>
  python
    .parse('app.py', src)
    .routes.map((r) => `${r.method} ${r.path}${r.guarded ? ' guarded' : ''}`)
    .sort();

const NEXT_PKG = JSON.stringify({ dependencies: { next: '14.0.0' } });

describe('Next.js file routes', () => {
  it('reads app/**/route.ts exports, page.tsx, pages/api, strips (groups) and keeps [id]', async () => {
    const out = await routesOf({
      'package.json': NEXT_PKG,
      'app/api/users/route.ts': 'export async function GET() {}\nexport const POST = async () => {};\n',
      'app/api/users/[id]/route.ts': 'export async function DELETE() {}\n',
      'app/(marketing)/about/page.tsx': 'export default function About() { return null; }\n',
      'app/page.jsx': 'export default function Home() { return null; }\n',
      'pages/api/echo.ts': 'export default function handler(req, res) { res.end(); }\n',
      'pages/api/index.ts': 'export default function handler(req, res) { res.end(); }\n',
    });
    expect(out).toEqual(['ALL /api', 'ALL /api/echo', 'DELETE /api/users/[id]', 'GET /', 'GET /about', 'GET /api/users', 'POST /api/users']);
  });

  it('recognises re-exported and destructured method names, ignores commented ones', () => {
    expect(exportedMethods('export { handler as GET, other as POST };')).toEqual(['GET', 'POST']);
    expect(exportedMethods('export const { GET, POST } = handlers;')).toEqual(['GET', 'POST']);
    expect(exportedMethods('// export async function DELETE() {}\n/* export const PUT = 1 */\nexport function GET() {}')).toEqual(['GET']);
    expect(exportedMethods('export const dynamic = "force-dynamic";\nexport function helper() {}')).toEqual([]);
  });

  it('does not turn request.headers.get / cookies().get into routes (phantom routes)', async () => {
    const out = await routesOf({
      'package.json': NEXT_PKG,
      'middleware.ts': "export function middleware(req) { return req.cookies.get('session'); }\n",
      'app/api/me/route.ts': [
        "import { cookies, headers } from 'next/headers';",
        'export async function GET(request) {',
        "  const a = request.headers.get('authorization');",
        "  const b = cookies().get('session');",
        "  const c = headers().get('x-id');",
        "  const d = request.nextUrl.searchParams.get('q');",
        '  return Response.json({ a, b, c, d });',
        '}',
      ].join('\n'),
    });
    expect(out).toEqual(['GET /api/me']);
  });

  it('still reads a real Express-style route whose path starts with a slash', async () => {
    const out = await routesOf({
      'server.js': "const app = require('express')();\napp.get('/ok', (req, res) => res.end());\napp.get('session', (req, res) => res.end());\n",
    });
    expect(out).toEqual(['GET /ok']);
  });

  it('negative: no next dependency in package.json means no file routes', async () => {
    expect(
      await routesOf({
        'package.json': JSON.stringify({ dependencies: { express: '4' } }),
        'app/api/ping/route.ts': 'export async function GET() {}\n',
        'pages/api/echo.ts': 'export default function h() {}\n',
      }),
    ).toEqual([]);
  });

  it('negative: private folders, parallel slots, intercepting routes, tests and non-handlers are skipped', async () => {
    expect(
      await routesOf({
        'package.json': NEXT_PKG,
        'app/_lib/route.ts': 'export async function GET() {}\n',
        'app/@modal/login/page.tsx': 'export default function P() {}\n',
        'app/feed/(.)photo/page.tsx': 'export default function P() {}\n',
        'app/api/x/route.test.ts': 'export async function GET() {}\n',
        'app/api/y/route.ts': 'export const dynamic = "force-dynamic";\n',
        'app/layout.tsx': 'export default function L() {}\n',
        'pages/api/helper.ts': 'export function helper() {}\n',
      }),
    ).toEqual([]);
  });

  it('uses src/app when the root app folder does not exist, and a monorepo package directory', async () => {
    expect(await routesOf({ 'package.json': NEXT_PKG, 'src/app/api/a/route.ts': 'export function GET() {}\n' })).toEqual(['GET /api/a']);
    expect(
      await routesOf({
        'apps/web/package.json': NEXT_PKG,
        'apps/web/app/api/b/route.ts': 'export function GET() {}\n',
      }),
    ).toEqual(['GET /api/b']);
  });

  it('applies a literal basePath and skips everything (with a note) for a computed one', async () => {
    expect(
      await routesOf({
        'package.json': NEXT_PKG,
        'next.config.js': "module.exports = { basePath: '/docs' };\n",
        'app/api/a/route.ts': 'export function GET() {}\n',
      }),
    ).toEqual(['GET /docs/api/a']);

    const graph = await analyze({
      'package.json': NEXT_PKG,
      'next.config.js': 'module.exports = { basePath: process.env.BASE_PATH };\n',
      'app/api/a/route.ts': 'export function GET() {}\n',
    });
    expect(graph.routes).toEqual([]);
    expect(graph.discoveryNotes?.join('\n')).toMatch(/basePath/);
  });

  it('file routes are never guarded, and a code route with the same method and path wins', async () => {
    const graph = await analyze({
      'package.json': NEXT_PKG,
      'middleware.ts': "export const config = { matcher: ['/admin/:path*'] };\n",
      'app/admin/page.tsx': 'export default function A() {}\n',
    });
    expect(graph.routes.map((r) => [r.method, r.path, r.guarded])).toEqual([['GET', '/admin', false]]);
  });

  it('EndpointMapper reports [id] segments as path parameters, not as a wildcard', () => {
    const plan = EndpointMapper.plan([
      { method: 'GET', path: '/api/users/[id]', file: 'app/api/users/[id]/route.ts', guarded: false },
      { method: 'GET', path: '/docs/[...slug]', file: 'app/docs/[...slug]/page.tsx', guarded: false },
      { method: 'GET', path: '/api/users', file: 'app/api/users/route.ts', guarded: false },
    ]);
    expect(plan.targets.map((t) => t.path)).toEqual(['/api/users']);
    expect(plan.skipped.map((s) => s.reason)).toEqual([expect.stringContaining('path parameter'), expect.stringContaining('path parameter')]);
  });
});

describe('NestJS controllers', () => {
  const header = "import { Controller, Get, Post, Delete, UseGuards } from '@nestjs/common';\n";

  it('joins @Controller prefix and method paths', () => {
    expect(
      tsRoutes(`${header}
@Controller('cats')
export class Cats {
  @Get() all() {}
  @Get(':id') one() {}
  @Post() create() {}
}
@Controller()
export class Root {
  @Get('health') h() {}
}
`),
    ).toEqual(['GET /cats', 'GET /cats/:id', 'GET /health', 'POST /cats']);
  });

  it('controller without a guard is open, with @UseGuards(AuthGuard) is guarded (class and method level)', () => {
    expect(tsRoutes(`${header}\n@Controller('a')\nexport class A { @Get() x() {} }\n`)).toEqual(['GET /a']);
    expect(tsRoutes(`${header}\n@UseGuards(AuthGuard('jwt'))\n@Controller('a')\nexport class A { @Get() x() {} }\n`)).toEqual(['GET /a guarded']);
    expect(
      tsRoutes(`${header}
@Controller('a')
export class A {
  @Get() open() {}
  @Post() @UseGuards(JwtAuthGuard) shut() {}
}`),
    ).toEqual(['GET /a', 'POST /a guarded']);
  });

  it('role decorators are guard evidence; @Public lifts the class guard', () => {
    expect(tsRoutes(`${header}\n@Controller('a')\nexport class A { @Get() @Roles('admin') x() {} }\n`)).toEqual(['GET /a guarded']);
    expect(
      tsRoutes(`${header}
@UseGuards(AuthGuard)
@Controller('a')
export class A {
  @Public() @Get('ping') ping() {}
  @Get('me') me() {}
}`),
    ).toEqual(['GET /a/me guarded', 'GET /a/ping']);
  });

  it('negative: guards that are not auth stay open', () => {
    expect(tsRoutes(`${header}\n@UseGuards(ThrottlerGuard)\n@Controller('a')\nexport class A { @Get() x() {} }\n`)).toEqual(['GET /a']);
    expect(isNestGuardName('ThrottlerGuard')).toBe(false);
    expect(isNestGuardName('CacheGuard')).toBe(false);
    expect(isNestGuardName('JwtAuthGuard')).toBe(true);
    expect(isNestGuardName('RolesGuard')).toBe(true);
  });

  it('negative: computed paths, versioned controllers and non-nest decorators are skipped', () => {
    expect(tsRoutes(`${header}\n@Controller(process.env.P)\nexport class A { @Get() x() {} }\n`)).toEqual([]);
    expect(tsRoutes(`${header}\n@Controller({ path: 'a', version: '1' })\nexport class A { @Get() x() {} }\n`)).toEqual([]);
    expect(tsRoutes("import { Controller } from './mine';\n@Controller('a')\nexport class A { @Get() x() {} }\n")).toEqual([]);
    expect(tsRoutes(`${header}\n@Controller('a')\nexport class A { @Get(SOME_IMPORTED) x() {} }\n`)).toEqual([]);
  });

  it('negative: setGlobalPrefix / RouterModule / enableVersioning drop controller routes and leave a note', async () => {
    const controller = `${header}\n@Controller('cats')\nexport class Cats { @Get() all() {} }\n`;
    for (const call of ["app.setGlobalPrefix('api');", 'app.enableVersioning();', "RouterModule.register([{ path: 'v1', module: M }]);"]) {
      const graph = await analyze({ 'cats.controller.ts': controller, 'main.ts': `${call}\n` });
      expect(graph.routes).toEqual([]);
      expect(graph.discoveryNotes?.join('\n')).toMatch(/NestJS: skipped 1 controller route/);
    }
    expect(await routesOf({ 'cats.controller.ts': controller, 'main.ts': 'bootstrap();\n' })).toEqual(['GET /cats']);
  });

  it('does not touch non-Nest routes when Nest global config is present', async () => {
    const out = await routesOf({
      'main.ts': "app.setGlobalPrefix('api');\n",
      'server.js': "const app = require('express')();\napp.get('/ok', (req, res) => res.end());\n",
    });
    expect(out).toEqual(['GET /ok']);
  });
});

describe('FastAPI guard evidence', () => {
  const head = 'from fastapi import APIRouter, Depends, FastAPI\napp = FastAPI()\n';

  it('router-level dependencies guard every route of the router', () => {
    expect(pyRoutes(`${head}router = APIRouter(dependencies=[Depends(get_current_user)])\n@router.get("/secret")\ndef s(): ...\napp.include_router(router)\n`)).toEqual(['GET /secret guarded']);
  });

  it('negative: router without dependencies, or with a non-auth dependency, stays open', () => {
    expect(pyRoutes(`${head}router = APIRouter()\n@router.get("/open")\ndef s(): ...\napp.include_router(router)\n`)).toEqual(['GET /open']);
    expect(pyRoutes(`${head}router = APIRouter(dependencies=[Depends(get_db)])\n@router.get("/open")\ndef s(): ...\napp.include_router(router)\n`)).toEqual(['GET /open']);
    expect(isPyAuthDependency('get_db')).toBe(false);
    expect(isPyAuthDependency('get_current_user')).toBe(true);
  });

  it('app-level FastAPI(dependencies=...) and include_router(dependencies=...) guard their routes', () => {
    expect(pyRoutes(`from fastapi import Depends, FastAPI\napp = FastAPI(dependencies=[Depends(verify_token)])\n@app.get("/a")\ndef a(): ...\n`)).toEqual(['GET /a guarded']);
    expect(pyRoutes(`${head}router = APIRouter()\n@router.get("/a")\ndef a(): ...\napp.include_router(router, prefix="/v1", dependencies=[Depends(get_current_user)])\n`)).toEqual(['GET /v1/a guarded']);
    expect(pyRoutes(`${head}router = APIRouter()\n@router.get("/a")\ndef a(): ...\napp.include_router(router, prefix="/v1")\n`)).toEqual(['GET /v1/a']);
  });

  it('route-level dependencies=[Depends(auth)] guards just that route', () => {
    expect(pyRoutes(`${head}@app.get("/a", dependencies=[Depends(require_admin)])\ndef a(): ...\n@app.get("/b")\ndef b(): ...\n`)).toEqual(['GET /a guarded', 'GET /b']);
  });

  it('a guarded include_router in another file guards the mounted routes (cross-file)', async () => {
    const out = await routesOf({
      'main.py': 'from fastapi import Depends, FastAPI\nfrom routes import items\napp = FastAPI()\napp.include_router(items.router, prefix="/items", dependencies=[Depends(get_current_user)])\n',
      'routes/items.py': 'from fastapi import APIRouter\nrouter = APIRouter()\n@router.get("/")\ndef l(): ...\n',
      'routes/__init__.py': '',
    });
    expect(out).toEqual(['GET /items guarded']);
  });

  it('a router reached through a guarded and an open registration is not guarded', () => {
    const src = `${head}router = APIRouter()\n@router.get("/a")\ndef a(): ...\napp.include_router(router, prefix="/x", dependencies=[Depends(get_current_user)])\napp.include_router(router, prefix="/y")\n`;
    expect(pyRoutes(src)).toEqual(['GET /x/a guarded', 'GET /y/a']);
  });
});

describe('Flask guard decorators', () => {
  const head = 'from flask import Flask\napp = Flask(__name__)\n';

  it('@login_required on the line after @app.route guards the route', () => {
    expect(pyRoutes(`${head}@app.route("/me")\n@login_required\ndef me(): ...\n`)).toEqual(['ALL /me guarded']);
  });

  it('works for admin_required, jwt_required() and roles_required(...), also with route above or below', () => {
    expect(pyRoutes(`${head}@app.route("/a")\n@admin_required\ndef a(): ...\n@app.route("/b")\n@jwt_required()\ndef b(): ...\n@app.route("/c")\n@roles_required("admin")\ndef c(): ...\n`)).toEqual([
      'ALL /a guarded',
      'ALL /b guarded',
      'ALL /c guarded',
    ]);
    expect(pyRoutes(`${head}@login_required\n@app.route("/a")\ndef a(): ...\n`)).toEqual(['ALL /a']);
  });

  it('negative: decorators that are not auth, or open on purpose, leave the route open', () => {
    expect(pyRoutes(`${head}@app.route("/a")\n@cache.cached(timeout=5)\ndef a(): ...\n`)).toEqual(['ALL /a']);
    expect(pyRoutes(`${head}@app.route("/a")\n@jwt_required(optional=True)\ndef a(): ...\n`)).toEqual(['ALL /a']);
    expect(pyRoutes(`${head}@app.route("/a")\ndef a(): ...\n\n@login_required\ndef helper(): ...\n`)).toEqual(['ALL /a']);
    expect(isPyGuardDecorator('login_required')).toBe(true);
    expect(isPyGuardDecorator('cached')).toBe(false);
  });

  it('a decorator stack never leaks onto the next route', () => {
    expect(pyRoutes(`${head}@app.route("/a")\ndef a(): ...\n\n@app.route("/b")\n@login_required\ndef b(): ...\n`)).toEqual(['ALL /a', 'ALL /b guarded']);
  });
});
