import * as path from 'path';
import { CodeParser } from '../src/parser/CodeParser';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { PythonAdapter } from '../src/parser/adapters/PythonAdapter';

const PY_APP = path.join(__dirname, 'python-app');

describe('PythonAdapter', () => {
  const adapter = new PythonAdapter();

  it('extracts routes and resolves include_router mounts', () => {
    const src = `from fastapi import FastAPI
from .routers import auth
app = FastAPI()
app.include_router(auth.router, prefix="/api/auth")
@app.get("/health")
def h(): return {}`;
    const r = adapter.parse('main.py', src);
    expect(r.routes.find((x) => x.path === '/health')?.method).toBe('GET');
    expect(r.mounts).toEqual(
      expect.arrayContaining([expect.objectContaining({ prefix: '/api/auth' })]),
    );
    expect(r.mounts.some((m) => m.source.includes('routers/auth'))).toBe(true);
  });
});

describe('CodeParser on a FastAPI project', () => {
  it('detects the fastapi stack', async () => {
    const graph = await CodeParser.analyze(PY_APP);
    expect(graph.stack.stack).toBe('fastapi');
    expect(graph.stack.language).toBe('python');
  });

  it('composes Python sub-router prefixes across files', async () => {
    const graph = await CodeParser.analyze(PY_APP);
    const paths = graph.routes.map((r) => r.path);
    expect(paths).toContain('/api/auth/login');
    expect(paths).toContain('/api/auth/me');
    expect(paths).toContain('/api/users/list');
    expect(paths).not.toContain('/login'); // bare router-local path must not leak
  });
});

describe('VulnerabilityDetector on Python', () => {
  it('finds Python-specific vulnerabilities', async () => {
    const findings = await VulnerabilityDetector.scan(PY_APP);
    const rules = new Set(findings.map((f) => f.rule));
    expect(rules.has('py-eval-exec')).toBe(true);
    expect(rules.has('py-sql-fstring')).toBe(true);
    expect(rules.has('py-shell-injection')).toBe(true);
    expect(rules.has('hardcoded-secret')).toBe(true);
  });

  it('does not apply JS-only rules to Python files', async () => {
    const findings = await VulnerabilityDetector.scan(PY_APP);
    // xss-sink / cors-wildcard / log-injection are JS-scoped and shouldn't appear.
    expect(findings.some((f) => f.rule === 'xss-sink')).toBe(false);
  });
});
