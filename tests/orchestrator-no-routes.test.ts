import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const find = jest.fn();
const prompt = jest.fn();

jest.mock('../src/dynamic/LocalhostDetector', () => ({
  LocalhostDetector: { find: (...a: unknown[]) => find(...a), findAll: jest.fn() },
}));
jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: { exists: async () => true, load: async () => ({ defaultPorts: [3000], model: 'none' }) },
}));
jest.mock('inquirer', () => ({ prompt: (...a: unknown[]) => prompt(...a) }));

import { Orchestrator } from '../src/core/Orchestrator';
import { Verifier } from '../src/core/Verifier';
import { ScoreCalculator } from '../src/analysis/ScoreCalculator';

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-noroutes-'));
  fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
  return dir;
}

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const token = `${b64({ alg: 'HS256' })}.${b64({ sub: '1' })}.sig`;

beforeEach(() => {
  find.mockReset();
  prompt.mockReset();
});

describe('Orchestrator with no discovered routes', () => {
  it('never detects, prompts or requests; reports a non-scored dynamic-skipped note', async () => {
    const dir = project({ 'lib.js': 'module.exports = 1;\n' });
    const base = await Orchestrator.analyze(dir, { noDynamic: true, noAi: true, json: true, yes: true });
    const r = await Orchestrator.analyze(dir, { noAi: true, json: true });
    expect(find).not.toHaveBeenCalled();
    expect(prompt).not.toHaveBeenCalled();
    const note = r.findings.find((f) => f.rule === 'dynamic-skipped');
    expect(note).toMatchObject({ severity: 'info', note: true, title: 'No routes discovered; dynamic checks skipped' });
    expect(r.score).toBe(base.score);
    expect(r.summary.notes).toBe(1);
    expect(ScoreCalculator.calculate(r.summary)).toBe(ScoreCalculator.calculate(base.summary));
  });

  it('active scan with no routes also detects nothing and emits an active-skipped note', async () => {
    const dir = project({ 'lib.js': 'module.exports = 1;\n' });
    const r = await Orchestrator.analyze(dir, { noAi: true, json: true, noDynamic: true, active: true, token });
    expect(find).not.toHaveBeenCalled();
    expect(r.findings.find((f) => f.rule === 'active-skipped')).toMatchObject({ severity: 'info', note: true });
  });

  it('active scan whose routes all need unfillable params or are non-GET emits an active-skipped note and detects nothing', async () => {
    const dir = project({
      'server.js':
        "const app = require('express')();\napp.get('/things/:slug', (q, s) => s.send(1));\napp.post('/things', (q, s) => s.send(1));\n",
    });
    const r = await Orchestrator.analyze(dir, { noAi: true, json: true, noDynamic: true, active: true, token });
    expect(r.graph.routes.length).toBeGreaterThan(0);
    expect(find).not.toHaveBeenCalled();
    const note = r.findings.find((f) => f.rule === 'active-skipped')!;
    expect(note.title).toMatch(/routes? discovered but none could be probed; active checks skipped/);
    expect(note.note).toBe(true);
  });
});

describe('Verifier with no routes', () => {
  it('returns unknown with a clear detail and does not detect or request', async () => {
    const res = await Verifier.verify(
      {
        id: 'x',
        rule: 'auth-bypass',
        title: 't',
        severity: 'critical',
        category: 'security',
        source: 'dynamic',
        endpoint: '/a',
        description: 'd',
        recommendation: 'r',
      },
      { target: '.', dynamic: { baseUrl: 'http://127.0.0.1:1', routes: [] } },
    );
    expect(res.status).toBe('unknown');
    expect(res.detail).toMatch(/No routes were discovered/);
    expect(find).not.toHaveBeenCalled();
  });
});
