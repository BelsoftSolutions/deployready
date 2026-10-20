import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

let mockAiText = '';

jest.mock('../src/config/ConfigManager', () => ({
  ConfigManager: {
    exists: async () => true,
    load: async () => ({ model: 'ollama', ollamaPort: 11434, ollamaModel: 'x', warnBeforeExternalSend: false, defaultPorts: [] }),
  },
}));

jest.mock('../src/ai/ModelRouter', () => {
  const { parseAiResponse } = jest.requireActual('../src/ai/parseAiResponse');
  return {
    ModelRouter: class {
      sendsExternally = false;
      isConfigured(): boolean {
        return true;
      }
      async checkReady(): Promise<unknown> {
        return { state: 'ready', provider: 'x', message: 'ok' };
      }
      consentNotice(): string {
        return 'notice';
      }
      async analyze(): Promise<unknown> {
        return parseAiResponse(mockAiText);
      }
    },
  };
});

import { Orchestrator } from '../src/core/Orchestrator';
import { shouldFail } from '../src/core/CiGate';

function project(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-orch-'));
  fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
  fs.writeFileSync(path.join(dir, 'app.js'), 'const r = eval(input);\n');
  return dir;
}

const ai = (file: string | undefined) => ({
  rule: 'ai-made-up',
  title: 'Invented critical',
  severity: 'critical',
  category: 'security',
  description: 'Totally real.',
  recommendation: 'Panic.',
  file,
});

describe('Orchestrator AI merge', () => {
  it('unverified AI output never moves the score or the gate; unverifiable findings are dropped and reported', async () => {
    const dir = project();
    const opts = { noDynamic: true, yes: true, json: true };

    const without = await Orchestrator.analyze(dir, { ...opts, noAi: true });

    mockAiText = JSON.stringify({
      summary: 'Model summary.',
      findings: [ai('ghost/missing.js'), ai('../../etc/passwd'), ai('app.js'), ai(undefined)],
    });
    const withAi = await Orchestrator.analyze(dir, opts);

    expect(withAi.score).toBe(without.score);
    expect(withAi.summary).toMatchObject({
      critical: without.summary.critical,
      warning: without.summary.warning,
      info: without.summary.info,
      total: without.summary.total,
      unverified: 2,
    });
    expect(shouldFail(withAi.summary, 'critical')).toBe(shouldFail(without.summary, 'critical'));
    const aiFindings = withAi.findings.filter((f) => f.source === 'ai');
    expect(aiFindings).toHaveLength(2);
    expect(aiFindings.every((f) => f.unverified === true && f.severity === 'info')).toBe(true);
    expect(withAi.aiSummary).toContain('2 AI finding(s) dropped: referenced file not found');
  });

  it('an AI-only critical on a clean project does not fail the gate', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-orch-clean-'));
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(dir, 'ok.js'), 'module.exports = 1;\n');
    mockAiText = JSON.stringify({ summary: '', findings: [ai('ok.js')] });
    const r = await Orchestrator.analyze(dir, { noDynamic: true, yes: true, json: true });
    expect(r.score).toBe(100);
    expect(shouldFail(r.summary, 'info')).toBe(false);
    expect(r.summary.unverified).toBe(1);
  });
});
