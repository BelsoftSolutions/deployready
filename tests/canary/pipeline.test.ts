/**
 * End-to-end canary test: a synthetic project holding one canary of EVERY detector type is
 * pushed through the full pipeline, and no canary substring may appear in ANY output channel:
 * JSON / markdown / HTML / SARIF exports, terminal output, fix prompts, MCP tool handlers
 * (including get_finding's whole-file content and errors), AI prompts (PromptBuilder,
 * ModelRouter with a fake provider capturing its input, CLI-provider stdin), the logger, and
 * proof builders.
 */
import * as fs from 'fs';
import * as path from 'path';
import { Orchestrator } from '../../src/core/Orchestrator';
import { toCiJson } from '../../src/core/CiGate';
import { ExportManager } from '../../src/ui/ExportManager';
import { HtmlReporter } from '../../src/ui/HtmlReporter';
import { IssuePresenter } from '../../src/ui/IssuePresenter';
import { toSarif } from '../../src/ui/Sarif';
import { renderJson } from '../../src/ui/sanitize';
import { buildFixPrompt } from '../../src/agent/fixPrompt';
import { DeployReadyTools } from '../../src/mcp/tools';
import { wrap } from '../../src/mcp/server';
import { supabaseCheck } from '../../src/mcp/supabase';
import { PromptBuilder } from '../../src/ai/PromptBuilder';
import { ModelRouter } from '../../src/ai/ModelRouter';
import { OllamaHandler } from '../../src/ai/OllamaHandler';
import { formatCliStdin } from '../../src/ai/CliHandler';
import { logger, setVerbose } from '../../src/utils/logger';
import { curlCommand, proofBody } from '../../src/dynamic/proof';
import type { AppConfig, ScanReport } from '../../src/types';
import { buildCanaries, leaks, publicValues, writeCanaryProject, type Canary } from './canaries';

jest.setTimeout(60_000);

let canaries: Canary[];
let root: string;
let report: ScanReport;
let allFiles: string;

beforeAll(async () => {
  process.env.DEPLOYREADY_GITLEAKS = '0';
  canaries = buildCanaries();
  root = writeCanaryProject(canaries);
  const quiet = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  const quietErr = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  report = await Orchestrator.analyze(root, { yes: true, json: true, noAi: true, noDynamic: true });
  quiet.mockRestore();
  quietErr.mockRestore();
  allFiles = listFiles(root)
    .map((f) => fs.readFileSync(path.join(root, f), 'utf8'))
    .join('\n');
});

afterAll(() => {
  delete process.env.DEPLOYREADY_GITLEAKS;
  fs.rmSync(root, { recursive: true, force: true });
});

function listFiles(dir: string, base = ''): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(path.join(dir, base), { withFileTypes: true })) {
    const rel = base ? `${base}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...listFiles(dir, rel));
    else out.push(rel);
  }
  return out;
}

function expectNoLeak(channel: string, text: string): void {
  expect({ channel, leaked: leaks(text, canaries) }).toEqual({ channel, leaked: [] });
}

/** Run fn while capturing everything written to console.* */
async function captureConsole(fn: () => unknown): Promise<string> {
  const chunks: string[] = [];
  const grab = (...a: unknown[]) => {
    chunks.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
  };
  const spies = (['log', 'error', 'warn', 'info'] as const).map((m) => jest.spyOn(console, m).mockImplementation(grab));
  try {
    await fn();
  } finally {
    spies.forEach((s) => s.mockRestore());
  }
  return chunks.join('\n');
}

describe('canary project sanity', () => {
  it('really contains every canary on disk (so a clean output means redaction, not absence)', () => {
    for (const c of canaries) for (const n of c.needles) expect({ type: c.type, present: allFiles.includes(n) }).toEqual({ type: c.type, present: true });
  });

  it('detects the high-confidence shapes and leaves public keys alone', () => {
    const config = report.findings.filter((f) => f.file === 'src/config.ts');
    const at = (needle: string) => {
      const lines = fs.readFileSync(path.join(root, 'src/config.ts'), 'utf8').split('\n');
      return lines.findIndex((l) => l.includes(needle)) + 1;
    };
    const ruleAt = (needle: string) => config.find((f) => f.line === at(needle))?.rule;
    for (const type of ['anthropic', 'openai', 'github-fine-grained-pat', 'aws-access-key-id', 'stripe-secret', 'slack-token', 'supabase-secret-key', 'supabase-service-role-jwt', 'postgres-url']) {
      const c = canaries.find((x) => x.type === type)!;
      expect({ type, rule: ruleAt(c.value) }).toEqual({ type, rule: 'hardcoded-secret' });
    }
    const pub = publicValues();
    expect(ruleAt(pub.publishable)).toBeUndefined();
    expect(ruleAt(pub.anonJwt)).toBeUndefined();
    expect(ruleAt(pub.stripePk)).toBeUndefined();
    // A placeholder-PREFIXED password is a real value, not a placeholder.
    expect(ruleAt(canaries.find((x) => x.type === 'placeholder-prefixed-password')!.value)).toBe('possible-hardcoded-secret');
    expect(report.findings.some((f) => f.file === 'keys/server.pem' && f.rule === 'hardcoded-secret')).toBe(true);
    expect(report.findings.some((f) => f.file === 'service-account.json' && f.rule === 'hardcoded-secret')).toBe(true);
  });
});

describe('no canary reaches any output channel', () => {
  it('raw report object (what every renderer starts from)', () => {
    expectNoLeak('report.findings', JSON.stringify(report.findings));
  });

  it('JSON report (analyze --json)', () => {
    expectNoLeak('json', renderJson(toCiJson(report, 'critical')));
  });

  it('markdown report', () => {
    expectNoLeak('markdown', ExportManager.toMarkdown(report));
  });

  it('HTML report', () => {
    expectNoLeak('html', HtmlReporter.render(report));
  });

  it('SARIF report', () => {
    expectNoLeak('sarif', JSON.stringify(toSarif(report, 'test')));
  });

  it('terminal output', async () => {
    expectNoLeak('terminal', await captureConsole(() => IssuePresenter.display(report)));
  });

  it('fix prompts for every finding', () => {
    expect(report.findings.length).toBeGreaterThan(10);
    expectNoLeak('fix-prompt', report.findings.map((f) => buildFixPrompt(f)).join('\n'));
  });

  it('MCP tool handlers: scan, get_finding (whole file) for every finding, score, errors', async () => {
    const tools = new DeployReadyTools(root);
    const scan = await tools.scan();
    const out: string[] = [JSON.stringify(scan)];
    const files = new Set<string>();
    for (const f of scan.findings) {
      const d = await tools.getFinding({ id: f.id });
      const repo = d.untrusted_repository_content as { file_content?: string } | undefined;
      if (typeof repo?.file_content === 'string') files.add(f.file ?? '');
      out.push(JSON.stringify(d));
    }
    // get_finding really returned the whole file for the secret-bearing files.
    for (const f of ['src/config.ts', 'service-account.json', 'keys/server.pem', 'keys/deploy_key', 'docs/request.http', '.env']) {
      expect(files.has(f) || files.has(f.replace(/^\.\//, ''))).toBe(true);
    }
    out.push(JSON.stringify(await tools.score()));
    out.push(JSON.stringify(await supabaseCheck(root, {})));
    // The stdio wrapper: responses and error messages.
    const ok = await wrap(async () => ({ echo: allFiles }))({});
    const bad = await wrap(async () => {
      throw new Error(`boom ${allFiles}`);
    })({});
    out.push(JSON.stringify(ok), JSON.stringify(bad));
    expectNoLeak('mcp', out.join('\n'));
  });

  it('MCP get_finding keeps line numbers aligned after redacting multi-line keys', async () => {
    const tools = new DeployReadyTools(root);
    const scan = await tools.scan();
    const pem = scan.findings.find((f) => f.file === 'keys/server.pem')!;
    const d = (await tools.getFinding({ id: pem.id })) as { untrusted_repository_content: { file_content: string } };
    const original = fs.readFileSync(path.join(root, 'keys/server.pem'), 'utf8').split('\n');
    // Fenced by one BEGIN and one END marker line.
    expect(d.untrusted_repository_content.file_content.split('\n')).toHaveLength(original.length + 2);
  });

  it('AI prompts: PromptBuilder, ModelRouter with a fake provider, CLI stdin', async () => {
    const sent: string[] = [];
    jest.spyOn(OllamaHandler.prototype, 'complete').mockImplementation(async (p) => {
      sent.push(p.system, p.user);
      return '```js\nconst x = 1;\n```';
    });
    const config: AppConfig = {
      model: 'ollama',
      claudeApiKey: null,
      openaiApiKey: null,
      ollamaPort: 11434,
      ollamaModel: 'fake',
      warnBeforeExternalSend: false,
      defaultPorts: [],
      probeCommonPaths: false,
    };
    const router = new ModelRouter(config);
    await router.analyze(report);
    // A fix snippet is the one place code leaves the machine: send the WHOLE canary project.
    const finding = report.findings[0]!;
    await router.suggestFix(finding, allFiles, allFiles.split('\n').slice(0, 30));
    const built = PromptBuilder.build(report);
    const fix = PromptBuilder.buildFixPrompt(finding, allFiles, allFiles);
    const stdin = formatCliStdin(fix) + formatCliStdin(built);
    jest.restoreAllMocks();
    expect(sent.length).toBeGreaterThanOrEqual(4);
    expectNoLeak('ai-provider-input', sent.join('\n'));
    expectNoLeak('prompt-builder', [built.system, built.user, fix.system, fix.user, router.previewPayload(report)].join('\n'));
    expectNoLeak('cli-stdin', stdin);
  });

  it('logger (info, debug, warn, error, stderr, success) with strings, objects and errors', async () => {
    setVerbose(true);
    const text = await captureConsole(() => {
      logger.info('loaded', allFiles);
      logger.debug('config', { files: allFiles, password: canaries[0]!.value }, new Error(`fail ${allFiles}`));
      logger.warn(`warn ${allFiles}`);
      logger.error(`error ${allFiles}`);
      logger.stderr(`stderr ${allFiles}`);
      logger.success(`ok ${allFiles}`);
    });
    setVerbose(false);
    expectNoLeak('logger', text);
  });

  it('proof builders (request and truncated response)', () => {
    const q = canaries.find((c) => c.type === 'url-query-token')!.value;
    const out = [
      curlCommand({ method: 'GET', url: `https://api.canary.test/v1/x?token=${q}`, auth: '$TOKEN' }),
      proofBody(allFiles),
      proofBody(allFiles, 120),
    ].join('\n');
    expect(out).toContain('$TOKEN');
    expectNoLeak('proof', out);
  });
});
