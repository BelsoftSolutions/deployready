import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { extractFixRange, MAX_LINES } from '../src/agent/context';
import { FileEditor } from '../src/agent/FileEditor';
import { FixManager } from '../src/agent/FixManager';
import { buildFixPrompt } from '../src/agent/fixPrompt';
import { PromptBuilder } from '../src/ai/PromptBuilder';
import { toCiJson } from '../src/core/CiGate';
import { HtmlReporter } from '../src/ui/HtmlReporter';
import { DeployReadyTools } from '../src/mcp/tools';
import { makeFinding } from '../src/utils/finding';
import type { ScanReport } from '../src/types';

const JS = [
  "const express = require('express');", // 1
  "import fs from 'fs';", // 2
  '', // 3
  'function a() {', // 4
  '  return 1;', // 5
  '}', // 6
  '', // 7
  'class C {', // 8
  '  method(x) {', // 9
  '    const h = x.map((y) => y + 1);', // 10
  '    return crypto.createHash("md5");', // 11
  '  }', // 12
  '}', // 13
  'const top = 5;', // 14
].join('\n');

describe('extractFixRange: JS/TS', () => {
  it('picks the smallest enclosing method, not the class', () => {
    const r = extractFixRange(JS, 11, '.js');
    expect([r.startLine, r.endLine]).toEqual([9, 12]);
  });

  it('ignores a one-line inline arrow and keeps the enclosing method', () => {
    const r = extractFixRange(JS, 10, '.js');
    expect([r.startLine, r.endLine]).toEqual([9, 12]);
  });

  it('uses the top-level statement outside any function', () => {
    const r = extractFixRange(JS, 14, '.js');
    expect([r.startLine, r.endLine]).toEqual([14, 14]);
  });

  it('returns import/require lines outside the range as read-only context', () => {
    const r = extractFixRange(JS, 5, '.js');
    expect([r.startLine, r.endLine]).toEqual([4, 6]);
    expect(r.imports).toEqual(["const express = require('express');", "import fs from 'fs';"]);
  });

  it('does not list imports that fall inside the replaced range', () => {
    const r = extractFixRange(JS, 1, '.js');
    expect(r.imports).toEqual(["import fs from 'fs';"]);
  });

  it('falls back to +-15 lines (and regex imports) when the file does not parse', () => {
    const src = ["import a from 'a';", ...Array.from({ length: 40 }, (_, i) => `x ${i} (`)].join('\n');
    const r = extractFixRange(src, 20, '.js');
    expect([r.startLine, r.endLine]).toEqual([5, 35]);
    expect(r.imports).toEqual(["import a from 'a';"]);
  });

  it('falls back to +-15 when the unit is larger than the cap', () => {
    const body = Array.from({ length: MAX_LINES + 30 }, (_, i) => `  const v${i} = ${i};`);
    const src = ['function big() {', ...body, '}'].join('\n');
    const r = extractFixRange(src, 70, '.js');
    expect([r.startLine, r.endLine]).toEqual([55, 85]);
  });
});

describe('extractFixRange: Python and others', () => {
  const PY = [
    'import os', // 1
    'from flask import Flask', // 2
    '', // 3
    '@app.route("/")', // 4
    'def index():', // 5
    '    name = request.args["n"]', // 6
    '', // 7
    '    return eval(name)', // 8
    '', // 9
    'class K:', // 10
    '    def m(self):', // 11
    '        return 1', // 12
    '    x = 2', // 13
    'y = 3', // 14
  ].join('\n');

  it('uses the enclosing def (with decorators), including interior blank lines', () => {
    const r = extractFixRange(PY, 8, '.py');
    expect([r.startLine, r.endLine]).toEqual([4, 8]);
    expect(r.imports).toEqual(['import os', 'from flask import Flask']);
  });

  it('prefers the innermost def over the class', () => {
    expect(extractFixRange(PY, 12, '.py')).toMatchObject({ startLine: 11, endLine: 12 });
  });

  it('uses the class block for class-level lines and +-15 at module level', () => {
    expect(extractFixRange(PY, 13, '.py')).toMatchObject({ startLine: 10, endLine: 13 });
    expect(extractFixRange(PY, 14, '.py')).toMatchObject({ startLine: 1, endLine: 14 });
  });

  it('uses +-15 lines for other file types, with no imports', () => {
    const src = Array.from({ length: 50 }, (_, i) => `l${i + 1}`).join('\n');
    const r = extractFixRange(src, 25, '.rb');
    expect([r.startLine, r.endLine]).toEqual([10, 40]);
    expect(r.imports).toEqual([]);
  });
});

describe('FileEditor.fixContext / FixManager', () => {
  function project(content: string, name = 'a.js'): { root: string; editor: FileEditor } {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-ctx-'));
    fs.writeFileSync(path.join(root, name), content);
    return { root, editor: new FileEditor(root) };
  }

  it('returns the enclosing unit text, range and imports', async () => {
    const { editor } = project(JS);
    const s = await editor.fixContext('a.js', 11);
    expect(s.startLine).toBe(9);
    expect(s.endLine).toBe(12);
    expect(s.text.split('\n')[0]).toBe('  method(x) {');
    expect(s.imports).toHaveLength(2);
  });

  it('handles CRLF files with the same line numbers', async () => {
    const { editor } = project(JS.replace(/\n/g, '\r\n'));
    const s = await editor.fixContext('a.js', 11);
    expect([s.startLine, s.endLine]).toEqual([9, 12]);
    expect(s.text).not.toContain('\r');
  });

  it('a fix replaces only the unit; imports stay untouched, and bad syntax is still rejected', async () => {
    const { root, editor } = project(JS);
    const f = makeFinding({
      rule: 'weak-hash', title: 'Weak hash', severity: 'warning', category: 'security', source: 'static',
      description: 'd', recommendation: 'r', file: 'a.js', line: 11,
    });
    const snippet = await FixManager.snippetFor(f, editor);
    const bad = await FixManager.applySuggestion(f, snippet, '  method(x) {', editor);
    expect(bad.applied).toBe(false);
    const ok = await FixManager.applySuggestion(f, snippet, '  method(x) {\n    return 2;\n  }', editor);
    expect(ok.applied).toBe(true);
    const out = fs.readFileSync(path.join(root, 'a.js'), 'utf8');
    expect(out.startsWith("const express = require('express');\nimport fs from 'fs';")).toBe(true);
    expect(out).toContain('return 2;');
    expect(out).not.toContain('md5');
  });
});

describe('PromptBuilder.buildFixPrompt context labelling', () => {
  const f = makeFinding({
    rule: 'r', title: 'T', severity: 'warning', category: 'security', source: 'static',
    description: 'd', recommendation: 'fix it', file: 'a.js', line: 3,
  });

  it('labels read-only imports separately from the snippet to rewrite', () => {
    const p = PromptBuilder.buildFixPrompt(f, 'let a = 1;', "const x = require('x');");
    const ro = p.user.indexOf('READ-ONLY context');
    const sn = p.user.indexOf('Code snippet to fix');
    expect(ro).toBeGreaterThan(-1);
    expect(sn).toBeGreaterThan(ro);
    expect(p.user.slice(ro, sn)).toContain("const x = require('x');");
    expect(p.user.slice(sn)).not.toContain("require('x')");
    expect(p.system).toContain('READ-ONLY');
  });

  it('omits the read-only block when there is no context', () => {
    expect(PromptBuilder.buildFixPrompt(f, 'let a = 1;').user).not.toContain('READ-ONLY');
  });
});

describe('buildFixPrompt (copy fix prompt)', () => {
  const f = makeFinding({
    rule: 'weak-hash', title: 'Weak hash (MD5)', severity: 'warning', category: 'security', source: 'static',
    description: 'd', recommendation: 'Use SHA-256 instead of MD5.', file: 'src/a.js', line: 12,
    owasp: 'A04:2025', cwe: 'CWE-328',
    evidence: `const k = '${'sk-ant-' + 'api03-' + 'A'.repeat(28)}'; RAW_CODE_MARKER`,
  });

  it('names the location, issue, refs, recommendation, minimal-change rule and how to confirm', () => {
    const p = buildFixPrompt(f);
    expect(p).toContain('Where: src/a.js:12');
    expect(p).toContain('Weak hash (MD5) (CWE-328, A04:2025)');
    expect(p).toContain('What to change: Use SHA-256 instead of MD5.');
    expect(p).toMatch(/do not change behaviour/);
    expect(p).toContain('npx deployready@latest analyze');
    expect(p).toContain(`id "${f.id}"`);
    expect(p).not.toContain('npx deployready@latest verify');
  });

  it('can omit the MCP hint, and never includes evidence or raw code', () => {
    const p = buildFixPrompt(f, { mcp: false });
    expect(p).not.toContain('MCP');
    expect(p).not.toContain('RAW_CODE_MARKER');
    expect(p).not.toContain('sk-ant');
  });

  it('uses the endpoint for live findings', () => {
    const live = makeFinding({
      rule: 'x', title: 'Open', severity: 'critical', category: 'security', source: 'dynamic',
      description: 'd', recommendation: 'Require auth.', endpoint: 'GET /admin',
    });
    expect(buildFixPrompt(live)).toContain('Where: GET /admin');
  });
});

describe('fix prompt exposure', () => {
  const f = makeFinding({
    rule: 'weak-hash', title: 'Weak hash', severity: 'warning', category: 'security', source: 'static',
    description: 'd', recommendation: 'Use SHA-256 <b>.', file: 'a.js', line: 2,
  });
  const report = {
    target: '/app', startedAt: 's', finishedAt: 'e', version: '0',
    stack: { stack: 'express', language: 'javascript', evidence: [] },
    graph: { root: '/app', stack: { stack: 'express', language: 'javascript', evidence: [] }, entryPoints: [], modules: [], routes: [], fileCount: 1 },
    findings: [f], score: 90, summary: { critical: 0, warning: 1, info: 0, total: 1 },
  } as unknown as ScanReport;

  it('adds fixPrompt to each JSON report finding', () => {
    const json = toCiJson(report, 'none') as { findings: { fixPrompt: string }[] };
    expect(json.findings[0]?.fixPrompt).toBe(buildFixPrompt(f));
  });

  it('renders a Copy fix prompt button per finding with the prompt escaped in an attribute', () => {
    const html = HtmlReporter.render(report);
    expect(html).toContain('class="copy-prompt"');
    expect(html).toContain('Copy fix prompt');
    expect(html).toContain('Use SHA-256 &lt;b&gt;.');
    expect(html).toContain('navigator.clipboard');
    expect(html).toContain('execCommand');
  });

  it('adds fixPrompt to MCP get_finding', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-mcp-fp-'));
    fs.writeFileSync(path.join(root, 'app.js'), "const crypto = require('crypto');\nconst h = crypto.createHash('md5');\n");
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x","dependencies":{"express":"4.0.0"}}');
    const t = new DeployReadyTools(root);
    const { findings } = await t.scan();
    const weak = findings.find((x) => x.rule === 'weak-hash')!;
    const d = (await t.getFinding({ id: weak.id })) as { fixPrompt: string };
    expect(d.fixPrompt).toContain('app.js:2');
    expect(d.fixPrompt).toContain(weak.id);
  });
});
