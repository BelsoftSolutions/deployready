/**
 * Detect the framework/stack from manifest files and dependency names.
 * Drives stack-specific deployment guidance and tailors security checks.
 */
import * as path from 'path';
import type { WalkedFile } from '../utils/FileWalker';
import { FileWalker } from '../utils/FileWalker';
import type { Stack, StackInfo } from '../types';

interface Signal {
  stack: Stack;
  language: StackInfo['language'];
  deps: string[];
}

const JS_SIGNALS: Signal[] = [
  { stack: 'nextjs', language: 'javascript', deps: ['next'] },
  { stack: 'nestjs', language: 'javascript', deps: ['@nestjs/core'] },
  { stack: 'fastify', language: 'javascript', deps: ['fastify'] },
  { stack: 'koa', language: 'javascript', deps: ['koa'] },
  { stack: 'express', language: 'javascript', deps: ['express'] },
];

const PY_SIGNALS: { stack: Stack; pattern: RegExp }[] = [
  { stack: 'fastapi', pattern: /fastapi/i },
  { stack: 'django', pattern: /django/i },
  { stack: 'flask', pattern: /flask/i },
];

export class StackDetector {
  static async detect(root: string, files: WalkedFile[]): Promise<StackInfo> {
    const byName = new Map(files.map((f) => [path.basename(f.absPath), f]));
    const evidence: string[] = [];

    // ---- JavaScript / TypeScript via package.json ----
    const pkg = byName.get('package.json');
    if (pkg) {
      try {
        const json = JSON.parse(await FileWalker.read(pkg)) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        const deps = { ...json.dependencies, ...json.devDependencies };
        const hasTs = files.some((f) => f.relPath.endsWith('.ts') || f.relPath.endsWith('.tsx'));
        for (const sig of JS_SIGNALS) {
          if (sig.deps.some((d) => d in deps)) {
            evidence.push(`package.json depends on ${sig.deps.join('/')}`);
            return {
              stack: sig.stack,
              language: hasTs ? 'typescript' : 'javascript',
              evidence,
            };
          }
        }
        // It's a JS project but no known framework.
        return {
          stack: 'unknown',
          language: hasTs ? 'typescript' : 'javascript',
          evidence: ['package.json present, no known web framework dependency'],
        };
      } catch {
        evidence.push('package.json present but unparseable');
      }
    }

    // ---- Python via requirements.txt ----
    const reqs = byName.get('requirements.txt');
    if (reqs) {
      const text = await FileWalker.read(reqs);
      for (const sig of PY_SIGNALS) {
        if (sig.pattern.test(text)) {
          evidence.push(`requirements.txt mentions ${sig.stack}`);
          return { stack: sig.stack, language: 'python', evidence };
        }
      }
      return { stack: 'unknown', language: 'python', evidence: ['Python project'] };
    }

    // ---- PHP / Laravel ----
    if (byName.has('composer.json')) {
      const text = await FileWalker.read(byName.get('composer.json')!);
      if (/laravel\/framework/i.test(text)) {
        return { stack: 'laravel', language: 'php', evidence: ['composer.json -> laravel/framework'] };
      }
      return { stack: 'unknown', language: 'php', evidence: ['composer.json present'] };
    }

    return { stack: 'unknown', language: 'unknown', evidence: ['No recognizable manifest found'] };
  }
}
