import { PlatformRecommender } from '../src/deploy/PlatformRecommender';
import type { Stack, StackInfo } from '../src/types';

function input(stack: Stack, fileCount: number, routes: number, language: StackInfo['language'] = 'javascript') {
  return {
    stack: { stack, language, evidence: [] } as StackInfo,
    graph: {
      root: '/app',
      stack: { stack, language, evidence: [] } as StackInfo,
      entryPoints: [],
      modules: [],
      routes: Array.from({ length: routes }, (_, i) => ({ method: 'GET', path: `/r${i}`, file: 'a', guarded: false })),
      fileCount,
    },
  };
}

describe('PlatformRecommender', () => {
  it('recommends Vercel (free) for a small Next.js app', () => {
    const rec = PlatformRecommender.recommend(input('nextjs', 20, 4, 'typescript'));
    expect(rec.kind).toBe('fullstack');
    expect(rec.size).toBe('small');
    expect(rec.primary.name).toBe('Vercel');
    expect(rec.primary.free).toBe(true);
  });

  it('recommends Render (free) for a small Express API', () => {
    const rec = PlatformRecommender.recommend(input('express', 15, 6));
    expect(rec.kind).toBe('backend');
    expect(rec.primary.name).toBe('Render');
    expect(rec.primary.free).toBe(true);
    expect(rec.split.recommended).toBe(false); // single deployable
  });

  it('classifies a large Django project as a large backend and avoids Vercel', () => {
    const rec = PlatformRecommender.recommend(input('django', 220, 40, 'python'));
    expect(rec.kind).toBe('backend');
    expect(rec.size).toBe('large');
    expect(rec.primary.name).not.toBe('Vercel');
  });

  it('recommends splitting frontend/backend for a large Next.js app with a heavy API surface', () => {
    const rec = PlatformRecommender.recommend(input('nextjs', 300, 60, 'typescript'));
    expect(rec.split.recommended).toBe(true);
    expect(rec.split.frontend?.name).toBe('Vercel');
    expect(rec.split.backend).toBeDefined();
  });

  it('scales the size tier up when there are many routes even with few files', () => {
    expect(PlatformRecommender.recommend(input('express', 10, 5)).size).toBe('small');
    expect(PlatformRecommender.recommend(input('express', 10, 30)).size).toBe('medium');
  });

  it('handles an unknown stack without crashing', () => {
    const rec = PlatformRecommender.recommend(input('unknown', 5, 0, 'unknown'));
    expect(rec.kind).toBe('unknown');
    expect(rec.primary).toBeDefined();
  });

  it('always returns at least one alternative distinct from the primary', () => {
    const rec = PlatformRecommender.recommend(input('fastify', 40, 10));
    expect(rec.alternatives.length).toBeGreaterThan(0);
    expect(rec.alternatives.map((a) => a.name)).not.toContain(rec.primary.name);
  });
});
