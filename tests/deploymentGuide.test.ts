import { DeploymentGuide, platformFromArg, platformKeyFromName } from '../src/ui/DeploymentGuide';

describe('DeploymentGuide', () => {
  it('produces Vercel steps for a Next.js app', () => {
    const steps = DeploymentGuide.generate('nextjs', 'vercel');
    expect(steps.length).toBeGreaterThan(0);
    expect(steps.some((s) => /vercel/i.test(s.command ?? ''))).toBe(true);
  });

  it('produces Render steps for an Express app', () => {
    const steps = DeploymentGuide.generate('express', 'render');
    expect(steps.length).toBeGreaterThan(0);
    expect(steps.some((s) => /render|render\.yaml|dashboard/i.test(s.title + (s.command ?? '')))).toBe(true);
  });

  it('still supports the original aws and digitalocean platforms', () => {
    expect(DeploymentGuide.generate('express', 'aws').length).toBeGreaterThan(0);
    expect(DeploymentGuide.generate('flask', 'digitalocean').length).toBeGreaterThan(0);
  });

  it('handles new platforms for python and unknown stacks without throwing', () => {
    for (const p of ['render', 'railway', 'fly', 'netlify', 'vercel', 'cloudflare'] as const) {
      expect(() => DeploymentGuide.generate('fastapi', p)).not.toThrow();
      expect(() => DeploymentGuide.generate('unknown', p)).not.toThrow();
    }
  });

  it('gives Cloudflare its own (wrangler) guide instead of aliasing to Netlify', () => {
    expect(platformKeyFromName('Cloudflare Pages')).toBe('cloudflare');
    const steps = DeploymentGuide.generate('nextjs', 'cloudflare');
    expect(steps.some((s) => /wrangler/i.test(s.command ?? ''))).toBe(true);
  });

  it('platformFromArg resolves CLI tokens and aliases, null for unknown', () => {
    expect(platformFromArg('do')).toBe('digitalocean');
    expect(platformFromArg('Fly.io')).toBe('fly');
    expect(platformFromArg('vercel')).toBe('vercel');
    expect(platformFromArg('nope')).toBeNull();
  });
});
