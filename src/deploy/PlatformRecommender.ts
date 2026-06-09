/**
 * Recommends a hosting platform from a scanned project.
 *
 * Pure + deterministic: given the detected stack and a couple of size signals
 * (file count, route count), it picks a primary platform, a few alternatives,
 * and decides whether the frontend and backend are better off split across two
 * platforms. Platforms with a free tier that suits the project are flagged
 * `free: true` so the UI can mark them "(free)".
 *
 * No network, no pricing lookups — the catalog below is hand-curated and the
 * `free` flag means "has a free tier realistically usable for a project of this
 * size", not "free forever at any scale".
 */
import type { Stack, StackInfo, CodeGraph } from '../types';

export type ProjectKind = 'frontend' | 'backend' | 'fullstack' | 'unknown';
export type SizeTier = 'small' | 'medium' | 'large';

export interface PlatformPick {
  name: string;
  url: string;
  /** Has a free tier suitable for a project of this size. */
  free: boolean;
  /** Why this platform fits this project. */
  reason: string;
}

export interface SplitRecommendation {
  recommended: boolean;
  reason: string;
  frontend?: PlatformPick;
  backend?: PlatformPick;
}

export interface DeployRecommendation {
  kind: ProjectKind;
  size: SizeTier;
  primary: PlatformPick;
  alternatives: PlatformPick[];
  split: SplitRecommendation;
  notes: string[];
}

export interface RecommenderInput {
  stack: StackInfo;
  graph: Pick<CodeGraph, 'fileCount' | 'routes'>;
}

// ---- Platform catalog -------------------------------------------------------
// Each entry is a factory so the `reason` can be tailored per project.
const P = {
  vercel: (reason: string): PlatformPick => ({ name: 'Vercel', url: 'https://vercel.com', free: true, reason }),
  netlify: (reason: string): PlatformPick => ({ name: 'Netlify', url: 'https://www.netlify.com', free: true, reason }),
  cloudflare: (reason: string): PlatformPick => ({ name: 'Cloudflare Pages', url: 'https://pages.cloudflare.com', free: true, reason }),
  render: (reason: string): PlatformPick => ({ name: 'Render', url: 'https://render.com', free: true, reason }),
  railway: (reason: string): PlatformPick => ({ name: 'Railway', url: 'https://railway.app', free: false, reason }),
  fly: (reason: string): PlatformPick => ({ name: 'Fly.io', url: 'https://fly.io', free: false, reason }),
  digitalocean: (reason: string): PlatformPick => ({ name: 'DigitalOcean App Platform', url: 'https://www.digitalocean.com/products/app-platform', free: false, reason }),
  aws: (reason: string): PlatformPick => ({ name: 'AWS', url: 'https://aws.amazon.com', free: false, reason }),
};

const NODE_STACKS: Stack[] = ['express', 'fastify', 'nestjs', 'koa'];
const PY_STACKS: Stack[] = ['fastapi', 'flask', 'django'];

export class PlatformRecommender {
  static recommend(input: RecommenderInput): DeployRecommendation {
    const stack = input.stack.stack;
    const fileCount = input.graph.fileCount;
    const routes = input.graph.routes.length;

    const kind = classifyKind(stack);
    const size = classifySize(fileCount, routes);
    const notes: string[] = [];

    let primary: PlatformPick;
    let alternatives: PlatformPick[];

    if (stack === 'nextjs') {
      primary = P.vercel('Built by the Next.js team; zero-config deploys, edge network, and a generous hobby tier.');
      alternatives = [
        P.netlify('First-class Next.js support with a free tier.'),
        P.render('Run Next.js as a Node service if you want a single provider for app + API.'),
        size === 'large' ? P.aws('Full control for large/complex traffic via Amplify or containers.') : P.cloudflare('Static + edge functions on a fast free tier.'),
      ];
    } else if (NODE_STACKS.includes(stack)) {
      if (size === 'large') {
        primary = P.digitalocean('Predictable pricing and managed databases for a larger Node backend.');
        alternatives = [P.render('Free tier to start; scales to paid instances.'), P.aws('Most control for complex/large workloads (ECS/App Runner).'), P.fly('Run close to users with a usage-based model.')];
      } else {
        primary = P.render('Free web-service tier, native Node support, zero Docker required.');
        alternatives = [P.railway('Great DX for small Node services (usage-based after trial).'), P.fly('Usage-based; deploy near your users.'), P.digitalocean('Step up to predictable pricing as you grow.')];
      }
    } else if (PY_STACKS.includes(stack)) {
      if (size === 'large') {
        primary = P.digitalocean('Managed Postgres + predictable pricing suit a larger Python backend.');
        alternatives = [P.render('Native Python support with a free tier to start.'), P.aws('Most control for complex/large workloads.'), P.fly('Usage-based, run close to users.')];
        if (stack === 'django') notes.push('Add a managed Postgres and run migrations on deploy; serve static files via WhiteNoise or a CDN.');
      } else {
        primary = P.render('Native Python support and a free web-service tier — ideal for FastAPI/Flask.');
        alternatives = [P.railway('Fast Python deploys (usage-based after trial).'), P.fly('Usage-based; global regions.'), P.digitalocean('Predictable pricing as you scale.')];
      }
    } else if (stack === 'laravel') {
      primary = P.digitalocean('Solid PHP/Laravel support with managed databases.');
      alternatives = [P.render('Deploy Laravel via Docker on a free-to-start tier.'), P.fly('Containerized PHP close to your users.'), P.aws('Most control for large PHP workloads.')];
      notes.push('Set APP_ENV=production, APP_DEBUG=false, run `php artisan migrate --force`, and cache config/routes on deploy.');
    } else {
      // Unknown stack — give a safe general-purpose default.
      primary = P.render('General-purpose host with a free tier that runs most stacks.');
      alternatives = [P.vercel('Best if this turns out to be a frontend/JS app.'), P.fly('Usage-based container hosting for anything Dockerizable.')];
      notes.push('Stack not confidently detected — confirm whether this is a frontend, backend, or full-stack app for a sharper recommendation.');
    }

    // Ensure no alternative duplicates the primary.
    alternatives = alternatives.filter((a) => a.name !== primary.name);

    const split = decideSplit(kind, size, routes);
    if (size === 'large') notes.push('Large codebase: provision managed databases/queues separately and keep secrets in the platform’s secret store, not in code.');

    return { kind, size, primary, alternatives, split, notes };
  }
}

function classifyKind(stack: Stack): ProjectKind {
  if (stack === 'nextjs') return 'fullstack';
  if (NODE_STACKS.includes(stack) || PY_STACKS.includes(stack) || stack === 'laravel') return 'backend';
  return 'unknown';
}

function classifySize(fileCount: number, routes: number): SizeTier {
  let tier: SizeTier = fileCount >= 150 ? 'large' : fileCount >= 30 ? 'medium' : 'small';
  // A heavy route surface bumps the tier up even when the file count is modest.
  if (routes >= 60 && tier !== 'large') tier = 'large';
  else if (routes >= 25 && tier === 'small') tier = 'medium';
  return tier;
}

function decideSplit(kind: ProjectKind, size: SizeTier, routes: number): SplitRecommendation {
  if (kind === 'fullstack' && size === 'large' && routes >= 40) {
    return {
      recommended: true,
      reason:
        'Large full-stack app with a heavy API surface — host the frontend on a CDN/edge platform and move long-running or background API work to a dedicated backend service.',
      frontend: P.vercel('Edge-hosted frontend with instant rollbacks.'),
      backend: P.render('Dedicated always-on backend for heavy/long-running API routes.'),
    };
  }
  return {
    recommended: false,
    reason:
      kind === 'fullstack'
        ? 'A single full-stack deployment is simplest at this size — split only if the API outgrows the frontend host.'
        : 'Single deployable — no need to split the frontend and backend across platforms.',
  };
}
