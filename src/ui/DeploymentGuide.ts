/**
 * Generates a step-by-step deployment walkthrough tailored to the detected
 * stack and target platform. Pure text generation (no price estimates).
 *
 * Platforms are aligned with PlatformRecommender's catalog so the `deploy`
 * command can take the recommended platform and print actionable steps.
 */
import type { Stack } from '../types';

export interface DeployStep {
  title: string;
  command?: string;
}

export type Platform =
  | 'aws'
  | 'digitalocean'
  | 'vercel'
  | 'netlify'
  | 'cloudflare'
  | 'render'
  | 'railway'
  | 'fly';

const NODE_STACKS: Stack[] = ['express', 'nextjs', 'fastify', 'nestjs', 'koa'];

/**
 * Single source of truth for platform identity: the token that appears both in
 * a user's CLI argument and (as a substring) in the recommender's display name.
 * Order matters for substring matching — list longer/more-specific tokens first.
 */
const PLATFORM_TOKENS: { token: string; platform: Platform }[] = [
  { token: 'digitalocean', platform: 'digitalocean' },
  { token: 'cloudflare', platform: 'cloudflare' },
  { token: 'vercel', platform: 'vercel' },
  { token: 'netlify', platform: 'netlify' },
  { token: 'render', platform: 'render' },
  { token: 'railway', platform: 'railway' },
  { token: 'fly', platform: 'fly' },
  { token: 'aws', platform: 'aws' },
];

/** Extra CLI-only aliases users might type. */
const ARG_ALIASES: Record<string, string> = { do: 'digitalocean', 'fly.io': 'fly', flyio: 'fly' };

/** Map a PlatformRecommender display name to a guide Platform key (defaults to aws). */
export function platformKeyFromName(name: string): Platform {
  const n = name.toLowerCase();
  return PLATFORM_TOKENS.find((t) => n.includes(t.token))?.platform ?? 'aws';
}

/** Map a user-typed CLI argument to a Platform, or null if unrecognized. */
export function platformFromArg(arg: string): Platform | null {
  const a = arg.trim().toLowerCase();
  const norm = ARG_ALIASES[a] ?? a;
  return PLATFORM_TOKENS.find((t) => t.token === norm)?.platform ?? null;
}

export class DeploymentGuide {
  static generate(stack: Stack, platform: Platform): DeployStep[] {
    switch (platform) {
      case 'vercel':
        return [
          { title: 'Install the Vercel CLI', command: 'npm i -g vercel' },
          { title: 'Log in', command: 'vercel login' },
          { title: 'Add your environment variables in the Vercel dashboard (Project → Settings → Environment Variables)' },
          { title: 'Deploy a preview', command: 'vercel' },
          { title: 'Promote to production', command: 'vercel --prod' },
        ];
      case 'netlify':
        return [
          { title: 'Install the Netlify CLI', command: 'npm i -g netlify-cli' },
          { title: 'Log in', command: 'netlify login' },
          { title: 'Link or create a site', command: 'netlify init' },
          { title: 'Set environment variables', command: 'netlify env:set KEY value' },
          { title: 'Deploy to production', command: 'netlify deploy --prod' },
        ];
      case 'cloudflare':
        return [
          { title: 'Install Wrangler (Cloudflare CLI)', command: 'npm i -g wrangler' },
          { title: 'Log in', command: 'wrangler login' },
          { title: 'Build your site/app, then deploy with Pages', command: 'npx wrangler pages deploy ./dist' },
          { title: 'Set environment variables / secrets', command: 'wrangler pages secret put KEY' },
        ];
      case 'render':
        return [
          { title: 'Push your repo to GitHub/GitLab' },
          { title: 'Add a render.yaml blueprint (or create a Web Service in the dashboard)' },
          { title: 'Set environment variables as secrets in the Render dashboard' },
          { title: 'Connect the repo on render.com — Render auto-deploys on push' },
          { title: 'Trigger the first deploy', command: 'git push origin main' },
        ];
      case 'railway':
        return [
          { title: 'Install the Railway CLI', command: 'npm i -g @railway/cli' },
          { title: 'Log in', command: 'railway login' },
          { title: 'Initialize the project', command: 'railway init' },
          { title: 'Add environment variables', command: 'railway variables set KEY=value' },
          { title: 'Deploy', command: 'railway up' },
        ];
      case 'fly':
        return [
          { title: 'Install flyctl', command: 'curl -L https://fly.io/install.sh | sh' },
          { title: 'Log in', command: 'fly auth login' },
          { title: 'Launch (generates a fly.toml)', command: 'fly launch' },
          { title: 'Set secrets', command: 'fly secrets set KEY=value' },
          { title: 'Deploy', command: 'fly deploy' },
        ];
      case 'digitalocean':
        return [
          { title: 'Install doctl (DigitalOcean CLI)', command: 'brew install doctl' },
          { title: 'Authenticate', command: 'doctl auth init' },
          { title: 'Create an App Platform app from your repo', command: 'doctl apps create --spec .do/app.yaml' },
          { title: 'Configure environment variables as encrypted secrets in the dashboard' },
          { title: 'Deploy', command: 'doctl apps create-deployment <app-id>' },
        ];
      case 'aws':
      default:
        return DeploymentGuide.awsSteps(stack);
    }
  }

  private static awsSteps(stack: Stack): DeployStep[] {
    const common: DeployStep[] = [
      { title: 'Install the AWS CLI', command: 'brew install awscli' },
      { title: 'Configure credentials', command: 'aws configure' },
    ];
    const node = NODE_STACKS.includes(stack);
    const stackSteps: DeployStep[] = node
      ? [
          { title: 'Initialize Elastic Beanstalk', command: 'eb init' },
          { title: 'Create environment', command: 'eb create production' },
          { title: 'Set environment variables (secrets)', command: 'eb setenv NODE_ENV=production' },
          { title: 'Deploy', command: 'eb deploy' },
        ]
      : [
          { title: 'Containerize the app with a Dockerfile' },
          { title: 'Push image to ECR', command: 'aws ecr create-repository --repository-name app' },
          { title: 'Deploy on ECS/Fargate or App Runner' },
        ];
    return [...common, ...stackSteps];
  }
}
