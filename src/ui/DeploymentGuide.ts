/**
 * Generates a step-by-step deployment walkthrough tailored to the detected
 * stack. Pure text generation (no price estimates), per spec. Phase 1.5 adds
 * the interactive "Done? (y/n)" stepping; for now it returns the ordered steps.
 */
import type { Stack } from '../types';

export interface DeployStep {
  title: string;
  command?: string;
}

export type Platform = 'aws' | 'digitalocean';

export class DeploymentGuide {
  static generate(stack: Stack, platform: Platform): DeployStep[] {
    const common: DeployStep[] =
      platform === 'aws'
        ? [
            { title: 'Install the AWS CLI', command: 'brew install awscli' },
            { title: 'Configure credentials', command: 'aws configure' },
          ]
        : [
            { title: 'Install doctl (DigitalOcean CLI)', command: 'brew install doctl' },
            { title: 'Authenticate', command: 'doctl auth init' },
          ];

    return [...common, ...DeploymentGuide.stackSteps(stack, platform)];
  }

  private static stackSteps(stack: Stack, platform: Platform): DeployStep[] {
    const node = stack === 'express' || stack === 'nextjs' || stack === 'fastify' || stack === 'nestjs' || stack === 'koa';
    if (platform === 'aws') {
      return node
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
    }
    // DigitalOcean
    return [
      { title: 'Create an App Platform app from your repo', command: 'doctl apps create --spec .do/app.yaml' },
      { title: 'Configure environment variables as encrypted secrets in the dashboard' },
      { title: 'Deploy', command: 'doctl apps create-deployment <app-id>' },
    ];
  }
}
