/**
 * Orchestrator step for the policy-driven authorization matrix (0.6).
 *
 * Runs when `--active` is given and the project declares `active.policy`
 * (or identities). Applies the same gates as the token-based active scan:
 * consent, loopback-or-owned target, safety level (stateful only on a declared
 * disposable environment), request budget, --dry-run / passive preview.
 */
import inquirer from 'inquirer';
import ora from 'ora';
import { LocalhostDetector } from '../dynamic/LocalhostDetector';
import { assertLoopback } from '../dynamic/httpClient';
import { logger } from '../utils/logger';
import type { AppConfig, CodeGraph, Finding } from '../types';
import type { CoverageRecorder } from '../core/coverage';
import { assertActiveTarget, parseOwnedHosts } from './scope';
import { assertSafetyAllowed, resolveActivePolicy, type ActivePolicy } from './safety';
import { disposeIdentities, resolveIdentities } from './identities';
import { previewAuthz, runAuthz } from './authzEngine';
import { createActiveHttpAdapter } from './httpAdapter';
import type { AuthzSettings } from './projectConfig';
import type { AuthzMatrix } from './authzTypes';

export interface AuthzStepOptions {
  yes?: boolean;
  dryRun?: boolean;
  safetyLevel?: string;
  activeUrl?: string;
  ownedHosts?: string[];
  token?: string;
  tokenB?: string;
}

export interface AuthzStepResult {
  findings: Finding[];
  authz?: AuthzMatrix;
}

export async function runAuthzStep(
  projectPath: string,
  graph: CodeGraph,
  opts: AuthzStepOptions,
  config: AppConfig,
  settings: AuthzSettings,
  cov: CoverageRecorder,
): Promise<AuthzStepResult> {
  const skip = (reason: string, requested = true): AuthzStepResult => {
    cov.set('active', 'untested', reason, { requested });
    return { findings: [] };
  };
  for (const p of settings.problems) logger.warn(`Authorization policy: ${p}`);
  if (!settings.policy) {
    logger.warn('Identities are configured but there is no active.policy. Draft one with `deployready policy init`, review it, then re-run.');
    return skip('Identities are configured but no active.policy exists (draft one with `deployready policy init`).');
  }
  if (settings.policy.draft) {
    logger.warn(`The authorization policy in ${settings.source} is still a DRAFT. Review every entry, set "draft": false, then re-run. Nothing was sent.`);
    return skip(`The authorization policy is a draft ("draft": true in ${settings.source}); review it and set "draft": false. Nothing was sent.`);
  }
  if (!settings.policy.resources.length) return skip('The authorization policy has no valid resource.');

  let policy: ActivePolicy;
  let owned: string[];
  try {
    policy = resolveActivePolicy(config, { safetyLevel: opts.safetyLevel });
    owned = parseOwnedHosts([...(opts.ownedHosts ?? []), ...(Array.isArray(config.ownedTargets) ? config.ownedTargets : [])]);
  } catch (err) {
    logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
    return skip(`Active settings rejected: ${(err as Error).message}`);
  }
  const preview = Boolean(opts.dryRun) || policy.safetyLevel === 'passive';

  let baseUrl: string | undefined;
  if (opts.activeUrl) {
    try {
      assertActiveTarget(opts.activeUrl, owned);
    } catch (err) {
      logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
      return skip(`Target refused: ${(err as Error).message}`);
    }
    baseUrl = opts.activeUrl;
  } else if (!preview) {
    const local = await LocalhostDetector.find(config.defaultPorts);
    if (!local) {
      logger.info('Active scan: no local server found listening — start your app, then re-run. Skipping.');
      return skip('No local server found listening.');
    }
    baseUrl = local.baseUrl;
  }
  if (baseUrl) {
    try {
      assertSafetyAllowed(policy, baseUrl, owned);
    } catch (err) {
      logger.warn(`Active scan: ${(err as Error).message} Skipping.`);
      return skip(`Safety level "${policy.safetyLevel}" not allowed here: ${(err as Error).message}`);
    }
  }
  let loopback = true;
  try {
    assertLoopback(baseUrl ?? 'http://localhost');
  } catch {
    loopback = false;
  }

  const identities = await resolveIdentities(settings.identities, {
    cliToken: opts.token,
    cliTokenB: opts.tokenB,
    baseUrl,
    projectPath,
    ownedHosts: owned,
    planOnly: preview,
  });
  for (const i of identities) if (i.unavailable) logger.warn(`Identity "${i.name}" is unavailable: ${i.unavailable}. Its cells are untested.`);

  const engineInput = {
    policy: settings.policy,
    identities,
    routes: graph.routes,
    safetyLevel: policy.safetyLevel,
    unsafeRoutes: policy.unsafeRoutes,
    ignoredFields: policy.ignoredFields,
    maxRequests: policy.maxRequests,
    baseUrl,
    policySource: settings.source,
    problems: settings.problems,
    onSend: (identity: string, method: string, path: string) => logger.debug(`[authz] ${identity}: ${method} ${path}`),
  };

  try {
    if (preview) {
      const dry = previewAuthz(engineInput);
      for (const line of dry.lines) logger.info(line);
      cov.set(
        'active',
        'untested',
        opts.dryRun
          ? `Dry run (--dry-run): authorization matrix of ${dry.matrix.cells.length} cell(s) planned at safety level "${policy.safetyLevel}", none sent.`
          : 'Safety level "passive": the authorization matrix was previewed, no request was sent.',
        { requested: false },
      );
      return { findings: [], authz: dry.matrix };
    }

    const writes = policy.safetyLevel === 'stateful';
    if (!opts.yes) {
      const { ok } = await inquirer.prompt<{ ok: boolean }>([
        {
          type: 'confirm',
          name: 'ok',
          message: `Run the AUTHORIZATION MATRIX (${identities.filter((i) => i.provider).length} identities, safety level "${policy.safetyLevel}", at most ${policy.maxRequests} requests) against ${baseUrl}? ${
            writes
              ? 'This level CREATES, CHANGES and DELETES records (disposable environment declared) to prove write and mass-assignment issues.'
              : 'Read requests only (no writes).'
          } Preview with --dry-run.`,
          default: false,
        },
      ]);
      if (!ok) {
        logger.info('Skipping active scan by your choice.');
        return skip('Declined at the prompt.', false);
      }
    }

    const adapter = createActiveHttpAdapter({ baseUrl: baseUrl!, ownedHosts: owned, maxRequests: policy.maxRequests });
    const spinner = ora('Authorization matrix: testing…').start();
    try {
      const { matrix, findings } = await runAuthz(engineInput, adapter);
      const s = matrix.summary;
      const line = `${s.violation} violation(s), ${s['denied-as-expected']} denied as expected, ${s['allowed-as-expected']} allowed as expected, ${s.inconclusive} inconclusive, ${s.untested} untested; ${matrix.requestsSent} request(s)`;
      spinner.succeed(`Authorization matrix done — ${line}.`);
      const conclusive = s.violation + s['denied-as-expected'] + s['allowed-as-expected'];
      cov.set(
        'active',
        conclusive > 0 ? 'passed' : 'inconclusive',
        `Authorization matrix on ${baseUrl}${loopback ? '' : ' (owned host)'} at safety level "${policy.safetyLevel}": ${line}.`,
        { requested: true },
      );
      return { findings, authz: matrix };
    } catch (err) {
      spinner.fail(`Authorization matrix failed: ${(err as Error).message}`);
      cov.set('active', 'failed', `Authorization matrix errored: ${(err as Error).message}`, { requested: true });
      return { findings: [] };
    }
  } finally {
    await disposeIdentities(identities);
  }
}
