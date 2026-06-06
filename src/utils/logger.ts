/**
 * Tiny logger that auto-redacts secrets from every message before it touches
 * stdout/stderr. Never use console.* directly elsewhere — route through here so
 * we cannot accidentally print an API key or a secret found in user code.
 */
import chalk from 'chalk';
import { redact } from './redact';

let verbose = false;

export function setVerbose(v: boolean): void {
  verbose = v;
}

function clean(args: unknown[]): unknown[] {
  return args.map((a) => (typeof a === 'string' ? redact(a) : a));
}

export const logger = {
  info(...args: unknown[]): void {
    console.log(...clean(args));
  },
  success(msg: string): void {
    console.log(chalk.green(`✓ ${redact(msg)}`));
  },
  warn(msg: string): void {
    console.warn(chalk.yellow(`⚠ ${redact(msg)}`));
  },
  /** Human-readable, actionable errors only — never raw stack traces to users. */
  error(msg: string): void {
    console.error(chalk.red(`✗ ${redact(msg)}`));
  },
  debug(...args: unknown[]): void {
    if (verbose) console.error(chalk.gray('[debug]'), ...clean(args));
  },
};
