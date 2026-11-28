/**
 * Playwright-driven session capture: `record` (manual, headed) and `login`
 * (scripted form login for test accounts). Playwright is an optional runtime
 * dependency, loaded lazily so the rest of the CLI never needs it.
 */
import * as readline from 'readline';
import { assertActiveTarget } from '../active/scope';
import { ensureGitignored, saveSession, type SessionState, type StoredOrigin } from './session';

/* eslint-disable @typescript-eslint/no-explicit-any */
function loadPlaywright(): any {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('playwright');
  } catch {
    throw new Error('Playwright is not installed. Run `npm install playwright && npx playwright install chromium`, then retry.');
  }
}

export function hasDisplay(env: NodeJS.ProcessEnv = process.env, platform = process.platform): boolean {
  return platform !== 'linux' || Boolean(env.DISPLAY || env.WAYLAND_DISPLAY);
}

async function launch(pw: any, headless: boolean): Promise<any> {
  try {
    return await pw.chromium.launch({ headless });
  } catch (err) {
    const msg = String((err as Error).message).split('\n')[0] ?? '';
    throw new Error(
      `Could not launch Chromium (${msg.slice(0, 160)}). Install it with \`npx playwright install chromium\`${
        headless ? '' : ', and run this where a browser window can open (not a headless server/CI)'
      }.`,
    );
  }
}

/** Capture cookies + localStorage + sessionStorage for every open page's origin. */
async function capture(context: any): Promise<StoredOrigin[]> {
  const state = await context.storageState();
  const origins: StoredOrigin[] = (state.origins ?? []).map((o: any) => ({ origin: o.origin, localStorage: o.localStorage ?? [] }));
  for (const page of context.pages()) {
    try {
      const origin = new URL(page.url()).origin;
      const ss: Array<{ name: string; value: string }> = await page.evaluate(
        "Object.keys(sessionStorage).map((k) => ({ name: k, value: sessionStorage.getItem(k) || '' }))",
      );
      let entry = origins.find((o) => o.origin === origin);
      if (!entry) origins.push((entry = { origin, localStorage: [] }));
      entry.sessionStorage = ss;
    } catch {
      /* page closed or about:blank */
    }
  }
  return origins;
}

async function persist(context: any, root: string, name: string, loginUrl: URL): Promise<string> {
  const state = await context.storageState();
  const full: SessionState = { cookies: state.cookies ?? [], origins: await capture(context), deployreadyOrigin: loginUrl.origin };
  return saveSession(root, name, full);
}

export interface RecordOptions {
  root: string;
  name: string;
  url: string;
  ownedHosts?: string[];
  /** Resolves when the user is done (default: wait for Enter on stdin). */
  waitForUser?: () => Promise<void>;
  log?: (msg: string) => void;
}

function waitForEnter(): Promise<void> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question('', () => {
      rl.close();
      resolve();
    });
  });
}

export async function recordSession(o: RecordOptions): Promise<string> {
  const log = o.log ?? (() => {});
  const url = assertActiveTarget(o.url, o.ownedHosts ?? []);
  if (!o.waitForUser && !hasDisplay()) {
    throw new Error(
      '`auth record` opens a visible browser window and needs a desktop display. Run it on your own machine (not a headless server or CI), or use `auth login` with test-account env vars.',
    );
  }
  const pw = loadPlaywright();
  const browser = await launch(pw, false);
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(url.href);
    log('A browser window is open. Log in there, then come back here and press Enter to save the session.');
    await (o.waitForUser ?? waitForEnter)();
    const file = await persist(context, o.root, o.name, url);
    ensureGitignored(o.root);
    return file;
  } finally {
    await browser.close().catch(() => {});
  }
}

export interface LoginOptions {
  root: string;
  name: string;
  url: string;
  username: string;
  password: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  ownedHosts?: string[];
  headless?: boolean;
  timeoutMs?: number;
}

const USER_SEL = 'input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i], input[name*="login" i], input[id*="user" i], input[id*="email" i], input[type="text"]';
const PASS_SEL = 'input[type="password"]';
const SUBMIT_SEL = 'button[type="submit"], input[type="submit"], form button:not([type="button"])';
const CAPTCHA_SEL = 'iframe[src*="recaptcha"], iframe[src*="hcaptcha"], iframe[src*="turnstile"], .g-recaptcha, .h-captcha, .cf-turnstile';
const MFA_SEL = 'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="totp" i], input[name*="mfa" i], input[name*="2fa" i]';
const MFA_TEXT = /(two[- ]factor|2fa|verification code|authenticator app|one[- ]time (code|password)|enter the code)/i;

async function challenge(page: any): Promise<string | null> {
  if (await page.locator(CAPTCHA_SEL).count()) return 'CAPTCHA';
  if (await page.locator(MFA_SEL).count()) return 'MFA';
  const text: string = await page.evaluate("document.body ? document.body.innerText : ''").catch(() => '');
  return MFA_TEXT.test(text) ? 'MFA' : null;
}

export async function scriptedLogin(o: LoginOptions): Promise<string> {
  const url = assertActiveTarget(o.url, o.ownedHosts ?? []);
  const timeout = o.timeoutMs ?? 20_000;
  const pw = loadPlaywright();
  const browser = await launch(pw, o.headless ?? true);
  const useRecord = 'Use `deployready auth record` to log in by hand instead.';
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.setDefaultTimeout(timeout);
    await page.goto(url.href, { waitUntil: 'load' });

    const blocked = await challenge(page);
    if (blocked === 'CAPTCHA') throw new Error(`The login page shows a CAPTCHA, which cannot be scripted. ${useRecord}`);

    const userField = page.locator(o.usernameSelector ?? USER_SEL).first();
    const passField = page.locator(o.passwordSelector ?? PASS_SEL).first();
    if (!(await userField.count()) || !(await passField.count())) {
      throw new Error('Could not find the username/password fields. Pass --username-selector and --password-selector, or use `deployready auth record`.');
    }
    await userField.fill(o.username);
    await passField.fill(o.password);
    const submit = page.locator(o.submitSelector ?? SUBMIT_SEL).first();
    const nav = page.waitForLoadState('networkidle').catch(() => {});
    if (await submit.count()) await submit.click();
    else await passField.press('Enter');
    await page.waitForTimeout(250);
    await nav;
    await page.waitForLoadState('load').catch(() => {});

    const after = await challenge(page);
    if (after) throw new Error(`The site is asking for ${after === 'MFA' ? 'a second factor (MFA/2FA)' : 'a CAPTCHA'}, which cannot be scripted. ${useRecord}`);
    if (await page.locator(PASS_SEL).count()) {
      throw new Error('Login did not complete: the password field is still showing. Check the test account credentials and selectors (no values were printed).');
    }
    const file = await persist(context, o.root, o.name, url);
    ensureGitignored(o.root);
    return file;
  } finally {
    await browser.close().catch(() => {});
  }
}
