/**
 * PlaywrightSessionProvider: an identity (name/role/tenant + headers()) backed
 * by a saved browser session. Structurally matches the active suite's
 * `IdentityProvider` ({ name; role; tenant?; headers(): Promise<Record<string,string>> }).
 *
 * Credentials are only ever produced for the single declared target origin,
 * which must be loopback or an explicitly owned host (the 0.5.0 scope check).
 */
import { assertActiveTarget } from '../active/scope';
import { SessionExpiredError, extractHeaders, loadSession, loadSessionFile, type SessionState } from './session';

export interface PlaywrightSessionOptions {
  name: string;
  role: string;
  tenant?: string;
  /** Declared target base URL. Headers are produced for this origin only. */
  target: string;
  /** Hosts the user declared ownership of (--i-own-this-target). */
  ownedHosts?: readonly string[];
  /** Project root holding `.deployready/sessions` (default: cwd). */
  root?: string;
  /** Explicit session file (overrides root/name lookup). */
  sessionFile?: string;
  /** In-memory state (tests). */
  state?: SessionState;
}

export class PlaywrightSessionProvider {
  readonly name: string;
  readonly role: string;
  readonly tenant?: string;
  private readonly target: URL;
  private readonly opts: PlaywrightSessionOptions;

  constructor(opts: PlaywrightSessionOptions) {
    this.opts = opts;
    this.name = opts.name;
    this.role = opts.role;
    if (opts.tenant !== undefined) this.tenant = opts.tenant;
    this.target = assertActiveTarget(opts.target, opts.ownedHosts ?? []);
  }

  private state(): SessionState {
    if (this.opts.state) return this.opts.state;
    if (this.opts.sessionFile) return loadSessionFile(this.opts.sessionFile);
    return loadSession(this.opts.root ?? process.cwd(), this.opts.name);
  }

  async headers(): Promise<Record<string, string>> {
    const state = this.state();
    if (state.deployreadyOrigin && state.deployreadyOrigin !== this.target.origin) {
      throw new Error(
        `Session "${this.name}" was recorded for ${state.deployreadyOrigin}, not the declared target ${this.target.origin}; refusing to use it there.`,
      );
    }
    return extractHeaders(state, this.target).headers;
  }

  /** Check validity without exposing values. Returns null when fine, else a message. */
  async check(): Promise<string | null> {
    try {
      await this.headers();
      return null;
    } catch (err) {
      if (err instanceof SessionExpiredError) return err.message;
      throw err;
    }
  }
}
