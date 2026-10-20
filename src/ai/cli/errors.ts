/** Typed failures for the CLI providers. The router never catches these and switches provider. */
export type ProviderErrorCode =
  | 'cli_missing'
  | 'invalid_config'
  | 'not_logged_in'
  | 'login_expired'
  | 'usage_limit'
  | 'timeout'
  | 'nonzero_exit'
  | 'bad_output'
  | 'output_too_large'
  | 'tools_used'
  | 'spawn_failed';

export class ProviderError extends Error {
  constructor(
    readonly code: ProviderErrorCode,
    message: string,
    readonly hint?: string,
  ) {
    super(hint ? `${message} ${hint}` : message);
    this.name = 'ProviderError';
  }
}
