/**
 * Minimal, friendly instructions for a user who doesn't know how to get the
 * JWT/bearer token an active scan needs. Shown when `--active` is requested
 * without a `--token` (and via `help`). Pure text, no I/O.
 */
export function jwtRetrievalSteps(): string[] {
  return [
    'Open your app in a browser and log in as a test user.',
    'Open DevTools (F12, or Ctrl/Cmd+Shift+I) and click the "Network" tab.',
    'Do something in the app (or refresh) so requests appear, then click one that hits your API/backend.',
    'In that request\'s "Headers" → "Request Headers", find "Authorization: Bearer <long string>" and copy the long string (that is your JWT).',
    'No Authorization header? Check "Application/Storage" → Local Storage or Cookies for a value like "token", "access_token", or "jwt".',
    'Pass it to DeployReady: --token "<paste-the-token-here>"  (add --token-b "<second user>" to test tenant isolation).',
  ];
}

export function renderTokenHelp(): string {
  const steps = jwtRetrievalSteps()
    .map((s, i) => `  ${i + 1}. ${s}`)
    .join('\n');
  return [
    'To run an active (authenticated) scan, DeployReady needs a login token so it can act as a',
    'real user and then try to reach data it should not. Here is how to get one:',
    '',
    steps,
    '',
    'Note: tokens expire — if you start seeing 401s, grab a fresh one and run again.',
  ].join('\n');
}
