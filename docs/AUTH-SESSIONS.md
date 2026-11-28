# Saved login sessions (`deployready auth`)

Authenticated checks need a logged-in identity. Instead of copying JWTs and cookies by hand, DeployReady can save a browser session and turn it into request headers.

A saved session is a **secret**. It is stored at `.deployready/sessions/<name>.json` (file mode 0600, directory 0700). DeployReady adds `.deployready/` to your `.gitignore` if it is not ignored already. Values are never printed or logged; summaries show counts only.

## Record a session by hand

    deployready auth record alice --url http://localhost:3000/login

A visible Chromium window opens. Log in (SSO, MFA and CAPTCHA are fine here), return to the terminal and press Enter. This needs a desktop display, so run it on your own machine, not on a headless server or in CI. Requires Playwright (`npm i playwright && npx playwright install chromium`).

## Scripted login for test accounts

    export ALICE_USER=test@example.com ALICE_PASS=...
    deployready auth login alice --url http://localhost:3000/login \
      --username-env ALICE_USER --password-env ALICE_PASS \
      [--username-selector 'css'] [--password-selector 'css'] [--submit-selector 'css']

Credentials come only from environment variables, never flags. Without selectors it looks for a text/email field, a password field and a submit button, submits, and waits for navigation. If it meets a CAPTCHA or an MFA prompt it stops and tells you to use `auth record`. Use dedicated test accounts only.

## Scope

Login URLs and the provider's target must be loopback, or a host you own, confirmed with `--i-own-this-target <host>` (same rule as the active suite, no wildcards). Credentials are produced for the declared target origin only. A session recorded for another origin is refused.

## Headers produced

`PlaywrightSessionProvider` (`src/auth/provider.ts`) has the `IdentityProvider` shape (`name`, `role`, `tenant?`, `headers()`):

- `Cookie`: unexpired cookies that apply to the target (Secure cookies only over https or loopback).
- `Authorization: Bearer <jwt>` when a JWT is found in localStorage/sessionStorage of that origin: Supabase `sb-*-auth-token` JSON (`access_token`), or keys such as `token`, `accessToken`, `jwt`. NextAuth session cookies stay cookies.
- Expiry: an expired JWT `exp` or all-expired cookies raise `session expired - re-run auth record/login`.

## Notes

Sessions expire. Re-run `auth record` or `auth login` when the provider reports expiry. Delete a session by removing its file.
