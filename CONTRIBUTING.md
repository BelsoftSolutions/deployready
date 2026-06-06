# Contributing to DeployReady

Thanks for your interest in improving **DeployReady** — the local-first, AI-optional
production-readiness scanner by [Belsoft Solutions](https://github.com/BelsoftSolutions).

This document explains how to contribute and, importantly, the licensing terms your
contributions are made under. **Please read the [Licensing of Contributions](#licensing-of-contributions)
section before opening a pull request** — by contributing you agree to those terms.

---

## Ways to contribute

- **Report a bug** — open an [issue](https://github.com/BelsoftSolutions/deployready/issues)
  with steps to reproduce, the command you ran, and the output you got vs. expected.
- **Suggest a feature or rule** — open an issue describing the problem you want solved
  (not just the solution). New detection rules are especially welcome.
- **Improve docs** — fixes to the README, examples, or this file are always appreciated.
- **Send a pull request** — see the workflow below.

If you're planning a large change, please open an issue first so we can agree on the
approach before you invest time.

---

## Development setup

```bash
# Requires Node.js >= 18
git clone https://github.com/BelsoftSolutions/deployready.git
cd deployready
npm install

npm run dev      # run the CLI from TypeScript source (tsx)
npm run build    # compile to dist/
npm test         # run the Jest test suite
npm run lint     # type-check (tsc --noEmit)
```

Please make sure `npm test` and `npm run lint` both pass before opening a PR.

---

## Pull request workflow

1. Fork the repo and create a branch off `main` (e.g. `fix/sqli-false-positive`).
2. Make focused changes. One logical change per PR is easier to review.
3. Add or update tests for any behavior you change. New rules need test coverage.
4. Run `npm test` and `npm run lint`.
5. **Sign off your commits** (see [DCO](#developer-certificate-of-origin-dco) below).
6. Open the PR with a clear description of *what* and *why*.

We aim to review PRs promptly. Maintainers may request changes or, occasionally,
decline a change that doesn't fit the project's direction — please don't take it
personally.

---

## Licensing of Contributions

> **TL;DR** — Your contributions are licensed to everyone under the **MIT License**
> (same as the project), **and** you also grant Belsoft Solutions the right to
> relicense your contribution under other terms. This lets the free core stay
> open and MIT forever, while allowing Belsoft to build paid/commercial features
> on top without legal ambiguity. You keep the copyright to your own work.

DeployReady follows an **open-core** model: the core scanner is and will remain
free and MIT-licensed; some future advanced or hosted features may be offered
under separate commercial terms. To keep that possible, contributions are accepted
under the following two-part grant.

By submitting a contribution (a pull request, patch, or any other code, docs, or
content) to this project, you agree that:

1. **Inbound = Outbound (MIT).** Your contribution is licensed to the project and
   to all downstream users under the [MIT License](LICENSE), the same license that
   covers the project.

2. **Relicensing grant to Belsoft Solutions.** You additionally grant Belsoft
   Solutions a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
   license to use, reproduce, modify, sublicense, and **relicense** your
   contribution — including under proprietary or other non-MIT terms — as part of
   DeployReady or related Belsoft products. This grant does **not** transfer your
   copyright; you retain ownership of your contribution and may continue to use it
   for any purpose.

3. **You have the right to contribute.** You confirm that you wrote the
   contribution yourself, or otherwise have the right to submit it under the terms
   above, and that it does not knowingly violate anyone else's rights (see DCO
   below).

If you cannot agree to these terms, please don't submit a contribution — instead,
open an issue to discuss, and we'll find another way to incorporate your idea.

### Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) to
record that you have the right to make your contribution. Certify it by adding a
`Signed-off-by` line to each commit:

```bash
git commit -s -m "Add detection for hardcoded JWT secrets"
```

This appends a line like:

```
Signed-off-by: Your Name <you@example.com>
```

By signing off, you certify the DCO terms (you have the right to submit the work
under this project's license) **and** agree to the relicensing grant described above.

---

## Code style

- TypeScript, compiled with the project's `tsconfig.json`.
- Match the style of the surrounding code; keep changes minimal and focused.
- Prefer clear names and small functions. Detection rules should be testable in isolation.

---

## Questions

Open an issue or reach out via the [Belsoft Solutions](https://github.com/BelsoftSolutions)
organization page. Thanks for helping make deploys safer for everyone.
