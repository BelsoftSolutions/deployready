#!/usr/bin/env node
/**
 * CLI entry point. Runs the compiled tool; falls back to a clear message if the
 * project hasn't been built yet.
 */
'use strict';

try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { run } = require('../dist/index.js');
  run().catch((err) => {
    console.error(err && err.message ? err.message : err);
    process.exit(1);
  });
} catch (err) {
  if (err && err.code === 'MODULE_NOT_FOUND') {
    console.error('EnterpriseReady is not built yet. Run `npm run build` first (or `npm install -g .`).');
    process.exit(1);
  }
  throw err;
}
