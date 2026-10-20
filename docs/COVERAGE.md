# Unit-test coverage

Measured for 0.3.0 with Jest (ts-jest, `collectCoverageFrom: src/**/*.ts`): 64 suites, 1096 tests, all passing.

```
npm run coverage
```

(equivalent to `npx jest --coverage`).

| Metric     | Value  |
| ---------- | ------ |
| Statements | 86.56% |
| Branches   | 78.07% |
| Functions  | 91.00% |
| Lines      | 88.95% |

## Threshold

`jest.config.js` sets a global `coverageThreshold` of 78% statements, 69% branches, 82% functions and 80% lines, below the numbers above. It exists to catch regressions and fails `jest --coverage` (and so `npm run coverage`) if overall coverage drops below it. Plain `npm test` does not collect coverage and is unaffected.

## Notes

- The orchestrator, verifier, AI handlers, model router, prompt builder, response parsers and exporters are at or near 100%.
- The interactive CLI layer (`cli/*`) and a few small utilities are the least covered parts.
- All tests use mocks, fakes and dummy servers on `127.0.0.1`: no network access, no live AI calls and no real credentials.
