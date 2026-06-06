/** Jest config — TypeScript via ts-jest. */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts'],
  // The sample-app is intentionally vulnerable fixture code, not a test target.
  testPathIgnorePatterns: ['/node_modules/', '/tests/sample-app/'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: {
          // Tests import from src/ (outside the build rootDir) and index arrays
          // freely; relax the strictest flags for the test pass only.
          rootDir: '.',
          noUnusedLocals: false,
          noUncheckedIndexedAccess: false,
        },
      },
    ],
  },
};
