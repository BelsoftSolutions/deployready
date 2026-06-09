import * as path from 'path';
import { Orchestrator } from '../src/core/Orchestrator';
import { getVersion } from '../src/utils/version';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../package.json') as { version: string };

describe('report version', () => {
  it('getVersion() returns the package.json version', () => {
    expect(getVersion()).toBe(pkg.version);
  });

  it('a scan report stamps the real package version, not a hardcoded one', async () => {
    const sampleApp = path.join(__dirname, 'sample-app');
    const report = await Orchestrator.analyze(sampleApp, {
      yes: true,
      noDynamic: true,
      noAi: true,
      json: true,
    });
    expect(report.version).toBe(pkg.version);
  });
});
