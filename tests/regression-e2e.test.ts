import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { SeverityScorer } from '../src/analysis/SeverityScorer';

function project(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-reg-'));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, name), content);
  return root;
}

describe('0.4.0 end-to-end regressions', () => {
  it('flags a hardcoded JWT secret even when the payload contains brackets', async () => {
    const root = project({
      'server.js': "const jwt = require('jsonwebtoken');\nconst t = jwt.sign({ id: r[0].id }, 'secret123');\n",
    });
    const findings = await VulnerabilityDetector.scan(root);
    expect(findings.some((f) => f.rule === 'jwt-hardcoded-secret' && f.severity === 'critical')).toBe(true);
  });

  it('keeps an untracked, un-ignored .env at warning after severity scoring', async () => {
    const root = project({ '.env': 'SECRET=x\n', 'index.js': 'console.log(1)\n' });
    const findings = SeverityScorer.apply(await VulnerabilityDetector.scan(root));
    const env = findings.find((f) => f.rule === 'env-not-ignored');
    expect(env?.severity).toBe('warning');
  });
});
