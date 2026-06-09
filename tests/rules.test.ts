import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';

function scanWith(files: Record<string, string>): Promise<{ rule: string }[]> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'er-rules-'));
  // a gitignored .env so env-not-ignored doesn't add noise
  fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return VulnerabilityDetector.scan(dir);
}

async function rules(files: Record<string, string>): Promise<Set<string>> {
  const found = await scanWith(files);
  return new Set(found.map((f) => f.rule));
}

describe('Phase 2 static rules', () => {
  it('flags the JWT "none" algorithm in JS', async () => {
    expect(await rules({ 'jwt.js': "jwt.verify(t, k, { algorithms: ['none'] });\n" })).toContain(
      'jwt-none-alg',
    );
  });

  it('flags cookies with httpOnly disabled in JS', async () => {
    expect(await rules({ 'app.js': 'res.cookie("sid", v, { httpOnly: false });\n' })).toContain(
      'insecure-cookie',
    );
  });

  it('flags tempfile.mktemp() in Python', async () => {
    expect(await rules({ 'm.py': 'p = tempfile.mktemp()\n' })).toContain('py-mktemp');
  });

  it('flags the JWT "none" algorithm in Python', async () => {
    expect(await rules({ 'a.py': "jwt.decode(t, k, algorithms=['none'])\n" })).toContain(
      'py-jwt-none',
    );
  });

  it('does not flag a properly configured cookie', async () => {
    expect(await rules({ 'ok.js': 'res.cookie("sid", v, { httpOnly: true });\n' })).not.toContain(
      'insecure-cookie',
    );
  });
});
