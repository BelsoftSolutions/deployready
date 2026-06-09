import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';

async function rules(files: Record<string, string>): Promise<Set<string>> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'er-sec-'));
  fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  const found = await VulnerabilityDetector.scan(dir);
  return new Set(found.map((f) => f.rule));
}

describe('Phase 5 security-mission static rules', () => {
  it('flags Row-Level Security being disabled', async () => {
    expect(await rules({ 'm.sql': 'ALTER TABLE users DISABLE ROW LEVEL SECURITY;\n' })).toContain(
      'rls-disabled',
    );
  });

  it('flags use of the Supabase service_role key in app code', async () => {
    expect(
      await rules({ 'db.js': 'const c = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n' }),
    ).toContain('supabase-service-role');
  });

  it('flags an insecure http:// URL to a real host', async () => {
    expect(await rules({ 'api.js': 'const base = "http://api.example.com/v1";\n' })).toContain(
      'insecure-http-url',
    );
  });

  it('does NOT flag localhost or schema/namespace http URLs', async () => {
    expect(await rules({ 'dev.js': 'const u = "http://localhost:3000";\n' })).not.toContain(
      'insecure-http-url',
    );
    expect(await rules({ 'svg.js': 'const ns = "http://www.w3.org/2000/svg";\n' })).not.toContain(
      'insecure-http-url',
    );
  });

  it('does NOT flag https URLs', async () => {
    expect(await rules({ 'ok.js': 'const base = "https://api.example.com/v1";\n' })).not.toContain(
      'insecure-http-url',
    );
  });

  it('flags a table created without RLS when the project uses RLS elsewhere', async () => {
    const found = await rules({
      'schema.sql':
        'CREATE TABLE users (id int);\nCREATE TABLE posts (id int);\nALTER TABLE users ENABLE ROW LEVEL SECURITY;\n',
    });
    expect(found).toContain('rls-not-enabled');
  });
});
