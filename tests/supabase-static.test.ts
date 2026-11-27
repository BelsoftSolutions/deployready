import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanSupabaseFiles, scanSupabaseStatic, isClientFile, safeEvidence } from '../src/supabase/static';
import { classifyKey, projectRefFromUrl } from '../src/supabase/keys';
import { ANON, SERVICE, OTHER_SERVICE, REF, URL_HOSTED, makeJwt } from './helpers/supabaseMock';

const SB_SECRET = 'sb_secret_abcdefghijklmnopqrstuvwxyz123456';

describe('supabase/keys', () => {
  it('classifies keys by decoded role claim and new-format prefix', () => {
    expect(classifyKey(ANON)).toEqual({ kind: 'anon', ref: REF });
    expect(classifyKey(SERVICE)).toEqual({ kind: 'service_role', ref: REF });
    expect(classifyKey(makeJwt({ role: 'authenticated' })).kind).toBe('other-jwt');
    expect(classifyKey(SB_SECRET).kind).toBe('service_role');
    expect(classifyKey('sb_publishable_abcdefghijklmnop').kind).toBe('anon');
    expect(classifyKey('nope').kind).toBe('unknown');
    expect(classifyKey(undefined).kind).toBe('unknown');
  });

  it('extracts the project ref only from hosted supabase URLs', () => {
    expect(projectRefFromUrl(URL_HOSTED + '/rest/v1')).toBe(REF);
    expect(projectRefFromUrl('https://api.example.com')).toBeUndefined();
    expect(projectRefFromUrl('not a url')).toBeUndefined();
  });
});

describe('supabase/static — service key in client code', () => {
  it('flags a service_role JWT literal in a "use client" file (critical, key redacted)', () => {
    const { findings } = scanSupabaseFiles([
      { relPath: 'app/admin/page.tsx', source: `'use client';\nconst sb = createClient(url, "${SERVICE}");\n` },
    ]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.rule).toBe('supabase-service-jwt-client');
    expect(f.severity).toBe('critical');
    expect(f.line).toBe(2);
    expect(JSON.stringify(f)).not.toContain(SERVICE);
  });

  it('does not flag the same literal in server-only code, nor an anon key in client code', () => {
    const { findings } = scanSupabaseFiles([
      { relPath: 'app/api/admin/route.ts', source: `'use client';\nconst k = "${SERVICE}";` },
      { relPath: 'app/page.tsx', source: `'use client';\nconst k = "${ANON}";` },
      { relPath: 'lib/admin.ts', source: `const k = "${SERVICE}";` },
    ]);
    expect(findings).toEqual([]);
  });

  it('treats src/ in a Vite project as client code and masks sb_secret_ keys in evidence', () => {
    const { findings } = scanSupabaseFiles([
      { relPath: 'package.json', source: '{"devDependencies":{"vite":"^5.0.0"}}' },
      { relPath: 'src/lib/supabase.ts', source: `export const sb = createClient(URL, '${SB_SECRET}');` },
    ]);
    expect(findings.map((f) => f.rule)).toEqual(['supabase-service-jwt-client']);
    expect(findings[0]!.evidence).not.toContain('sb_secret_');
    expect(safeEvidence(`x = '${SB_SECRET}'`)).not.toContain('sb_secret_abc');
  });

  it('src/ is not client code without Vite', () => {
    expect(isClientFile('src/lib/x.ts', 'const a = 1', false)).toBe(false);
    expect(isClientFile('src/lib/x.ts', 'const a = 1', true)).toBe(true);
    expect(isClientFile('src/server/x.ts', 'const a = 1', true)).toBe(false);
    expect(isClientFile('components/x.tsx', '// c\n"use client"\n', false)).toBe(true);
  });
});

describe('supabase/static — public env vars and detection', () => {
  it('flags a public-prefixed env var whose value decodes to service_role, whatever its name', () => {
    const { findings, detected } = scanSupabaseFiles([
      {
        relPath: '.env.local',
        source: `NEXT_PUBLIC_SUPABASE_URL=${URL_HOSTED}\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON}\nNEXT_PUBLIC_DB_KEY=${SERVICE}\nSUPABASE_SERVICE_ROLE_KEY=${SERVICE}\n`,
      },
    ]);
    expect(findings.map((f) => [f.rule, f.line])).toEqual([['supabase-service-jwt-public-env', 3]]);
    expect(findings[0]!.evidence).toBe('NEXT_PUBLIC_DB_KEY=«REDACTED»');
    expect(detected.url).toBe(URL_HOSTED);
    expect(detected.anonKey).toBe(ANON);
    expect(detected.anonKeySource).toBe('.env.local');
  });

  it('detects URL + anon key in source and tables in migrations', () => {
    const { detected } = scanSupabaseFiles([
      { relPath: 'lib/sb.ts', source: `createClient("${URL_HOSTED}", "${ANON}")` },
      {
        relPath: 'supabase/migrations/001.sql',
        source: 'create table public.profiles (id uuid);\nCREATE TABLE IF NOT EXISTS notes (id int);',
      },
    ]);
    expect(detected.url).toBe(URL_HOSTED);
    expect(detected.anonKey).toBe(ANON);
    expect(detected.migrationTables.sort()).toEqual(['notes', 'profiles']);
  });

  it('drops an anon key that belongs to a different project than the URL', () => {
    const otherAnon = makeJwt({ ref: 'yyyyyyyyyyyyyyyyyyyy', role: 'anon' });
    const { detected } = scanSupabaseFiles([{ relPath: '.env', source: `SUPABASE_URL=${URL_HOSTED}\nSUPABASE_ANON_KEY=${otherAnon}` }]);
    expect(detected.anonKey).toBeUndefined();
    expect(classifyKey(OTHER_SERVICE).ref).not.toBe(REF);
  });

  it('walks a project on disk', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-sb-static-'));
    try {
      fs.mkdirSync(path.join(dir, 'components'));
      fs.writeFileSync(path.join(dir, 'components', 'Admin.tsx'), `"use client";\nconst key = "${SERVICE}";\n`);
      const { findings } = await scanSupabaseStatic(dir);
      expect(findings.map((f) => f.file)).toEqual(['components/Admin.tsx']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
