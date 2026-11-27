import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { supabaseCheck } from '../src/mcp/supabase';
import { ANON, SERVICE, URL_HOSTED, mockTransport } from './helpers/supabaseMock';

describe('mcp supabase_check', () => {
  let dir: string;
  const saved = { ...process.env };
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-sb-mcp-'));
    for (const k of Object.keys(process.env)) if (k.startsWith('SUPABASE_')) delete process.env[k];
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    process.env = { ...saved };
  });

  it('runs static checks without any network and returns findings with redacted evidence', async () => {
    fs.writeFileSync(path.join(dir, '.env'), `VITE_SUPABASE_KEY=${SERVICE}\n`);
    const m = mockTransport(() => ({ status: 200 }));
    const res = await supabaseCheck(dir, {}, { transport: m.transport });
    expect(res.live).toBe(false);
    expect(res.findings.map((f) => f.rule)).toEqual(['supabase-service-jwt-public-env']);
    expect(JSON.stringify(res)).not.toContain(SERVICE);
    expect(m.sent).toHaveLength(0);
  });

  it('refuses live checks on a hosted project found in the project files (anon key is not ownership)', async () => {
    fs.writeFileSync(path.join(dir, '.env'), `SUPABASE_URL=${URL_HOSTED}\nSUPABASE_ANON_KEY=${ANON}\n`);
    const m = mockTransport(() => ({ status: 200 }));
    const res = await supabaseCheck(dir, { live: true }, { transport: m.transport });
    expect(res.refused).toBe(true);
    expect(m.sent).toHaveLength(0);
  });

  it('takes the ownership credential from env only, then runs (no prompt)', async () => {
    process.env.SUPABASE_URL = URL_HOSTED;
    process.env.SUPABASE_ANON_KEY = ANON;
    process.env.SUPABASE_SERVICE_ROLE_KEY = SERVICE;
    const m = mockTransport((r) => (r.path.startsWith('/auth/v1/admin/users') ? { status: 200 } : { status: 401 }));
    const res = await supabaseCheck(dir, { live: true }, { transport: m.transport });
    expect(res.refused).toBe(false);
    expect(m.sent.length).toBeGreaterThan(1);
    expect(JSON.stringify(res)).not.toContain(SERVICE);
  });
});
