import { tablesMissingRls } from '../src/analysis/rls';

describe('analysis/rls — tablesMissingRls', () => {
  it('flags a created table with no RLS enabled, when the project uses RLS elsewhere', () => {
    const files = [
      {
        relPath: 'migrations/001.sql',
        source: 'CREATE TABLE users (id int);\nCREATE TABLE posts (id int);\nALTER TABLE users ENABLE ROW LEVEL SECURITY;\n',
      },
    ];
    const missing = tablesMissingRls(files);
    expect(missing).toEqual([{ table: 'posts', file: 'migrations/001.sql', line: 2 }]);
  });

  it('does NOT flag anything when the project never uses RLS (not a Postgres/Supabase RLS project)', () => {
    const files = [{ relPath: 'a.sql', source: 'CREATE TABLE users (id int);\nCREATE TABLE posts (id int);\n' }];
    expect(tablesMissingRls(files)).toHaveLength(0);
  });

  it('matches RLS enabled across files and ignores schema-qualified names + IF NOT EXISTS', () => {
    const files = [
      { relPath: 'a.sql', source: 'create table if not exists public.accounts (id int);\ncreate table public.secrets (id int);\n' },
      { relPath: 'b.sql', source: 'alter table public.accounts enable row level security;\n' },
    ];
    const missing = tablesMissingRls(files);
    expect(missing.map((m) => m.table)).toEqual(['secrets']);
  });
});
