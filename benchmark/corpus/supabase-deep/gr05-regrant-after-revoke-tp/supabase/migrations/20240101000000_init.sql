-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.audit_log (
  id bigint generated always as identity primary key,
  actor uuid,
  action text
);
alter table public.audit_log enable row level security;
create policy "anyone can append" on public.audit_log for insert with check (true);
revoke all on public.audit_log from anon;
grant all on all tables in schema public to anon;
