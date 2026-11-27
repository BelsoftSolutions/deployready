-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.memberships (org_id uuid not null, user_id uuid not null, primary key (org_id, user_id));
alter table public.memberships enable row level security;
create policy "own memberships" on public.memberships for select to authenticated using (user_id = (select auth.uid()));
create table public.projects (id bigint primary key, org_id uuid not null, name text);
alter table public.projects enable row level security;
create policy "org members read projects" on public.projects for select to authenticated
  using (exists (select 1 from public.memberships m where m.user_id = (select auth.uid()) and m.org_id = org_id));
