-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.orgs (id uuid primary key default gen_random_uuid(), name text);
create table public.memberships (org_id uuid not null references public.orgs(id), user_id uuid not null, primary key (org_id, user_id));
alter table public.orgs enable row level security;
alter table public.memberships enable row level security;
create policy "members see their memberships" on public.memberships for select to authenticated using (user_id = (select auth.uid()));
create policy "members see their orgs" on public.orgs for select to authenticated
  using (id in (select m.org_id from public.memberships m where m.user_id = (select auth.uid())));
