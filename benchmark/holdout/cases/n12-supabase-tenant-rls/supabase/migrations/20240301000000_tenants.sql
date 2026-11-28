create table public.organizations (id uuid primary key default gen_random_uuid(), name text not null);
create table public.memberships (
  org_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member',
  primary key (org_id, user_id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id),
  name text not null
);

alter table public.organizations enable row level security;
alter table public.memberships enable row level security;
alter table public.projects enable row level security;

create policy "members read their memberships" on public.memberships for select using (user_id = auth.uid());
create policy "members read org" on public.organizations for select
  using (exists (select 1 from public.memberships m where m.org_id = id and m.user_id = auth.uid()));
create policy "members read projects" on public.projects for select
  using (exists (select 1 from public.memberships m where m.org_id = projects.org_id and m.user_id = auth.uid()));
create policy "admins write projects" on public.projects for all
  using (exists (select 1 from public.memberships m where m.org_id = projects.org_id and m.user_id = auth.uid() and m.role = 'admin'))
  with check (exists (select 1 from public.memberships m where m.org_id = projects.org_id and m.user_id = auth.uid() and m.role = 'admin'));
