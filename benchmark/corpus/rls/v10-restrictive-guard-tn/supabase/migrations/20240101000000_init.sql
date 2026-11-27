-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.documents (id bigint primary key, owner_id uuid not null, body text);
alter table public.documents enable row level security;
create policy "signed in" on public.documents for select to authenticated using (true);
create policy "owner only" on public.documents as restrictive for select to authenticated using (owner_id = (select auth.uid()));
