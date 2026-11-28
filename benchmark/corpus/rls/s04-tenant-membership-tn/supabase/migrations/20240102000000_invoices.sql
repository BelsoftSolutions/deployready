-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.invoices (id bigint generated always as identity primary key, org_id uuid not null references public.orgs(id), amount_cents integer);
alter table public.invoices enable row level security;
create policy "org members read invoices" on public.invoices for select to authenticated
  using (exists (select 1 from public.memberships m where m.org_id = invoices.org_id and m.user_id = (select auth.uid())));
