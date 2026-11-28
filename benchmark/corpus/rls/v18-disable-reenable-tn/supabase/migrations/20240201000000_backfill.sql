-- DeployReady benchmark: synthetic migration written for the RLS model tests.
alter table public.invoices disable row level security;
update public.invoices set user_id = user_id;
