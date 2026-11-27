-- DeployReady benchmark: synthetic migration written for the RLS model tests.
drop table public.invoices cascade;
create table public.invoices (id bigint primary key, user_id uuid not null, amount_cents integer);
