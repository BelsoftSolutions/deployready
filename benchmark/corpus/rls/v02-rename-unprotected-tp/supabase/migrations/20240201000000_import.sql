-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table public.customers_import (id bigint primary key, email text, user_id uuid);
