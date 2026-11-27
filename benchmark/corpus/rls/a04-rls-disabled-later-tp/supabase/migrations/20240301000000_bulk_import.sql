-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
-- temporarily turn RLS off for the import job
alter table public.invoices disable row level security;
