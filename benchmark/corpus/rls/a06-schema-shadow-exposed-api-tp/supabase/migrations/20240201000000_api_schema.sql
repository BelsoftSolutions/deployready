-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create schema if not exists api;
grant usage on schema api to anon, authenticated;
create table api.invoices (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  amount_cents integer not null default 0
);
grant select, insert, update, delete on all tables in schema api to anon, authenticated;
