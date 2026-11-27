-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create table if not exists "public"."Orders" ("id" bigint primary key, "userId" uuid not null, "total" integer);
alter table only "public"."Orders" enable row level security;
create policy "Users see their orders" on "public"."Orders" as permissive for select to "authenticated" using ((select auth.uid()) = "userId");
