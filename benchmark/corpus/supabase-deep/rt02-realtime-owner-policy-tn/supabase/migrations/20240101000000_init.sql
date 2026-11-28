-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null,
  recipient_id uuid not null,
  body text not null
);
alter table public.messages enable row level security;
create policy "participants read" on public.messages for select to authenticated
  using ((select auth.uid()) in (sender_id, recipient_id));
alter publication supabase_realtime add table public.messages;
