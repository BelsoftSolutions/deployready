-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null,
  recipient_id uuid not null,
  body text not null
);
alter publication supabase_realtime add table public.messages;
