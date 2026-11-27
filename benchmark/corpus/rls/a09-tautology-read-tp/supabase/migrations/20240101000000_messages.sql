-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.messages (id bigint generated always as identity primary key, sender_id uuid not null, body text);
alter table public.messages enable row level security;
create policy "read messages" on public.messages for select using (1 = 1);
create table public.profiles (id uuid primary key, full_name text, phone text);
alter table public.profiles enable row level security;
create policy "read profiles" on public.profiles for select to anon, authenticated using ('a' = 'a');
