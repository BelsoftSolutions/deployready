-- added later by the AI assistant, RLS forgotten
create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid references public.profiles(id),
  content text
);
