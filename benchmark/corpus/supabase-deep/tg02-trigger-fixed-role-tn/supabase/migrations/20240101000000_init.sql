-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
create table public.user_roles (
  user_id uuid primary key,
  role text not null default 'user'
);
alter table public.user_roles enable row level security;
create policy "users read own role" on public.user_roles for select to authenticated using ((select auth.uid()) = user_id);
create function public.handle_new_user() returns trigger
  language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.user_roles (user_id, role) values (new.id, 'user');
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
