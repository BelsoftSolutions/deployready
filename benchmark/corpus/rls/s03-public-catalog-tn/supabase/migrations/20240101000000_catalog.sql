-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
create table public.products (id bigint generated always as identity primary key, name text not null, price_cents integer not null);
alter table public.products enable row level security;
create policy "Products are public" on public.products for select to anon, authenticated using (true);
create table public.posts (id bigint generated always as identity primary key, author_id uuid not null, title text, published boolean not null default false);
alter table public.posts enable row level security;
create policy "Published posts are public" on public.posts for select using (published = true or author_id = (select auth.uid()));
create policy "Authors write posts" on public.posts for insert to authenticated with check (author_id = (select auth.uid()));
