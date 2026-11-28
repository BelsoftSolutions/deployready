-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
drop policy if exists "Allow all" on public.invoices;
create policy "Owners read their invoices" on public.invoices
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Owners create their invoices" on public.invoices
  for insert to authenticated with check ((select auth.uid()) = user_id);
