-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
insert into storage.buckets (id, name, public) values ('documents', 'documents', false);
create policy "owners read documents" on storage.objects for select to authenticated
  using (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "owners delete documents" on storage.objects for delete to authenticated
  using (bucket_id = 'documents' and owner_id = (select auth.uid())::text);
