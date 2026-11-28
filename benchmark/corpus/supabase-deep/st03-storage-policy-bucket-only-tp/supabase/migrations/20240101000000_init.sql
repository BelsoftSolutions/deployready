-- DeployReady benchmark: synthetic Supabase migration (supabase-deep corpus).
insert into storage.buckets (id, name, public) values ('documents', 'documents', false);
create policy "signed in users read documents" on storage.objects for select to authenticated
  using (bucket_id = 'documents');
create policy "signed in users delete documents" on storage.objects for delete to authenticated
  using (bucket_id = 'documents' and auth.role() = 'authenticated');
