-- DeployReady benchmark: our own reconstruction of an audit case (the original audit corpus was not available).
-- support team needs to see invoices
alter policy "Owner access" on public.invoices using (true);
