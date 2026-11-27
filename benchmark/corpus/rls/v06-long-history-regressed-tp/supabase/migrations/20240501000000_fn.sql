-- DeployReady benchmark: synthetic migration written for the RLS model tests.
create or replace function public.touch() returns trigger language plpgsql as $$
begin
  new.read_at := now(); -- not a policy; using (true) in a comment
  return new;
end;
$$;
