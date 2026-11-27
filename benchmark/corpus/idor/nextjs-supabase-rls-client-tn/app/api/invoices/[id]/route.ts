import { cookies } from 'next/headers';
import { createServerClient } from '@supabase/ssr';

function supabaseForRequest() {
  const store = cookies();
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { get: (name: string) => store.get(name)?.value },
  });
}

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const supabase = supabaseForRequest();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const { data } = await supabase.from('invoices').select('*').eq('id', params.id).single();
  return Response.json(data);
}
