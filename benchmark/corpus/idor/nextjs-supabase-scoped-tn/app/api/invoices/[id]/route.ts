import { getServerSession } from 'next-auth';
import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  const { data } = await supabaseAdmin
    .from('invoices')
    .select('*')
    .eq('id', params.id)
    .eq('user_id', session.user.id)
    .single();
  return data ? Response.json(data) : new Response('Not found', { status: 404 });
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  await supabaseAdmin.from('invoices').delete().eq('id', params.id).eq('user_id', session.user.id);
  return new Response(null, { status: 204 });
}
