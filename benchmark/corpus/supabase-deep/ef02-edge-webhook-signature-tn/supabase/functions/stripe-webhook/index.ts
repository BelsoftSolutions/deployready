// DeployReady benchmark: synthetic Edge Function (supabase-deep corpus).
import Stripe from 'npm:stripe@14';
import { createClient } from 'npm:@supabase/supabase-js@2';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!);

Deno.serve(async (req) => {
  const body = await req.text();
  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(body, req.headers.get('stripe-signature')!, Deno.env.get('STRIPE_WEBHOOK_SECRET')!);
  } catch {
    return new Response('bad signature', { status: 400 });
  }
  const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  if (event.type === 'invoice.paid') await admin.from('invoices').update({ paid: true }).eq('stripe_id', event.data.object.id);
  return new Response('ok');
});
