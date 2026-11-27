import 'server-only';
import { createClient } from '@supabase/supabase-js';

// Server-only admin client; the key never reaches the browser.
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } }
);
