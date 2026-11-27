'use client';
import { createClient } from '@supabase/supabase-js';

// Lovable-style: one client for everything, "just works" in the browser
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);
