import 'server-only'
import { createClient } from '@supabase/supabase-js'

// Server-only admin client used by cron jobs; never imported from client components.
export const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
  auth: { persistSession: false },
})
