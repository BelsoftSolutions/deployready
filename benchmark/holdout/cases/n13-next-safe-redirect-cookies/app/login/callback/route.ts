import { NextResponse } from 'next/server'
import { cookies } from 'next/headers'

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
  const next = searchParams.get('next') ?? '/'
  const safe = next.startsWith('/') && !next.startsWith('//') ? next : '/'
  cookies().set('seen', '1', { httpOnly: true, secure: true, sameSite: 'lax' })
  return NextResponse.redirect(new URL(safe, origin))
}
