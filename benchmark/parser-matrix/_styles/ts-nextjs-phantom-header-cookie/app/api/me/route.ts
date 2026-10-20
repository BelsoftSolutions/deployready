import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const token = request.headers.get('authorization');
  const session = cookies().get('session');
  const theme = request.cookies.get('theme');
  return NextResponse.json({ token, session, theme });
}
