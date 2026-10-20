import { NextRequest } from 'next/server';

export async function GET() {
  return Response.json([]);
}

export async function POST(request: NextRequest) {
  if (!request.headers.get('authorization')) {
    return new Response('unauthorized', { status: 401 });
  }
  return Response.json(await request.json(), { status: 201 });
}
