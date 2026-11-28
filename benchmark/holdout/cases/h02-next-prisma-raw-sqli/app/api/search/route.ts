import { NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { getServerSession } from 'next-auth'

export async function GET(req: Request) {
  const session = await getServerSession()
  if (!session) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  const q = new URL(req.url).searchParams.get('q') ?? ''
  const rows = await prisma.$queryRawUnsafe(
    `SELECT id, title FROM "Product" WHERE title ILIKE '%${q}%' ORDER BY title LIMIT 50`
  )
  return NextResponse.json(rows)
}
