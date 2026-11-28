'use server'
import { prisma } from '@/lib/prisma'
import { auth } from '@/auth'
import { revalidatePath } from 'next/cache'

export async function deleteProject(formData: FormData) {
  const session = await auth()
  if (!session?.user) throw new Error('unauthorized')
  const id = String(formData.get('id'))
  await prisma.project.deleteMany({ where: { id, ownerId: session.user.id } })
  revalidatePath('/projects')
}
