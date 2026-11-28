'use server'
import { prisma } from '@/lib/prisma'
import { revalidatePath } from 'next/cache'

export async function deleteProject(formData: FormData) {
  const id = String(formData.get('id'))
  await prisma.project.delete({ where: { id } })
  revalidatePath('/projects')
}

export async function setUserRole(userId: string, role: string) {
  await prisma.user.update({ where: { id: userId }, data: { role } })
}
