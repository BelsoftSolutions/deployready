export async function GET(_req: Request, { params }: { params: { id: string } }) {
  return Response.json({ id: params.id });
}
