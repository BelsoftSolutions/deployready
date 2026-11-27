import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';
import { idParams } from '../src/analysis/idor';
import type { Finding } from '../src/types';

function proj(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'er-idor-'));
  for (const [name, content] of Object.entries(files)) {
    const abs = path.join(root, name);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}
const idor = async (files: Record<string, string>): Promise<Finding[]> =>
  (await VulnerabilityDetector.scan(proj(files))).filter((f) => f.rule === 'idor-missing-ownership-check');

const EXPRESS_HEAD = [
  "const app = require('express')();",
  'const requireAuth = (req, res, next) => next();',
  "app.get('/api/orders', requireAuth, async (req, res) => res.json(await db.orders.findAll({ where: { userId: req.user.id } })));",
];
const express = (...handler: string[]) => ({ 'server.js': [...EXPRESS_HEAD, ...handler].join('\n') });

describe('idor-missing-ownership-check', () => {
  it('extracts id-like path parameters in every route syntax', () => {
    expect(idParams('/api/orders/:id')).toEqual(['id']);
    expect(idParams('/items/{item_id}')).toEqual(['item_id']);
    expect(idParams('/notes/<int:note_id>')).toEqual(['note_id']);
    expect(idParams('/api/invoices/[invoiceId]')).toEqual(['invoiceId']);
    expect(idParams('/api/users/:slug')).toEqual([]);
  });

  it('flags an authenticated read and delete by id alone, critical for DELETE', async () => {
    const f = await idor(
      express(
        "app.get('/api/orders/:id', requireAuth, async (req, res) => {",
        '  res.json(await db.orders.findByPk(req.params.id));',
        '});',
        "app.delete('/api/orders/:id', requireAuth, async (req, res) => {",
        '  await prisma.order.delete({ where: { id: req.params.id } });',
        '  res.sendStatus(204);',
        '});',
      ),
    );
    expect(f.map((x) => [x.line, x.severity])).toEqual([
      [5, 'warning'],
      [8, 'critical'],
    ]);
    expect(f[0]!.cwe).toBe('CWE-639');
    expect(f[0]!.evidence).toContain('findByPk(req.params.id)');
    expect(f[1]!.description).toContain('DELETE /api/orders/:id');
    expect(f[1]!.recommendation).toContain('--active');
  });

  it('follows destructured and aliased ids', async () => {
    const f = await idor(
      express(
        "app.put('/api/orders/:id', requireAuth, async (req, res) => {",
        '  const { id } = req.params;',
        '  await prisma.order.update({ where: { id }, data: req.body });',
        '});',
        "app.patch('/api/carts/:cartId', requireAuth, async (req, res) => {",
        '  const cid = Number(req.params.cartId);',
        '  await Cart.findByIdAndUpdate(cid, req.body);',
        '});',
      ),
    );
    expect(f.map((x) => x.line)).toEqual([6, 10]);
  });

  it('stays quiet when the query or the handler is scoped to the user', async () => {
    const f = await idor(
      express(
        "app.get('/api/orders/:id', requireAuth, async (req, res) => {",
        '  res.json(await prisma.order.findFirst({ where: { id: req.params.id, userId: req.user.id } }));',
        '});',
        "app.delete('/api/docs/:id', requireAuth, async (req, res) => {",
        '  const doc = await Doc.findById(req.params.id);',
        '  if (String(doc.ownerId) !== String(req.user.id)) return res.sendStatus(404);',
        '  await doc.deleteOne();',
        '});',
        "app.delete('/api/notes/:id', requireAuth, async (req, res) => {",
        '  const note = await Note.findByPk(req.params.id);',
        '  if (!canEdit(req.user, note)) return res.sendStatus(403);',
        '  await note.destroy();',
        '});',
      ),
    );
    expect(f).toEqual([]);
  });

  it('skips admin/role guards, anonymous handlers, public catalog reads and projects without owners', async () => {
    expect(
      await idor(
        express(
          "app.delete('/api/orders/:id', requireAuth, requireAdmin, async (req, res) => {",
          '  await db.orders.destroy({ where: { id: req.params.id } });',
          '});',
          "app.get('/api/tickets/:id', requireAuth, async (req, res) => {",
          "  if (req.user.role !== 'support') return res.sendStatus(403);",
          '  res.json(await db.tickets.findByPk(req.params.id));',
          '});',
          "app.get('/api/products/:id', requireAuth, async (req, res) => {",
          '  res.json(await db.products.findByPk(req.params.id));',
          '});',
        ),
      ),
    ).toEqual([]);
    // No auth at all: missing-auth-route's job, not IDOR.
    expect(
      await idor({
        'server.js': [
          "const app = require('express')();",
          "app.get('/api/orders', async (req, res) => res.json(await db.orders.findAll({ where: { userId: 1 } })));",
          "app.get('/api/orders/:id', async (req, res) => res.json(await db.orders.findByPk(req.params.id)));",
        ].join('\n'),
      }),
    ).toEqual([]);
    // Nothing in the project has an owner column: shared data, nothing to scope by.
    expect(
      await idor({
        'server.js': [
          "const app = require('express')();",
          "app.get('/api/items/:id', requireAuth, async (req, res) => {",
          "  res.json(await db.query('SELECT * FROM items WHERE id = $1', [req.params.id]));",
          '});',
        ].join('\n'),
      }),
    ).toEqual([]);
  });

  it('handles parameterized SQL, and leaves SQL with an owner condition alone', async () => {
    const f = await idor(
      express(
        "app.delete('/api/invoices/:id', requireAuth, async (req, res) => {",
        "  await pool.query('DELETE FROM invoices WHERE id = $1', [req.params.id]);",
        '});',
        "app.get('/api/invoices/:id', requireAuth, async (req, res) => {",
        "  await pool.query('SELECT * FROM invoices WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);",
        '});',
      ),
    );
    expect(f.map((x) => [x.line, x.severity])).toEqual([[5, 'critical']]);
  });

  it('flags Supabase .eq("id") only on a service-role client', async () => {
    const route = (client: string) => [
      client,
      "export async function GET(req: Request, { params }: { params: { id: string } }) {",
      '  const session = await getServerSession();',
      "  if (!session) return new Response('no', { status: 401 });",
      "  const { data } = await db.from('invoices').select('*').eq('id', params.id).single();",
      '  return Response.json(data);',
      '}',
    ].join('\n');
    const base = {
      'package.json': '{"dependencies":{"next":"14.2.3"}}',
      'supabase/migrations/1.sql': 'create table invoices (id uuid, user_id uuid);',
    };
    const admin = await idor({
      ...base,
      'app/api/invoices/[id]/route.ts': route('const db = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);'),
    });
    expect(admin.map((x) => [x.file, x.line])).toEqual([['app/api/invoices/[id]/route.ts', 5]]);
    const rls = await idor({ ...base, 'app/api/invoices/[id]/route.ts': route('const db = createServerClient(url, anon, opts);') });
    expect(rls).toEqual([]);
  });

  it('checks FastAPI and every Flask handler that shares a path', async () => {
    const f = await idor({
      'main.py': [
        'from fastapi import Depends, FastAPI',
        'app = FastAPI()',
        '@app.get("/items")',
        'def items(db=Depends(get_db), current_user=Depends(get_current_user)):',
        '    return db.query(Item).filter(Item.owner_id == current_user.id).all()',
        '@app.get("/items/{item_id}")',
        'def item(item_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):',
        '    return db.query(Item).get(item_id)',
        '@app.get("/mine/{item_id}")',
        'def mine(item_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):',
        '    return db.query(Item).filter_by(id=item_id, owner_id=current_user.id).first()',
      ].join('\n'),
      'web.py': [
        'from flask import Flask',
        'app = Flask(__name__)',
        '@app.route("/notes/<int:note_id>")',
        '@login_required',
        'def get_note(note_id):',
        '    return Note.query.get_or_404(note_id).to_dict()',
        '@app.route("/notes/<int:note_id>", methods=["DELETE"])',
        '@login_required',
        'def delete_note(note_id):',
        '    note = Note.query.get_or_404(note_id)',
        '    db.session.delete(note)',
        '    return "", 204',
      ].join('\n'),
    });
    expect(f.map((x) => [x.file, x.line, x.severity])).toEqual([
      ['main.py', 8, 'warning'],
      ['web.py', 6, 'warning'],
      ['web.py', 10, 'critical'],
    ]);
  });
});

describe('hardcoded-secret and the Firebase web config', () => {
  const KEY = 'AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q';
  const secrets = async (files: Record<string, string>) =>
    (await VulnerabilityDetector.scan(proj(files))).filter((f) => /hardcoded-secret/.test(f.rule));

  it('does not flag the public apiKey of a Firebase web config', async () => {
    expect(
      await secrets({
        'src/firebase.ts': [
          "import { initializeApp } from 'firebase/app';",
          'export const app = initializeApp({',
          `  apiKey: '${KEY}',`,
          "  authDomain: 'demo.firebaseapp.com',",
          "  projectId: 'demo',",
          '});',
        ].join('\n'),
      }),
    ).toEqual([]);
  });

  it('still flags a Google API key outside a Firebase config', async () => {
    const f = await secrets({ 'src/maps.ts': `export const MAPS_KEY = '${KEY}';\nfetch(url + MAPS_KEY);` });
    expect(f.map((x) => [x.rule, x.severity])).toEqual([['hardcoded-secret', 'critical']]);
  });
});
