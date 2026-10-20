import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VulnerabilityDetector } from '../src/analysis/VulnerabilityDetector';

async function flagged(cases: Record<string, string>): Promise<Record<string, boolean>> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-sqli-'));
  fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
  const names = Object.keys(cases);
  names.forEach((name, i) => {
    const ext = name.startsWith('py:') ? 'py' : 'js';
    fs.writeFileSync(path.join(dir, `case${i}.${ext}`), cases[name]! + '\n');
  });
  const findings = await VulnerabilityDetector.scan(dir);
  const out: Record<string, boolean> = {};
  names.forEach((name, i) => {
    out[name] = findings.some((f) => f.rule === 'sql-injection' && f.file?.startsWith(`case${i}.`));
  });
  return out;
}

describe('sql-injection rule', () => {
  it('detects real SQL statements built by concatenation / interpolation', async () => {
    const cases: Record<string, string> = {
      'query concat': 'db.query("SELECT * FROM users WHERE id=" + id)',
      'query template': 'db.query(`SELECT * FROM users WHERE id=${id}`)',
      'execute delete single quotes': "db.execute('DELETE FROM t WHERE x=' + x)",
      'assigned select': 'const q = "SELECT name FROM users WHERE id = " + id;',
      'lower-case select': 'const q = "select * from users where id = " + id;',
      'update template': '`UPDATE users SET name=\'${n}\' WHERE id=${id}`',
      'insert concat': `"INSERT INTO t (a) VALUES ('" + a + "')"`,
      'single quote select': "const q = 'SELECT id FROM t WHERE a = ' + a;",
      'backtick concat': 'const q = `SELECT id FROM t WHERE a = ` + a;',
      'insert template': 'const q = `INSERT INTO t (a, b) VALUES (${a}, ${b})`;',
      'delete template': 'await pool.query(`DELETE FROM sessions WHERE user_id = ${uid}`);',
      'typed query': 'await db.query<Row>(`SELECT * FROM t WHERE id = ${id}`);',
      'prisma raw unsafe': 'prisma.$queryRawUnsafe("SELECT * FROM t WHERE id = " + id);',
      'knex raw': 'knex.raw(`SELECT * FROM t WHERE id = ${id}`);',
      'call with leading CTE': 'db.query(`WITH x AS (SELECT 1) SELECT * FROM t WHERE a=${a}`)',
      'split select concat': 'const q = "SELECT " + cols + " FROM users";',
      'insert into concat table': 'const q = "INSERT INTO " + table + " (a) VALUES (1)";',
      'continuation line of template': '  SELECT * FROM users WHERE id = ${id}',
      'python concat': 'py:cur.execute("SELECT * FROM users WHERE id=" + uid)',
    };
    const res = await flagged(cases);
    for (const name of Object.keys(cases)) {
      expect({ name, hit: res[name] }).toEqual({ name, hit: true });
    }
  });

  it('does not flag non-SQL uses of update/delete/select/insert', async () => {
    const cases: Record<string, string> = {
      'crypto hash update concat': "crypto.createHash('sha256').update(h + '.' + p)",
      'hash update template': 'hash.update(`${a}${b}`)',
      'ORM update': 'User.update({ name: n }, { where: { id } })',
      'array update': 'arr.update(x + 1)',
      'prose update': 'const m = "Please update " + name;',
      'prose delete': 'const m = "delete " + item;',
      'prose select': "const m = 'select ' + option;",
      'prose insert': 'const m = "insert " + coin + " to continue";',
      'hmac update template': 'hmac.update(`${ts}.${body}`).digest("hex")',
      'parameterised $1': 'db.query("SELECT * FROM users WHERE id = $1", [id])',
      'parameterised ?': "db.query('SELECT * FROM t WHERE a=?', [a])",
      'map update': "cache.update('k' + id, v)",
    };
    const res = await flagged(cases);
    for (const name of Object.keys(cases)) {
      expect({ name, hit: res[name] }).toEqual({ name, hit: false });
    }
  });
});
