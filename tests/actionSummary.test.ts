/* eslint-disable @typescript-eslint/no-var-requires */
const { buildSummary, MARKER } = require('../action/summary');
const upsertComment = require('../action/comment');
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const mk = (n: number) =>
  Array.from({ length: n }, (_, i) => ({
    rule: `r${i}`, title: `T${i} | x`, severity: i === 0 ? 'warning' : i === 1 ? 'critical' : 'info',
    file: i % 2 ? 'a.ts' : undefined, line: i % 2 ? i : undefined, endpoint: 'GET /e',
  }));

describe('buildSummary', () => {
  it('includes marker, score, counts, top 10 sorted by severity, and link', () => {
    const md = buildSummary(
      { score: 71, summary: { critical: 1, warning: 1, info: 10, total: 12 }, findings: mk(12) },
      { exitCode: 2, failOn: 'critical', runUrl: 'https://example.test/run/1' },
    );
    expect(md.startsWith(MARKER)).toBe(true);
    expect(md).toContain('Score: 71/100');
    expect(md).toContain('gate failed');
    expect(md).toContain('| 1 | 1 | 10 |');
    expect(md).toContain('Top 10 of 12');
    expect(md).toContain('a.ts:1');
    expect(md).toContain('GET /e');
    expect(md).toContain('2 more');
    expect(md).toContain('https://example.test/run/1');
    expect(md.indexOf('critical |')).toBeLessThan(md.indexOf('warning |'));
    expect(md).toContain('T0 \\| x');
  });

  it('handles a clean pass and a missing report', () => {
    expect(buildSummary({ score: 100, summary: { critical: 0, warning: 0, info: 0, total: 0 }, findings: [] }, { exitCode: 0 })).toContain('gate passed');
    expect(buildSummary(null, { exitCode: 1 })).toContain('did not produce a report');
  });
});

describe('upsertComment', () => {
  const file = path.join(os.tmpdir(), `dr-summary-${process.pid}.md`);
  beforeAll(() => fs.writeFileSync(file, `${MARKER}\nbody`));
  afterAll(() => fs.unlinkSync(file));
  const setup = (existing: any[]) => {
    const github: any = {
      paginate: jest.fn().mockResolvedValue(existing),
      rest: { issues: { listComments: {}, createComment: jest.fn(), updateComment: jest.fn() } },
    };
    const context = { payload: { pull_request: { number: 5 } }, repo: { owner: 'o', repo: 'r' } };
    return { github, context, core: { warning: jest.fn() } };
  };
  it('creates when no marker comment exists', async () => {
    const s = setup([{ id: 1, body: 'other' }]);
    await upsertComment(s, file);
    expect(s.github.rest.issues.createComment).toHaveBeenCalledTimes(1);
    expect(s.github.rest.issues.updateComment).not.toHaveBeenCalled();
  });
  it('updates the existing sticky comment', async () => {
    const s = setup([{ id: 9, body: `${MARKER} old` }]);
    await upsertComment(s, file);
    expect(s.github.rest.issues.updateComment).toHaveBeenCalledWith(expect.objectContaining({ comment_id: 9 }));
    expect(s.github.rest.issues.createComment).not.toHaveBeenCalled();
  });
});
