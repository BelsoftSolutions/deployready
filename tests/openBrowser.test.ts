import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const spawnMock = jest.fn(() => ({ on: jest.fn(), unref: jest.fn() }));
jest.mock('child_process', () => ({ spawn: (...a: unknown[]) => (spawnMock as any)(...a) }));

import { openInBrowser, openerFor } from '../src/utils/openBrowser';

describe('openInBrowser', () => {
  beforeEach(() => spawnMock.mockClear());

  it('passes a hostile path as one argv entry and never uses a shell', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dr-open-'));
    const file = path.join(dir, 'report $(touch pwned) `id` & x".html');
    fs.writeFileSync(file, '<html></html>');
    openInBrowser(file);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [, args, opts] = spawnMock.mock.calls[0] as unknown as [string, string[], { shell: boolean }];
    expect(args).toEqual([file]);
    expect(opts.shell).toBe(false);
  });

  it('refuses anything that is not an existing local file', () => {
    openInBrowser('https://example.com/$(id)');
    openInBrowser('/definitely/missing/file.html');
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it('uses argv-only openers on every platform', () => {
    expect(openerFor('/x', 'win32')).toEqual({ cmd: 'explorer.exe', args: ['/x'] });
    expect(openerFor('/x', 'darwin')).toEqual({ cmd: 'open', args: ['/x'] });
    expect(openerFor('/x', 'linux')).toEqual({ cmd: 'xdg-open', args: ['/x'] });
  });
});
