/**
 * Open a local file (e.g. the HTML dashboard) in the OS default application,
 * cross-platform. Detached and best-effort: if no opener exists (headless/CI),
 * it fails silently rather than crashing the tool.
 *
 * Security: never goes through a shell. The path is passed as a single argv
 * entry, so characters such as `$(...)`, backticks, `&` or quotes in a project
 * path cannot be interpreted as commands. Only existing local files are opened.
 */
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export function openerFor(target: string, platform: NodeJS.Platform = process.platform): { cmd: string; args: string[] } {
  if (platform === 'win32') return { cmd: 'explorer.exe', args: [target] };
  if (platform === 'darwin') return { cmd: 'open', args: [target] };
  return { cmd: 'xdg-open', args: [target] };
}

export function openInBrowser(target: string): void {
  const abs = path.resolve(target);
  try {
    if (!fs.statSync(abs).isFile()) return;
  } catch {
    return; // not a local file — never hand arbitrary strings to an opener
  }
  const { cmd, args } = openerFor(abs);
  try {
    const child = spawn(cmd, args, { shell: false, detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => {
      /* no opener available — ignore */
    });
    child.unref();
  } catch {
    /* ignore — opening is a convenience, never fatal */
  }
}
