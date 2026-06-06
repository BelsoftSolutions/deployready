/**
 * Open a local file (e.g. the HTML dashboard) in the OS default application,
 * cross-platform. Detached and best-effort: if no opener exists (headless/CI),
 * it fails silently rather than crashing the tool.
 */
import { spawn } from 'child_process';

export function openInBrowser(target: string): void {
  // The target is a tool-generated report path; strip any quote chars defensively.
  const safe = target.replace(/"/g, '');
  const cmd =
    process.platform === 'win32'
      ? `start "" "${safe}"`
      : process.platform === 'darwin'
        ? `open "${safe}"`
        : `xdg-open "${safe}"`;

  try {
    const child = spawn(cmd, { shell: true, detached: true, stdio: 'ignore' });
    child.on('error', () => {
      /* no opener available — ignore */
    });
    child.unref();
  } catch {
    /* ignore — opening is a convenience, never fatal */
  }
}
