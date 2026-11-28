/**
 * Path confinement for the MCP server. Every `path` tool argument must resolve (after following
 * symlinks) to the server's root or a directory inside it. An agent, or text in a scanned repo that
 * steers the agent, cannot point a tool at another project, a parent directory, or a symlink escape.
 */
import * as fs from 'fs';
import * as path from 'path';

export class PathOutsideRootError extends Error {}

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** Real path of the server root. Throws if it does not exist or is not a directory. */
export function realRoot(root: string): string {
  const real = fs.realpathSync(path.resolve(root));
  if (!fs.statSync(real).isDirectory()) throw new Error(`MCP server root is not a directory: ${root}`);
  return real;
}

/**
 * Resolve a tool's `path` argument against the (already real) server root. Relative paths are
 * relative to the root; absolute paths are accepted only when they point inside it. Rejects NUL
 * bytes, `..` escapes, absolute paths elsewhere, symlinks that leave the root, and missing paths.
 */
export function confinePath(root: string, p?: string): string {
  if (p === undefined || p === '' || p === '.') return root;
  if (typeof p !== 'string' || p.includes('\0')) throw new PathOutsideRootError('Invalid path argument.');
  const outside = () =>
    new PathOutsideRootError(
      `Refused: path "${p}" is outside the DeployReady MCP server root (${root}). This server only works on that directory and its subdirectories. To scan another project, the user must start a server for it (deployready mcp <dir>).`,
    );
  const abs = path.resolve(root, p);
  if (!isInside(root, abs)) throw outside();
  let real: string;
  try {
    real = fs.realpathSync(abs);
  } catch {
    throw new Error(`Path "${p}" does not exist inside the server root.`);
  }
  if (!isInside(root, real)) throw outside();
  return real;
}
