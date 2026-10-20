/** Join a mount prefix and a route path into a single normalized URL path. */
export function joinPath(base: string, sub: string): string {
  let combined = `${base || ''}/${sub || ''}`.replace(/\/{2,}/g, '/');
  if (combined.length > 1) combined = combined.replace(/\/$/, '');
  if (!combined.startsWith('/')) combined = `/${combined}`;
  return combined;
}

/** Key for comparing routes from different sources: parameter syntaxes (`:id`, `{id}`, `<id>`, `[id]`) all collapse to `{}`. */
export function normalizeRoutePath(p: string): string {
  const joined = joinPath('', p);
  return joined
    .split('/')
    .map((seg) => (/^(:[^/]+|\{[^/]*\}|<[^/]*>|\[[^/]*\])$/.test(seg) ? '{}' : seg))
    .join('/');
}
