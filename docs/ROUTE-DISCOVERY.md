# Route discovery (on by default, nothing guessed)

The live tests request a path only when there is evidence for it: the code defines it, a spec on disk declares it, or the running app itself advertises it. Anything else is never requested unless you opt in to the [common-path probe](COMMON-PATH-PROBE.md).

## OpenAPI/Swagger from disk

DeployReady reads `openapi.{json,yaml,yml}` and `swagger.{json,yaml,yml}` from your project (at most 5 files of 2 MB each, respecting `.gitignore`; no request is involved) and treats every `method + path` in them as a route, so it works for stacks that have no code parser. A Swagger 2 `basePath`, or an OpenAPI 3 `servers[0].url` that is a relative path or a loopback URL, is used as the prefix; a production hostname's path is not trusted. A spec operation counts as guarded when it has a non-empty `security` (or the spec has a global one). Block-style YAML is supported; flow-style YAML it cannot read is skipped with an info line. Paths with parameters and non-GET operations are listed as "could not check", never requested.

## Advertised links

From responses the scan already fetched from discovered or spec-declared routes, DeployReady follows what the app itself advertises: same-origin `<a href>` and `<link href>`, `Link:` headers with `rel` `sitemap`, `service-desc` or `describedby`, and OpenAPI documents served by an advertised path. `robots.txt` and `sitemap.xml` are read only if your project has such a file in a static folder (`public/`, `static/`, `www/`, `dist/`, project root) or a response or route points at them; they are never requested on a hunch. Limits: one level deep, at most 25 new GET paths per scan, no static assets, no other hosts, no `mailto:`/`javascript:`/`#`, and no link whose path contains logout, signout, delete, remove, destroy, unsubscribe, revoke, reset or cancel as a whole word. With no discovered route there is no page to read links from, so nothing is requested. Use `--verbose` to see why each path was requested (`advertised by GET /x (link)`).
