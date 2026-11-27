# Firebase checks

DeployReady reads the Firebase files in your project and flags security rules that let the wrong people read or write your data. This release is **static only**: it reads files on disk, makes no network requests, and never talks to your Firebase project. The checks run on every scan; there is no flag to enable them.

## What is checked

| Rule id | Severity | Fires on |
| --- | --- | --- |
| `firebase-rules-open` | critical | `firestore.rules` / `storage.rules`: `allow ...: if true;` or an `allow` with no condition that includes a write, or any open `allow` on a recursive wildcard (`{document=**}`, `{allPaths=**}`) |
| `firebase-rules-open-read` | warning | Open read-only `allow` on a specific path (fine for a public catalogue, a leak for anything else) |
| `firebase-rules-test-mode` | critical (warning once expired) | The console's test-mode rule, `request.time < timestamp.date(Y, M, D)`: "open to everyone until <date>" |
| `firebase-rules-auth-only` | critical for writes, warning for reads | A user-owned path (`/users/{userId}`, `/orders/{id}`, `/messages/{id}`, `users/{uid}/...` in Storage, and similar) gated only by `request.auth != null`, with no comparison of `request.auth.uid` to the path variable or an owner field such as `resource.data.userId` |
| `firebase-rules-recursive-wildcard` | critical | A recursive wildcard that only requires sign-in. Anyone can sign up, so this is open to the internet |
| `firebase-rtdb-open` | critical (warning for a narrow public `.read`) | `database.rules.json`: `".read"` / `".write"` set to `true` at the root, at a `$wildcard`, or `.write: true` anywhere |
| `firebase-rtdb-test-mode` | critical (warning once expired) | `".read": "now < <epoch ms>"` |
| `firebase-rtdb-auth-only` | warning | `".read"` / `".write"` of `auth != null` only |
| `firebase-service-account-committed` | critical | A JSON file containing `"type": "service_account"` and a `private_key`, unless a root `.gitignore` rule ignores it. The key is never printed |
| `firebase-no-rules-file` | info (not scored) | `firebase.json` / `.firebaserc` present but no rules file in the repo, so deployed rules could not be checked |

Details:

- **Rules parsing.** A small tolerant scanner reads `match` nesting, `allow` statements and simple one-line helper functions (`function isOwner(id) { return request.auth.uid == id; }`), which are inlined before the condition is judged. Comments are ignored. Syntax it does not understand is skipped rather than failing the scan.
- **Conditions it judges.** `true`, no condition, sign-in-only (`request.auth != null`, `isSignedIn()`-style helpers, verified email) and the test-mode date check, combined with `&&` / `||`. Any other condition (owner comparison, custom claims, field validation, `get()`/`exists()` lookups) counts as a real restriction and is not flagged.
- **Findings** carry the file and line, redacted evidence, and a recommendation with a corrected rule example.
- **Files found.** `*.rules`, `database.rules.json` (also `*.database.rules.json`), `firebase.json`, `.firebaserc`, and other `*.json` files under 256 KB (for service account keys), anywhere in the project except `node_modules`, build output and dot-directories.

## What is not flagged on purpose

The Firebase **web config** (`apiKey`, `authDomain`, `projectId`, `appId`, ...) is public by design: it ships in every client, and access is enforced by your security rules, not by hiding it. The Firebase module never reports it. (If another DeployReady rule reports `apiKey: "AIza..."` as a hardcoded secret, that is a false positive from the general secret scanner; the benchmark case `firebase/web-config-apikey-tn` tracks it.) Restrict the key by HTTP referrer in Google Cloud Console if you want defense in depth.

## What is not checked

- **No live checks.** DeployReady does not connect to Firebase, so it cannot tell whether the rules in your repo are the rules deployed to your project, whether anonymous sign-in or open sign-up is enabled, or what an unauthenticated visitor can actually read.
- Rules that exist only in the Firebase console and not in the repo (see `firebase-no-rules-file`).
- Deep rule semantics: `get()` / `exists()` cross-document logic, custom claims correctness, field-level validation, rate limits, and per-method differences beyond the checks above.
- Rules in another language or format (Terraform, generated files), and rules files over 1 MB.
- Cloud Functions, App Check, Auth settings, and Firebase Hosting configuration.
- Service account keys outside JSON files, or files ignored by a nested `.gitignore` only. A key in git history is not detected: if one was ever committed, rotate it.

## Example fix

```
match /users/{userId} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
```
