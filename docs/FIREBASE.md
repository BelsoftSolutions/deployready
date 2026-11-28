# Firebase checks

DeployReady reads the Firebase files in your project and flags security rules that let the wrong people read or write your data. By default the checks are **static**: they read files on disk, make no network requests, and never talk to your Firebase project. They run on every scan. An opt-in mode, `--firebase-emulator`, additionally proves your Firestore and Storage rules by running them in the official Firebase Emulator Suite on localhost (see below).

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

- **No live checks against your Firebase project.** DeployReady never connects to it, so it cannot tell whether the rules in your repo are the rules deployed to your project, whether anonymous sign-in or open sign-up is enabled, or what an unauthenticated visitor can actually read.
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

## Proving rules with the Firebase Emulator Suite (`--firebase-emulator`)

```
deployready scan . --firebase-emulator
```

Reading rules is not the same as running them. With `--firebase-emulator`, DeployReady starts the Firestore and Storage emulators with **your** `firestore.rules` / `storage.rules`, then sends real requests and records what the rules actually allow.

**Requirements (yours to install; DeployReady never installs anything):** the `firebase` CLI ([firebase-tools](https://github.com/firebase/firebase-tools), MIT licensed) on `PATH` (or `DEPLOYREADY_FIREBASE_BIN=/path/to/firebase`) and Java 11 or newer (21 recommended). On first use firebase-tools itself downloads the emulator jars from Google into its own cache; that is firebase-tools' behaviour, not DeployReady's. If either tool is missing the coverage area `firebase (emulator)` is reported as **untested** with an install hint, and the static results are unchanged.

**What it does**

1. Picks one rules file per service (the one `firebase.json` names, else the shallowest) and builds a test plan from every `match` path: wildcard variables get concrete ids, and the variable the rules compare to the caller becomes the owner's uid.
2. Copies the rules into a temporary directory and starts the emulators bound to `127.0.0.1` on free ports under a throwaway `demo-deployready-*` project id. Nothing is read from or written to your repo, and no credentials are passed to the emulator process.
3. For each path, seeds a minimal document/object as admin (`Authorization: Bearer owner`, an emulator-only bypass), then tries **get, list, create, update, delete** as **anonymous**, **user A (the owner)** and **user B (another signed-in user)** using unsigned emulator tokens, resetting the data before each probe. Create probes set the document's owner fields (the fields your rules mention, default `ownerId`) to A, so a missing ownership check shows up as B creating a document on A's behalf.
4. Stops the emulators and deletes the temp directory. Every request is checked to be plain HTTP to loopback; a real Firebase project is never contacted.

**Results and how they combine with the static checks**

| Emulator result | Static result | Outcome |
| --- | --- | --- |
| Anonymous (or any user) allowed | Flagged | The static finding is kept and gains proof (request, status, response, and the owner's control request) |
| Anonymous allowed | Not flagged | New `firebase-emulator-open-access`, critical for writes, recursive or user-owned paths, else warning: the emulator disagrees with the static reader |
| Signed-in non-owner allowed | Not flagged or flagged lower | New `firebase-emulator-owner-check-missing`, critical when a write is allowed, warning for reads on user-owned paths. Signed-in reads on a shared, non-user path are only an info note (often intended) |
| Everything denied for anonymous and non-owners | Flagged | The static finding becomes an info note, `Not reproduced in the emulator: ...` (for example an expired test-mode rule). It is only downgraded when every probe returned a clear allow/deny |
| Seeding failed or responses were unclear | Any | Path reported as untested/inconclusive; static findings are left alone |

Emulator findings are listed with their file and `allow` line. The coverage area `firebase (emulator)` is `passed` when every path was tested cleanly, `inconclusive` when some paths were skipped or errored (for example a collection-level `match` without a wildcard, or a rules file beyond the first per service), and `untested` when the tools are missing.

**Limits.** Realtime Database rules are not emulated (still static). Probes use the emulators' REST APIs, so rules that depend on custom claims, App Check, `get()`/`exists()` data you did not seed, or field validation can deny every probe (including the owner's); a denial is then not proof of safety, and the report says so only through the control request. At most 40 paths are tested per scan.
