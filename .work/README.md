# `.work/` — local working state

Everything under this directory is **gitignored** (see `.gitignore`'s
`.work/` rule; this `README.md` is the one explicit exception, so the
directory and its purpose stay discoverable in a fresh checkout even though
nothing else in it is tracked). This is the recommended, consolidated home
for anything a fuzzing session produces or downloads locally — target
sources, prepared/instrumented copies, compiled grammars, downloaded specs,
run output, and secrets — as opposed to source code, which lives under
`src/`, `tools/`, `bin/`, and `docs/`.

## Layout

```
.work/
├── targets/     # cloned target repos + fuzz-prep-multi.py's instrumented output
│                #   e.g. .work/targets/bitwarden, .work/targets/bitwarden-prep
├── grammars/    # compile-grammar.sh --out .work/grammars/<name>
├── specs/       # downloaded OpenAPI/Swagger JSON (curl .../swagger.json -o .work/specs/foo.json)
├── runs/        # fuzzer run output
│   ├── crashes/       # -crash-file / -unique-crash-file
│   ├── summaries/     # -summary-file / -report-file
│   └── checkpoints/   # -checkpoint-path
└── secrets/     # auth.identities.json and other credential files -- NEVER commit these
```

None of these subdirectories need to exist ahead of time — create them as
you need them (`mkdir -p .work/targets`, or just point a tool's `--out`/
`-out` flag at a `.work/...` path directly and let it create the directory).

## Why this exists

Before 2026-07-31 this repo's convention was scattered, loose root-level
directories with individual `.gitignore` patterns: `bitwarden_fresh/`,
`bitwarden_fresh_prep/`, `crashes/`, `summaries/`, `grammars/`,
`swagger-bitwarden.json`, `auth.identities.json`, etc. — each pattern added
piecemeal as a new target/workflow needed one. That still works and none of
it was touched by this change (see "Migrating existing local data" below) —
`.work/` is simply the new, consolidated convention for anyone starting
fresh, so a repo root `ls` doesn't accumulate a growing pile of per-target
working directories over time.

## Using it

```bash
# Instrument a target into .work/targets/
python3 bin/fuzz-prep-multi.py --src ~/checkouts/some-target --out .work/targets/some-target-prep --main SomeApi

# Bring it up, grab its swagger spec into .work/specs/
cd .work/targets/some-target-prep && docker compose build && docker compose up -d
curl -s http://localhost:5299/swagger/v1/swagger.json -o ../../specs/some-target-swagger.json

# Compile the grammar into .work/grammars/
cd - && ./bin/compile-grammar.sh .work/specs/some-target-swagger.json --out .work/grammars/some-target

# Keep your auth identities file out of the repo entirely
cp your-real-auth-file.json .work/secrets/auth.identities.json

# Run, writing everything into .work/runs/
go -C src/void build -o /tmp/void ./cmd/void
TARGET_HOST=http://localhost:5299 /tmp/void \
  -grammar .work/grammars/some-target \
  -auth-file .work/secrets/auth.identities.json \
  -crash-file .work/runs/crashes/crashes.jsonl \
  -unique-crash-file .work/runs/crashes/unique.jsonl \
  -summary-file .work/runs/summaries/summary.json \
  -checkpoint-path .work/runs/checkpoints/checkpoint.json \
  -time-budget 60
```

## Migrating existing local data (safe, opt-in — nothing does this for you)

If you have an existing checkout with target directories at the repo root
(`bitwarden_fresh/`, `crashes/`, `summaries/`, `grammars/`, a loose
`auth.identities.json`, etc.) and want to adopt the `.work/` convention,
move them yourself, on your own schedule — **plain `mv`, not `git mv`**,
since none of this is tracked either way:

```bash
mkdir -p .work/targets .work/grammars .work/runs/crashes .work/runs/summaries .work/secrets

# Adjust names to whatever you actually have locally -- these are examples,
# not every directory below will exist in your checkout.
[ -d bitwarden_fresh ]      && mv bitwarden_fresh      .work/targets/bitwarden
[ -d bitwarden_fresh_prep ] && mv bitwarden_fresh_prep .work/targets/bitwarden-prep
[ -d grammars ]             && mv grammars/*           .work/grammars/ 2>/dev/null
[ -d crashes ]               && mv crashes/*            .work/runs/crashes/ 2>/dev/null
[ -d summaries ]             && mv summaries/*           .work/runs/summaries/ 2>/dev/null
[ -f auth.identities.json ] && mv auth.identities.json .work/secrets/
[ -f swagger-bitwarden.json ] && mv swagger-bitwarden.json .work/specs/bitwarden-swagger.json
```

Then update any command you run locally (or a `campaign.yaml`) to point at
the new `.work/...` paths instead of the old root-level ones. Nothing about
the fuzzer's behavior, flags, grammar format, or report format changes —
this is purely about where files live on disk.

**Before moving anything containing real credentials or session tokens**,
double-check it isn't already staged/tracked in git (`git status`,
`git ls-files | grep -F <filename>`) — this repo's own `.gitignore` has
always excluded `auth.identities.json` and friends, but always verify rather
than assume, especially across forks or older clones.
