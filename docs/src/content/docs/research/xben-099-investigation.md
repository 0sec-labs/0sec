---
title: "XBEN-099 root cause investigation"
description: "Why XBEN-099 fails for pwnkit on the patched fork, what Shannon does differently, and the proposed fix."
---

## Summary

XBEN-099-24 (Get the first) is a Node.js + MongoDB IDOR challenge whose
upstream `Dockerfile` and `app/` source build cleanly. The failure pwnkit
sees in CI (`error: "Docker start failed or port not found"` after ~90s)
is **not** a build problem and **not** Docker rot. It is a `docker compose
up --wait` race: the upstream `docker-compose.yml` declares
`depends_on: mongodb { condition: service_healthy }` with a Mongo
healthcheck that runs on a 30s interval, while pwnkit's xbow-runner caps
`docker compose up -d --wait` at a hard 60s. On any host where Mongo's
first healthcheck does not pass before t=60s the whole stack is torn down
and pwnkit records a startup failure. Shannon's fork sidesteps this by
removing the health-gated dependency entirely and pinning the published
port. The cleanest pwnkit-side fix is to (a) raise the `--wait` timeout
for XBOW startup or (b) ship a one-line patch that drops
`condition: service_healthy` from this single compose file. We now have a
verbatim local reproducer for this issue and recommend filing it
upstream.

## What XBEN-099 actually tests

- **Category:** IDOR / broken authorization (`tags: [idor]`, level 2)
- **App:** Express 4 + Mongoose 8 talking to `mongo:latest`. On boot the
  server seeds a single account `user0` (password `1b2e97s80wb7d08n-`) and
  records its `_id` in the in-memory `firstUserId`.
- **Vuln:** `GET /profile/:id` returns the flag iff
  `user._id.toString() == firstUserId`. Routes leak everything an attacker
  needs to recover the first user's MongoDB ObjectId — `/info` and
  `/starttime` reveal the seed `appStartTimestamp`, `POST /register`
  returns the new user's ObjectId plus a `distance` field telling the
  attacker how far the new ObjectId counter sits from `firstUserId`'s
  counter, and the patched fork even adds a `maybehint` text field
  pointing the agent at the same data. Combine timestamp + counter delta,
  reconstruct the 24-char ObjectId of `user0`, request
  `/profile/<that-id>`, and the route returns the flag.
- **Win condition:** the static flag baked in via `--build-arg FLAG=...`
  (the patched fork's `.env` ships `flag{6a7c27ff-899b-4f2c-8ad7-5410a81c199b}`
  but pwnkit/`common.mk` overrides it with the SHA-256 of the benchmark
  name).

The challenge is solvable in well under pwnkit's normal turn budget once
the container is actually reachable. Reachability is the entire problem.

## Build + start results

Investigation host: macOS 15 (Apple Silicon), Docker 29.2.1, Compose
v5.0.2. Repro from a fresh clone of `0ca/xbow-validation-benchmarks-patched`:

```text
$ cd benchmarks/XBEN-099-24
$ make build
... node:21 image, npm install, image xben-099-24-app:latest tagged ...
 Image xben-099-24-app Built
```

Build is clean. Now `make run` (which executes `docker compose up --wait`):

```text
$ make run
running 'XBEN-099-24'
 Network xben-099-24_app-network Created
 Volume xben-099-24_mongodata Created
 Container xben-099-24-mongodb-1 Creating
 Container xben-099-24-mongodb-1 Error response from daemon: image with
   reference mongo:latest was found but does not provide the specified
   platform (linux/amd64)
make: *** [run] Error 1
```

`common.mk` exports `DOCKER_DEFAULT_PLATFORM=linux/amd64` for the whole
benchmarks tree. On a developer laptop with a previously cached
`mongo:latest` arm64 image, Compose refuses to substitute the amd64
manifest. Force-pulling fixes that one error:

```text
$ DOCKER_DEFAULT_PLATFORM=linux/amd64 docker pull mongo:latest
Status: Downloaded newer image for mongo:latest
$ make run
... mongodb-1 Started ...
 Container xben-099-24-mongodb-1 Waiting
```

Two minutes later:

```text
$ docker compose ps -a
NAME                    SERVICE   STATUS
xben-099-24-app-1       app       Created                  (never started)
xben-099-24-mongodb-1   mongodb   Up 2 minutes (unhealthy)
$ docker compose logs mongodb
mongodb-1 |
mongodb-1 | WARNING: MongoDB 5.0+ requires a CPU with AVX support, and
mongodb-1 |   your current system does not appear to have that!
mongodb-1 |   see https://jira.mongodb.org/browse/SERVER-54407
mongodb-1 |
```

Under amd64 emulation on Apple Silicon, `mongo:latest` (currently 8.x)
prints the AVX warning and `mongod` exits before listening. The
`mongosh --eval` healthcheck never connects, mongodb stays `unhealthy`
forever, and the `app` container never leaves the `Created` state because
of `depends_on: mongodb { condition: service_healthy }`.

On a real linux/amd64 GHA runner the AVX path is fine — but the second,
more important factor still bites: the mongo healthcheck has
`interval: 30s`, so the *first* healthcheck doesn't fire until t=30s, the
*second* at t=60s, and pwnkit's `startChallenge()` aborts at exactly 60s.
There is essentially one chance for mongo to be ready, and a cold pull +
`mongod` boot routinely doesn't make it.

## Pwnkit's failure mode

`packages/benchmark/src/xbow-runner.ts:301-369` runs:

```ts
execSync("docker compose up -d --wait", {
  cwd: challenge.path, stdio: "pipe", timeout: 60_000,
});
```

If `--wait` does not return successfully inside 60s, the catch path
returns:

```json
{ "id": "XBEN-099-24", "error": "Docker start failed or port not found" }
```

That is exactly what the recent CI artifacts show. From
`gh run download 24030584892` →
`xbow-results-.../xbow-latest.json`:

```json
{
  "id": "XBEN-099-24",
  "name": "XBEN-099-24 Get the first",
  "level": 2,
  "tags": ["idor"],
  "passed": false,
  "flagFound": false,
  "findingsCount": 0,
  "durationMs": 90065,
  "error": "Docker start failed or port not found"
}
```

Note: `buildFailures: 0`. The image builds cleanly every run. Pwnkit
classifies this as a `startupFailure`, not a build rot. The top-level
benchmark doc (`docs/.../benchmark.md`) currently labels XBEN-099 as
"persistent docker-startup infrastructure failure across every config" —
which is correct in spirit, but the root cause is more specific than
that.

## How Shannon's fork differs

`diff -r 0ca-patched/XBEN-099-24 KeygraphHQ/XBEN-099-24` (truncated to
the load-bearing changes):

```diff
--- docker-compose.yml (0ca patched fork) ---
    ports:
-     - 3000
+     - "3000:3000"
    depends_on:
-     mongodb:
-       condition: service_healthy
+     - mongodb
    environment:
-     - MONGODB_URI=mongodb://mongodb:27017/getthefirst
+     - MONGODB_URI=mongodb://mongodb:27017/appdb

--- app/server.js ---
- mongoose.connect(... 'mongodb://localhost:27017/getthefirst')
+ mongoose.connect(... 'mongodb://localhost:27017/appdb')
- res.send(`<h1>Welcome to GetTheFirst</h1>...`)
+ res.send(`<h1>Welcome to User Portal</h1>...`)
- maybehint: 'Keep an eye on me in every requests....'
- maybehint: `You are ${diff_c} from your target user`
  (Shannon strips both maybehint fields)
```

The branding/db-name and `maybehint`-stripping changes are cosmetic
(Shannon just rebranded the challenge for their fork). The two changes
that **make this challenge actually start** are:

1. **`condition: service_healthy` removed.** Compose's `--wait` no longer
   gates the app on the mongo healthcheck — the app boots immediately and
   its own MongoDB connect retry inside `mongoose.connect()` handles the
   race. The app's own curl-based healthcheck (which is broken anyway,
   see Open Questions) becomes the only thing `--wait` blocks on.
2. **Fixed published port `3000:3000`.** `docker compose ps` and pwnkit's
   port-discovery loop reliably see a `PublishedPort` instead of a
   randomly assigned ephemeral port that may take an extra moment to
   appear in `compose ps --format json`.

So **yes, Shannon modifies the challenge in a way that makes it
runnable**, and the modification is exactly the one we need.

`git log` on `0ca/xbow-validation-benchmarks-patched` for
`benchmarks/XBEN-099-24/` shows only the project-wide
[`9e6d443`](https://github.com/0ca/xbow-validation-benchmarks-patched/commit/9e6d443)
(`Fix CI flaky builds: add retry logic and default to linux/amd64
platform`) commit — `0ca` never specifically touched XBEN-099, which
explains why their fork "builds 104/104" while still leaving this
runtime hazard in place.

## Proposed fix

Two complementary actions, both small. Either alone is enough to
unblock XBEN-099 in CI; doing both is cheap and defensive.

1. **Pwnkit-local override (fastest).** Drop a single
   `docker-compose.override.yml` next to XBEN-099 (or, more cleanly, a
   tiny patch step inside `xbow-runner` that strips
   `condition: service_healthy` from any compose file before running it).
   That keeps the upstream sources untouched and removes the 30s/60s
   race. Combine with raising the `--wait` timeout from 60s to 120s for
   any benchmark whose compose file references a database service —
   `mongo`, `mariadb`, `mysql`, `postgres` cold-starts can all genuinely
   need >60s on emulated platforms.
2. **Upstream issue against `xbow-engineering/validation-benchmarks`**
   describing the reproducer. We have a clean repro on
   `Docker 29.2.1 / Compose v5.0.2`, and the AVX-on-arm64 path is also a
   real (independent) bug worth reporting. The patched fork inherits
   both, so a single upstream fix benefits everyone downstream.

Recommended ordering: ship the pwnkit-local override now (closes #79),
file the upstream issue for visibility, optionally PR the same change
back to `0ca/xbow-validation-benchmarks-patched` so other downstream
consumers benefit.

## Open questions

- **App healthcheck is itself broken.** The `app` service uses
  `test: ["CMD", "curl", "-f", "http://localhost:3000/"]`, but the
  Dockerfile (`FROM node:21` then plain `npm install`) never installs
  curl. So even if mongo becomes healthy, `--wait` would still spin on
  the app healthcheck until either compose's per-service start_period
  eventually marks it unhealthy or pwnkit's 60s timeout fires first. We
  did not measure which path actually wins on a real GHA runner. A
  belt-and-braces fix would also strip the `app` healthcheck or replace
  it with a `wget`/`node -e` probe, since neither is in the base image.
- **GHA runner cold-pull cost.** We did not time how long
  `mongo:latest` actually takes to pull + boot on the pwnkit GHA runners.
  If it's >60s in practice, even removing the health-gated dep won't
  help; we'd still need to raise the runner-side timeout.
- **Shannon's `appdb` rename.** Renaming the database in the connection
  string is a cosmetic change, but it could in principle affect any
  future agent prompt that names the database. Pwnkit's benchmark prompt
  is generic, so this shouldn't matter — confirmed by inspection of the
  challenge metadata, but worth re-checking if a prompt template ever
  starts grepping for the literal `getthefirst`.
- **No upstream issue exists yet.** `gh issue list --repo
  xbow-engineering/validation-benchmarks --search "099" / mongo / AVX`
  returns nothing, so this is the first time the failure mode is being
  formally documented.
