# muster-alerts

A [muster](https://github.com/ZacxDev/muster) plugin that turns **alerts
into muster tasks**.

Point Prometheus Alertmanager (or anything that can send a small JSON
webhook) at it. Each alert group that starts firing becomes one muster task,
handed to your **chief** as "assigned". When the group resolves, an update is
added to that same task. A repeated notification never files a second task.
The plugin rate-limits what it sends, so an alert storm waits in its queue
instead of flooding muster.

**Tested against** muster commit `d8d3dca3e` (main, 2026-11-18): the run in
"Run it in 5 minutes" below, against a throwaway muster with
`MUSTER_PLUGINS=1` and `MUSTER_TASK_ROUTING=1`, with hand-sent Alertmanager
and generic payloads on loopback. A firing group filed one task, routed to the
chief. Its repeat, before and after a restart, filed nothing. A bad secret got
`401` and a malformed body `400`. A "resolved" sent while muster was down
reached the same task once muster came back.

## Run it in 5 minutes

You need Go (the version in `go.mod`) and a muster you can sign in to.

1. **On the muster server**, turn plugins on and name the task namespace this
   plugin files under. In the `.env` beside muster's `docker-compose.yml` add

   ```sh
   MUSTER_PLUGINS=1
   MUSTER_PLUGIN_TASK_NAMESPACES=alert    # add to any list you already have
   MUSTER_TASK_ROUTING=1                  # hands each firing group to your chief
   ```

   and restart muster (`docker compose up -d --wait`).
2. **Create the plugin** on muster's `/plugins` page (name `alerts`, label
   `Alerts`) and copy the `mpl_…` token it shows once.
3. **Configure and start:**

   ```sh
   cp .env.example .env
   # edit .env: MUSTER_URL, MUSTER_PLUGIN_TOKEN, ALERTS_SECRET (openssl rand -hex 32)
   set -a; . ./.env; set +a
   go run .
   ```

   It checks with muster (`GET /plugin/v1/tasks?namespace=alert&live=true`)
   that the namespace is in the server's `MUSTER_PLUGIN_TASK_NAMESPACES`, and
   refuses to start, saying which variable to change, if it is not. Then it
   logs `webhooks on http://127.0.0.1:9095 (/alertmanager, /generic)`.
4. **Send it an alert** (from the same machine):

   ```sh
   curl -s -H "X-Muster-Alerts-Secret: $ALERTS_SECRET" http://127.0.0.1:9095/generic \
     -d '{"id":"disk-db1","status":"firing","title":"Disk 95% full on db1","body":"/var is at 95%"}'
   ```

   It answers `{"accepted":1,…}` and logs
   `event alert:<group>-<start>#firing: task <id> (created true, commented true, routed chief)`.
   Send the same request again: `{"accepted":0,"duplicate":1,…}`. Send it with
   `"status":"resolved"`, and the task gets a "resolved" comment.
5. **Point Alertmanager at it** (`alertmanager.yml`):

   ```yaml
   receivers:
     - name: muster
       webhook_configs:
         - url: http://127.0.0.1:9095/alertmanager
           send_resolved: true
           http_config:
             authorization:
               type: Bearer
               credentials_file: /etc/alertmanager/muster-alerts-secret
   ```

## Security: untrusted text

Alert titles, summaries, descriptions, labels and generic `body` text come
from whatever sends the webhook, and Alertmanager copies them from your
alerting rules and the labels of the targets it scrapes. To this plugin they
are **outside data, never instructions**.

muster, not the plugin, fences plugin-filed task text, so the rule lives in
one place. That is muster PR
[#824](https://github.com/ZacxDev/muster/pull/824), which is **not merged** at
the time of writing; no muster release fences this text yet. Until a release
carrying #824 is out, an agent started on one of these tasks reads the
alert text unfenced.

Released muster can start agents on these tasks without you. With
`MUSTER_TASK_ROUTING=1` (the quickstart above turns it on) each new task is
handed to your chief, and the chief's `agent_dispatch` tool starts an agent on
a task whenever your user id is listed in `MUSTER_CHIEF_DISPATCH_OWNERS`. So,
until #824 ships:

- **Do not list yourself in `MUSTER_CHIEF_DISPATCH_OWNERS`** on the muster that
  this plugin files into.
- **Do not start an agent on these tasks by hand** either: not from a host
  (the host spawn), and not with `POST /api/agents` and the task's `note_id`.

Once a release with #824 is out, the first message an agent gets about the
task is fenced. Its tools may still return the text unfenced: `task_get`
(and `GET /api/tasks`) return the task as stored, on releases without a
follow-up to #824 that fences them too.
<!-- TODO: tighten this section once muster #824 merges: name the release that carries it, and whether task_get / GET /api/tasks are fenced in it. -->

This plugin has no auto-start switch of its own. muster PR
[#821](https://github.com/ZacxDev/muster/pull/821) would add per-plugin
auto-start on the plugin's card on `/plugins`; it is not merged, so no released
muster has that switch.

Every firing alert group becomes a task routed to your chief. Consider a
lower `ALERTS_MAX_PER_HOUR` than the default 60 (say `12`) if your alerts are
noisy: past it, alerts wait in the outbox instead of reaching your chief at
once.

## Configuration

Read from the environment only; `.env.example` lists them.

| variable | required | meaning |
|---|---|---|
| `MUSTER_URL` | yes | muster's address. `https://`, or `http://` to `localhost`, `127.0.0.1` or `[::1]` only; the address alone |
| `MUSTER_PLUGIN_TOKEN` | yes | the `mpl_…` token from `/plugins`. Never logged |
| `ALERTS_SECRET` | yes | the shared secret, at least 16 characters. Never logged |
| `ALERTS_LISTEN` | no | `host:port` to serve on; default `127.0.0.1:9095` (the Docker image sets `0.0.0.0:9095`: leave it unset there) |
| `ALERTS_ALLOW_NON_LOOPBACK` | no | `1` to allow a non-loopback `ALERTS_LISTEN`. The webhook is plain HTTP: use it only behind TLS or on a private network. Never set in the image: the container needs `-e ALERTS_ALLOW_NON_LOOPBACK=1` (see "Docker") |
| `ALERTS_TASK_NAMESPACE` | no | the task key namespace, default `alert`. It must be in the server's `MUSTER_PLUGIN_TASK_NAMESPACES` |
| `ALERTS_MAX_PER_HOUR` | no | requests to muster per hour, default `60`; lower it for a noisy Alertmanager |
| `ALERTS_BURST` | no | requests to muster at once before the hourly rate applies, default `10` |
| `ALERTS_MAX_PENDING` | no | events waiting for muster past which a **new** alert is answered `503`; default `500` |
| `STATE_DIR` | no | where the outbox and the open episodes live; default `./state` (the Docker image sets `/state`: leave it unset there) |

## The webhooks

Every request needs the secret, as `X-Muster-Alerts-Secret: <secret>` or
`Authorization: Bearer <secret>` (Alertmanager's `http_config.authorization`).
It is compared in constant time. A missing or wrong secret is `401`, checked
before the body is read. A body over 1 MiB is `413`.

**`POST /alertmanager`** takes Alertmanager's webhook body (version `"4"`)
as it is. It needs `groupKey`, `status` (`firing` or `resolved`) and at least
one alert with a `status` and `startsAt`.

**`POST /generic`** takes one object, for any other sender:

```json
{"id": "backup-nightly", "status": "firing", "title": "Nightly backup failed",
 "body": "exit 1", "url": "https://ci.example.com/run/7",
 "started_at": "2026-11-18T09:00:00Z", "labels": {"team": "ops"}}
```

| field | rule |
|---|---|
| `id` | required: 1-200 bytes, no control characters. The alert's stable identity: one alert group |
| `status` | required: `firing` or `resolved` |
| `title` | required when firing |
| `body`, `url`, `labels` | optional; shown in the task |
| `started_at` | optional, RFC 3339: when this firing started. Without it, the plugin starts the episode when it first hears the alert firing and ends it at `resolved` |

Unknown fields are refused (`400`), so a typo is not silently ignored.

| answer | meaning |
|---|---|
| `200 {"accepted": 1, "event_id"}` | recorded durably (fsynced) before the answer; it will reach muster |
| `200 {"duplicate": 1, "event_id"}` | a repeat of an event already recorded: nothing new |
| `200 {"accepted": 0, "note"}` | a `resolved` for nothing the plugin knows was firing |
| `400 {"error"}` | malformed: the same body will never be accepted |
| `401` | bad or missing secret |
| `503` + `Retry-After: 60` | `ALERTS_MAX_PENDING` events are still waiting for muster; send it again later (Alertmanager does) |

`GET /healthz` needs no secret and answers `{"ok": true}`. With the secret
(either header) it also says how many events wait for muster:
`{"ok": true, "pending": <n>}`.

## What it files

One **task per firing episode of an alert group**. An Alertmanager group is
its `groupKey`; a generic alert is its `id`. The episode starts at the
earliest `startsAt` of the group's firing alerts. The task key is
`alert:<group>-<start>`: `<group>` is 16 hex characters of the sha256 of the
group key, and `<start>` is the episode's start in Unix seconds.

| notification | to muster (`POST /plugin/v1/tasks`) | event id |
|---|---|---|
| firing | a task: title `[FIRING] <alertname> (<severity>): <group labels>`; body = the receiver, group key and Alertmanager link first, then the summary, common labels, up to 20 alerts with their labels, start and source link (a generic alert: its id, link, start and labels first, then its `body`), trimmed to about 15 KiB with a `[trimmed: …]` marker; `route_to_chief`, `notice: assigned` | `<key>#firing` |
| resolved | a comment on that task: when the last alert ended; `notice: update` | `<key>#resolved` |

The comment starts with the event id in brackets. muster adds a comment once
per text, keeps one open task per key, and names the routed event by key and
comment. The plugin's outbox (`STATE_DIR/outbox.jsonl`) refuses an event id it
already holds. So a repeat notification (Alertmanager's `repeat_interval`, a
new alert joining the group, a retry after a lost answer) is answered
`duplicate` and sends muster nothing.

**The episode stays on one key** while the group keeps firing, even after its
earliest alert resolves: the plugin remembers the episode
(`STATE_DIR/episodes.json`), and it continues as long as some alert firing now
started no later than the last notification. A group that went quiet without
a `resolved` (`send_resolved: false`) starts a new episode, and a new task,
the next time it fires. So does a group that fires again after it resolved.
If that re-fire carries the **same** start as the resolved episode (a generic
sender resending its `started_at`, or an Alertmanager alert that flaps back
with its original `startsAt`), the key gets a re-fire count,
`alert:<group>-<start>-r1`, then `-r2`, so it is still a new task and not taken
for a repeat.

That has a cost, by design: the plugin cannot tell a real re-fire with the same
start from a **late replay** of the episode's earlier "firing" notification
that arrives after its "resolved" (a retry the sender delayed). Both file a
`-r1` task. A spurious task you can see and close is the better failure than a
real re-fire that is silently lost as a "duplicate".

muster keeps at most 16 KiB of a task body and cuts from the
end, which is why the body puts what names the alert first.

This plugin files **copy** tasks (`create` and `comment`), not task
references, so it sends no `event_id` (muster accepts that field only on a
reference). The "resolved" update is a comment on the same task, which copy
tasks support directly.

## What it does on each answer from muster

| answer | the plugin |
|---|---|
| `201` / `200` | marks the event delivered |
| `400` | logs it and drops it: the same request can never be accepted |
| `409` | logs it and marks it delivered: the task is filed, but muster will not route this event, and sending it again cannot help |
| `429` | waits `Retry-After`, then sends the **same** request again |
| `503`, other `5xx`, no answer | waits (`Retry-After` if given, else 5 s doubling to 5 min) and sends it again; the event stays in the outbox, so a restart keeps it |
| `401`, `403`, `404` | stops: the token is revoked or lacks `messages`, or plugins are off on that server |

Events go to muster one at a time, oldest first, at most `ALERTS_BURST` at
once and `ALERTS_MAX_PER_HOUR` an hour. The outbox stores the exact request,
so a retry sends the same bytes.

## Token scope

The plugin token's default `messages` capability. It opens muster's
`/plugin/v1/*` routes and nothing else, acting as you. This plugin calls three
of them: `GET /plugin/v1/self` and `GET /plugin/v1/tasks` (once each, at
startup) and `POST /plugin/v1/tasks`. Revoke it on
`/plugins` at any time; the plugin then stops at its next call. The plugin
holds no other credential: the shared secret only authenticates senders to
the plugin.

## Telemetry: none

The plugin talks only to the muster at `MUSTER_URL`, and answers only the
webhooks sent to `ALERTS_LISTEN`.

## Docker

```sh
docker build -t muster-alerts .
docker run -d --env-file .env -e ALERTS_ALLOW_NON_LOOPBACK=1 \
  -p 127.0.0.1:9095:9095 -v muster-alerts-state:/state muster-alerts
```

The image sets `ALERTS_LISTEN=0.0.0.0:9095` (the container's own loopback is
unreachable from outside it) and `STATE_DIR=/state`. It does **not** set
`ALERTS_ALLOW_NON_LOOPBACK`, so the plugin refuses to start until you pass
`-e ALERTS_ALLOW_NON_LOOPBACK=1` yourself.

> **Warning.** `ALERTS_ALLOW_NON_LOOPBACK=1` says the plain-HTTP webhook may
> listen beyond loopback. Inside the container that is needed, and it is safe
> only because `-p 127.0.0.1:9095:9095` publishes it on the **host's**
> loopback. Publish it as `-p 9095:9095` (every interface) only on a private
> network or behind a TLS proxy: the secret travels in clear text.

The `.env` for Docker holds the secrets and leaves `ALERTS_LISTEN`,
`ALERTS_ALLOW_NON_LOOPBACK` and `STATE_DIR` out. Set in an `--env-file`, those
would override the image: `ALERTS_LISTEN=127.0.0.1:9095` makes the container
listen on its own loopback, which `-p` cannot reach, and `STATE_DIR=./state`
puts the state outside the volume. `.env.example` already leaves them
commented out. A Docker `.env`:

```sh
MUSTER_URL=https://muster.example.com
MUSTER_PLUGIN_TOKEN=mpl_replace_me
ALERTS_SECRET=replace_me_with_a_long_random_secret
ALERTS_TASK_NAMESPACE=alert
ALERTS_MAX_PER_HOUR=12
```

`MUSTER_URL` must be reachable from inside the container: `http://localhost`
there is the container itself. Use muster's `https://` address.

## Not done yet

- **An update when the group's alert set changes mid-episode** (an alert
  joins or leaves): today that is a duplicate of the episode's firing event.
- **Closing the task on resolve.** A copy task is closed in muster, by you or
  an agent. A plugin can complete only a task *reference*, and a reference
  sends every write on the task to the plugin, which Alertmanager has no API
  to apply.
- **TLS** on the listener: put it behind a proxy, or keep it on loopback.

## Layout

| path | what |
|---|---|
| `main.go` | reads the environment, serves the webhooks, runs delivery |
| `internal/alerts` | the webhook server, the two payload formats, the episodes |
| `internal/outbox` | the durable event outbox: the dedupe, and delivery across restarts |
| `internal/deliver` | delivers the outbox to muster, with the retry rules and the rate limit |
| `internal/muster` | the client for muster's plugin routes |
| `internal/mustertest` | a fake muster for tests (`httptest`), answering as muster does |

## Tests

```sh
go test -race ./...
```

They run against the fake muster with Alertmanager payloads built in the test
and cover: muster down, `429`, `503`, `409`, `400`, a revoked token, a
repeated notification, a restart before delivery and in the middle of a batch,
a bad or missing secret (also with an oversize body: `401`, not `413`),
malformed and oversize payloads, resolved updates, re-firing (including with
the same start after a resolve), episode continuity, long bodies, `/healthz`
without the secret, the namespace check, the generic format, a storm past
`ALERTS_MAX_PENDING`, the rate limit, byte-identical retries, and that no
request carries `event_id`. CI runs gofmt, `go vet`, `go test -race`,
`govulncheck` and gitleaks (history and tree, `.gitleaks.toml`).

## Licence

MIT. See [LICENSE](LICENSE).
