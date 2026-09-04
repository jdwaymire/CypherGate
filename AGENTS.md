# Driving CypherGate

*For an agent. Read this before touching the sessions. Human documentation is in
[`README.md`](README.md); the full route-by-route API reference, with response
shapes and error codes, is in [`API.md`](API.md).*

The owner keeps SSH sessions open in a browser at <http://127.0.0.1:8765>.
**You share those sessions** — what you run appears in their terminal as it
happens, and they can type into the same shell. Sessions are theirs, not yours.

## Two rules that matter

**You cannot unlock the server.** The master password is given in the browser,
so the process *can* start headless — but it binds in a locked state where every
route except `/api/state` and `/api/unlock` returns **423**, and no token file is
written until the owner unlocks it. Starting it therefore accomplishes nothing on
its own. If a change to `server.py` needs to take effect, *ask them to restart
it* and say why — do not start or restart it yourself.

A **423** means exactly this: the server is up but nobody has given the password
yet. Ask the owner to unlock it in the browser; do not treat it as a bug or retry
in a loop.

**A session costs a physical security-key touch to open, and nothing
thereafter.** So:

- **Never ask for a restart lightly** while sessions are open: it kills every one
  of them, and each costs a touch to rebuild, on top of re-entering the master
  password.
- **Do not open sessions speculatively.** Creating one makes the owner's key
  blink until they tap it. If you need a host that is not open, ask them to open
  a tab.
- Reuse what is already open. Check first, every time.

## Getting the token

Every `/api/*` call needs `X-Token`. It is regenerated at each server start,
written only after the master password is accepted, and deleted when the server
exits:

```bash
TOKEN=$(cat "state/$COMPUTERNAME/token")          # from the project folder
B=http://127.0.0.1:8765
```

**No token file means the server is not running *or is still locked*.** The file
is written the moment the master password is accepted, so its presence means the
console is up *and* usable. Ask the owner to start or unlock it; do not try to
start it yourself, and do not treat its absence as a bug.

## What is open right now

```bash
curl -s -H "X-Token: $TOKEN" $B/api/sessions
```

Returns a list with `name`, `kind`, `host`, `target`, `alive`, `rows`/`cols`,
`uptime` and the transcript path. The `name` is how you address a session — the
owner refers to them the same way.

**Two kinds of tab share this list.** `kind: "shell"` is a terminal.
`kind: "transfer"` is a file-transfer tab named `<host>-xfer`, and the shell
routes below refuse it with a 400 that says so. Check `kind` before assuming a
tab can run a command.

The browser polls this endpoint every four seconds, so a session you open appears
in the owner's window on its own — no reload needed, and no need to tell them to
refresh.

## Running a command

```bash
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01/run \
     -d '{"cmd":"uptime","timeout":30}'
# {"ok": true, "exit_code": 0, "timed_out": false, "output": " 14:07:53 up 200 days..."}
```

`/run` blocks until the command finishes and returns **only that command's
output** plus its exit code. Prefer it over `/exec`. It types the command exactly
as a human would, so the terminal shows no machinery.

**Quote carefully.** Building JSON in a shell one-liner breaks on nested quotes
and has wedged a session before. For anything with quotes, write the body with
Python and post the file:

```bash
python - > /tmp/cmd.json <<'PY'
import json; print(json.dumps({"cmd": "free -m | awk 'NR==2{print $3\"/\"$2}'"}))
PY
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01/run --data-binary @/tmp/cmd.json
```

Long jobs: raise `timeout` (seconds). `apt upgrade` wants 600+.

## Your commands are marked as yours

Everything you send is **labelled on the owner's screen and in the transcript**.
A `/run` or `/batch` gets an ochre bar behind the command and its output, and a
`--- api <timestamp> ---` delimiter in the log; `/input` gets the delimiter only.
What the owner types stays unmarked.

You do not have to do anything to make this happen and you cannot switch it off.
Two consequences worth holding on to:

- **The owner can see exactly what you did, and when.** Write commands you would
  be content to have read back to you.
- **Never describe one of your commands as something they ran, or theirs as
  yours.** The transcript settles it either way.

It exists because a session is shared: a command you send is echoed by the pty
exactly like a typed one, and when it lands mid-word it used to look like pty
corruption. If the owner asks why the terminal looks strange, the marks are the
first thing to read.

## Running several commands

**Use `/batch` rather than looping over `/run`.** Pass a list, get one result per
command back, each tagged with the `cmd` it came from:

```bash
python - > /tmp/b.json <<'PY'
import json
print(json.dumps({"cmds": ["hostname", "uptime", "df -h /"], "timeout": 45}))
PY
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01/batch --data-binary @/tmp/b.json
```

Two things a loop does not give you:

- The session is **held for the whole sequence**, so nothing — another caller, or
  the owner's keyboard — can land a command between two of yours.
- Commands travel as JSON array elements and never touch a shell on the way in,
  which is the quoting hazard above, gone.

`stop_on_error: true` stops at the first non-zero exit or timeout; `ran` and
`requested` in the reply say how far it got. Cap is 100 commands, because a batch
holds the session for its whole run.

## When output is too long

`/run` and `/batch` results carry `truncated`. If it is `true`, the command
produced more than the 2 MB in-memory window and **what you got back is missing
the front of it** — `lost_bytes` says how much, and `log` gives the transcript
path that still has all of it. Do not report a truncated result as though it were
the whole answer; read the log, or re-run with something narrower like
`| tail -200`.

## Reading and typing directly

| Need | Call |
|---|---|
| several commands at once | `POST /api/sessions/<name>/batch` `{"cmds":[...]}` |
| transcript from an offset | `GET /api/sessions/<name>/text?since=<n>` |
| raw keystrokes | `POST /api/sessions/<name>/input` `{"data":"...","b64":true}` |
| Ctrl-C (rescue a stuck shell) | `input` with `{"data":"Aw==","b64":true}` |

`/run` and `/batch` strip the shell's echo of the command by dropping the first
line, and that is correct however long the command is: readline wraps a long line
visually and puts no break in the stream.

**A multi-line `cmd` is refused.** Bash echoes a continuation prompt for each
extra line, and those used to land at the front of `output` — `> do`, `> done`,
and so on — which is a wrong answer that looks like a right one. `/run` and
`/batch` reject any `cmd` containing a newline or carriage return before anything
reaches the shell, and say so. Send one command per call, or pass the list to
`/batch`, which is what it is for.

If a command hangs or the shell ends up at a `>` continuation prompt, send Ctrl-C
through `/input` before doing anything else. It lands in the transcript as
`--- api sent keystrokes ---`; there is no bar for it, because two bytes have no
command boundary to bracket. Do not pass `{"source":"keyboard"}` to dodge the
mark — that field exists for the browser to identify real typing, and using it
would make your Ctrl-C look like the owner's.

## Files

Transfers ride the open session, so they cost **no touch**. Cap is 64 MB
(`max_inline`), and it applies **both ways** — a download over it is refused by
the remote before anything is encoded, with a 413-style error naming the limit.
Use a transfer tab's `pull`/`push` for anything bigger: those stream through a
file on disk and have no ceiling.

```bash
POST /api/sessions/<name>/download  {"path":"/etc/caddy/Caddyfile"}   -> {"b64": ...}
POST /api/sessions/<name>/upload    {"path":"/tmp/x","b64":"..."}
```

Both directions compress where the remote has `gzip`, and both checksum the real
bytes. The reply carries `verified`, `algorithm`, `compressed` and `size` (the
*uncompressed* size). A checksum mismatch fails the call outright rather than
handing back bad data.

**If `verified` is `false`, the transfer was not checked** — the remote had no
`md5sum` or `sha256sum`. The bytes are probably fine, but say so rather than
calling it verified.

## Transfer tabs

For anything more than a file or two — browsing, several files, a directory
listing — there is a second kind of tab. **It is a separate connection, so
opening one costs a key touch.** Ask first, exactly as you would before opening a
shell session.

```bash
POST /api/sessions            {"name":"web-01","kind":"transfer"}   -> web-01-xfer
POST /api/sessions/web-01-xfer/ls     {"path":"/etc"}   # name,dir,link,size,mtime,mode
POST /api/sessions/web-01-xfer/cd     {"path":"/tmp"}
POST /api/sessions/web-01-xfer/get    {"path":"nginx.conf"}      -> {"b64": ...}
POST /api/sessions/web-01-xfer/put    {"path":"x.conf","b64":"..."}
POST /api/sessions/web-01-xfer/mkdir  {"path":"newdir"}
POST /api/sessions/web-01-xfer/rm     {"path":"x.conf"}
POST /api/sessions/web-01-xfer/mv     {"from":"a","to":"b"}
DELETE /api/sessions/web-01-xfer                     # closes the connection
```

Relative paths resolve against the tab's `cwd`. Paths never pass through a shell
here, so spaces and quotes need no escaping — it is a binary protocol, not a
command line.

## Copying to and from this machine

The transfer tab has a second half: the local disk, listed by the server because
a browser cannot read the disk it runs on. These need no key touch beyond the tab
itself.

```bash
POST /api/local/ls     {"path":"C:/Users/you"}    # cwd, parent, drives, machine, entries
POST /api/local/mkdir  {"path":"..."}
POST /api/local/rm     {"path":"..."}             # non-recursive, same as the remote
POST /api/local/mv     {"from":"...","to":"..."}

POST /api/sessions/web-01-xfer/pull  {"remote":"/etc/hosts","local":"C:/tmp/hosts"}
POST /api/sessions/web-01-xfer/push  {"local":"C:/tmp/x","remote":"/tmp/x","recursive":true}
```

**Prefer these over `get`/`put` whenever the file is going to or coming from
disk.** They move the bytes server-side rather than base64 through the reply, so
there is no size cap and they measured about twice as fast. `recursive` copies a
whole tree and is refused if you leave it off for a directory; progress shows up
in `/api/sessions` as `job`.

**The owner's disk is the owner's data**, exactly like the remote side. Confirm
before overwriting or deleting anything local you did not create in this session,
and remember that `pull` overwrites the destination without asking.

**`rm` is not recursive and must not be made so.** A directory goes through
`RMDIR`, which fails if it is not empty. Delete the contents first, deliberately,
one at a time.

**Deleting and renaming are the owner's data.** Confirm before removing anything
you did not create yourself in this session, and never clear out a directory
speculatively.

Reuse an existing `-xfer` tab if one is open — check `/api/sessions` first, same
as for shells. Closing it costs nothing; reopening costs a touch.

## Failure modes worth recognising

- **`session busy`** — another operation holds the session. Wait and retry; do
  not restart anything.
- **`/run` returns `timed_out: true` with empty output** — the remote is probably
  still inside a command that is consuming input. Send Ctrl-C.
- **Silence after a transfer** — check the transcript path from `/api/sessions`;
  the payload is deliberately excluded from it.
- **`... is a transfer tab; that route needs a shell tab`** — you called `/run`,
  `/batch` or `/input` on a `-xfer` tab. Use the host's shell tab, or the
  transfer routes.
- **`locked: the master password has not been given yet`** (423) — the server is
  up but nobody has unlocked it. Ask the owner to unlock it in the browser; do
  not retry.
- **A transfer tab that will not open** — it needs its own touch. If the owner is
  not at the keyboard it will simply time out; that is not a bug.
- **`cmd contains a newline`** (400) — you sent more than one command in one
  `/run`. Split it; pass the list to `/batch`. Nothing reached the shell, so
  there is nothing to undo.
- **`... over the ... byte inline limit`** (413) — the file is bigger than
  `max_inline` and both directions enforce it. Nothing was transferred and no
  memory was spent. Open a transfer tab and use `pull`/`push`, which stream
  through disk and have no ceiling. Do not raise `max_inline` to get around it
  without asking.
- **`not found`** (404) on a route you believe exists — check the verb. Shell
  verbs and transfer verbs are separate sets, and a verb in neither is a plain
  404 rather than a confusing complaint about the wrong kind of tab.

## Changing server.py

`server.py` and `vault.py` only take effect on a restart, and **only the owner can
restart the server** — it comes back locked and needs the master password in a
browser. So an edit to either is not something you can verify by yourself. Say
what you changed and why a restart is needed, and let them decide when to pay for
it; do not ask casually, because a restart kills every open session and each one
costs a key touch to rebuild.

## What not to do

- `index.html` and `static/` are re-read on every request, so a browser reload is
  enough for front-end changes — prefer them when there is a choice. Only
  `server.py` and `vault.py` need a restart, which only the owner can perform.
- Do not touch `secrets.enc`. It holds saved SSH passwords sealed under the
  master password, it syncs between machines, and there is no recovery if it is
  damaged.
- Do not write credentials into `hosts.json`, `snippets.json`, or
  `settings.json`. They sync between machines.
- Do not delete anything in `logs/` — those are live transcripts, and they are
  removed automatically when a session closes.
- Do not propose `ControlMaster` / `ControlPersist`. The socket layer is not
  implemented in the bundled Win32 client — `getsockname failed: Not a socket`,
  before it even connects. The README carries the reproducer. One connection per
  touch is a platform fact here, not a preference.
- Do not try to drive the `sftp` **command** over pipes. Its prompt is not
  newline terminated and is therefore never flushed, so there is nothing to wait
  for. The binary protocol via `ssh -s sftp` is what `Transfer` speaks, and why.
- Clean up after yourself on the remote. If you write a test file, delete it in
  the same session — the transfer tab can now do that.
- Do not "simplify" the attribution decoration in `index.html` back to
  `layer: 'bottom'`, and do not drop `allowProposedApi: true` from the
  `new Terminal` options. Both look redundant and neither is: without the flag
  `registerDecoration` throws, and `layer: 'bottom'` does not actually put the
  bar under the glyphs in this build — the z-index juggling around `.xterm-rows`
  is what does. The README says why.
- Be careful with a `try/catch` that exists to swallow an expected error. One
  around the decoration call hid a total failure of the feature for every line of
  every run, with nothing in the console. If you add one, make it say something
  the first time.
