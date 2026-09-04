# CypherGate API

*For a programmer driving the console from your own code. Usage documentation is
in [README.md](README.md); the briefing for AI agents is in
[AGENTS.md](AGENTS.md).*

CypherGate exposes an HTTP API on `http://127.0.0.1:8765`. Your code opens and
drives SSH sessions **without ever holding an SSH credential** — the key, the
passphrase and any saved passwords stay inside the server, behind the master
password. What your code holds is a loopback token and a session name.

That is the whole point of scripting against this rather than against `ssh`
directly: a leaked script, a leaked log, or a leaked CI secret store gives up
nothing reusable.

---

## Contents

- [Getting the token](#getting-the-token)
- [A minimal client](#a-minimal-client)
- [Five rules that shape every client](#five-rules-that-shape-every-client)
- [State and configuration](#state-and-configuration)
- [Sessions](#sessions)
- [Running commands](#running-commands)
- [Reading output](#reading-output)
- [File transfer over the shell session](#file-transfer-over-the-shell-session)
- [Transfer tabs](#transfer-tabs)
- [The local disk](#the-local-disk)
- [Saved hosts and the command library](#saved-hosts-and-the-command-library)
- [Status codes and errors](#status-codes-and-errors)
- [Worked examples](#worked-examples)

---

## Getting the token

Every `/api/*` request needs an `X-Token` header. The token is regenerated at
each server start, written **only after** the master password is accepted, and
deleted when the server exits:

```
state/<COMPUTERNAME>/token
```

```bash
TOKEN=$(cat "state/$COMPUTERNAME/token")
B=http://127.0.0.1:8765

curl -s -H "X-Token: $TOKEN" $B/api/sessions
```

```python
import os, pathlib

ROOT  = pathlib.Path(__file__).resolve().parent      # the CypherGate folder
TOKEN = (ROOT / "state" / os.environ["COMPUTERNAME"] / "token").read_text().strip()
BASE  = "http://127.0.0.1:8765"
```

**No token file means the server is not running, or is running but still
locked.** Both are conditions your code should report rather than retry: only a
human at a browser can fix either. Treat a missing token file as "ask the
operator", not as an error to loop on.

The token is also the reason the API is safe to leave bound: it forces a CORS
preflight that is never answered, so a web page you happen to visit cannot POST
into your sessions. A `Host` check blocks DNS rebinding, so requests must arrive
addressed to `127.0.0.1` or `localhost`.

---

## A minimal client

The server speaks plain JSON over HTTP, so the standard library is enough — no
dependency required, matching the rest of the project.

```python
import json, os, pathlib, urllib.error, urllib.request


class CypherGateError(RuntimeError):
    """An error the server reported, with its HTTP status attached."""

    def __init__(self, status, message):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class CypherGate:
    def __init__(self, root, base="http://127.0.0.1:8765"):
        root = pathlib.Path(root)
        machine = os.environ.get("COMPUTERNAME", "machine")
        token_file = root / "state" / machine / "token"
        if not token_file.exists():
            raise CypherGateError(0, "no token file: the server is not running, "
                                     "or has not been unlocked in a browser yet")
        self.token = token_file.read_text().strip()
        self.base = base.rstrip("/")

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("X-Token", self.token)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                message = json.loads(payload).get("error", payload.decode())
            except ValueError:
                message = payload.decode("utf-8", "replace")
            raise CypherGateError(e.code, message) from None

    # --- the calls you will actually use -----------------------------------
    def sessions(self):
        return self._call("GET", "/api/sessions")

    def run(self, name, cmd, timeout=60):
        return self._call("POST", f"/api/sessions/{name}/run",
                          {"cmd": cmd, "timeout": timeout})

    def batch(self, name, cmds, timeout=60, stop_on_error=False):
        return self._call("POST", f"/api/sessions/{name}/batch",
                          {"cmds": cmds, "timeout": timeout,
                           "stop_on_error": stop_on_error})

    def open(self, name, **kw):
        return self._call("POST", "/api/sessions", {"name": name, **kw})

    def close(self, name):
        return self._call("DELETE", f"/api/sessions/{name}")


cg = CypherGate(r"C:\Tools\CypherGate")
print(cg.run("web-01", "uptime")["output"])
```

Note the `timeout=300` on the request itself. `/run` **blocks** until the remote
command finishes, so your HTTP timeout must exceed the `timeout` you send in the
body, or your client will give up while the server is still working.

---

## Five rules that shape every client

**1. A locked server answers `423` on everything.** Until someone types the
master password in a browser, every route but `/api/state` and `/api/unlock`
returns `423 Locked` — and since no token file exists yet, in practice you
cannot reach even those. Your code can never unlock the server; that is
deliberate. Surface it and stop.

**2. Opening a session costs a physical key touch; commands cost nothing.**
With a touch-required FIDO2 key, `POST /api/sessions` makes the operator's token
blink and waits for a finger. So **check `/api/sessions` and reuse what is
already open** rather than opening your own, and never open one speculatively.
A script that opens six sessions demands six taps from whoever is at the desk.

**3. One command per `/run`.** A `cmd` containing a newline is refused with a
`400` before anything reaches the shell, because bash echoes a continuation
prompt (`> `) for each extra line and those would land at the front of your
output — a wrong answer shaped like a right one. Use `/batch` for a sequence.

**4. Everything you send is marked as yours.** `/run` and `/batch` get an ochre
bar behind the command and its output in the operator's terminal, plus a
`--- api <timestamp> ---` delimiter in the transcript. There is no way to switch
this off, and `/input` counts as API traffic *unless* it declares
`{"source": "keyboard"}` — a field that exists so the browser can identify real
typing. **Do not send it from a script.** It would make your keystrokes
indistinguishable from the operator's own, in the one record that settles who
did what.

**5. Operations on a session are serialised.** A command issued while a transfer
is running waits up to 20 seconds and then comes back `{"ok": false, "error":
"session busy: ..."}` rather than blocking forever. Note that this is `200 OK`
with `ok: false`, not an HTTP error — check the field.

---

## State and configuration

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/state` | `{locked, has_vault, attempts_left, vault_path, port}` |
| `POST` | `/api/unlock` | `{password, confirm?}` — `confirm` only when creating a vault |
| `GET` | `/api/config` | `{default_key, ssh_bin, port, max_inline, known_hosts}` |
| `POST` | `/api/config` | `{default_key, max_inline?}` |

```bash
curl -s -H "X-Token: $TOKEN" $B/api/config
# {"default_key": "D:/keys/id_ed25519_sk", "ssh_bin": "...\\ssh\\ssh.exe",
#  "port": 8765, "max_inline": 67108864, "known_hosts": "...\\known_hosts"}
```

`ssh_bin` is worth reading if you are diagnosing behaviour: it tells you exactly
which client binary is in use, and it is always the bundled one.

**`/api/unlock` is documented for completeness, not for your use.** Posting a
master password from a script puts the one secret that gates everything into
your source, your shell history and your process list. Let a human type it.

---

## Sessions

| Method | Path | Body | Purpose |
|---|---|---|---|
| `GET` | `/api/sessions` | — | list every open tab |
| `POST` | `/api/sessions` | see below | open a shell tab |
| `POST` | `/api/sessions` | `{name, kind:"transfer"}` | open a transfer tab |
| `DELETE` | `/api/sessions/<name>` | — | close one, deleting its transcript |

A shell tab's entry:

```json
{
  "name": "web-01", "kind": "shell", "host": "web-01",
  "target": "deploy@web-01.example.com", "auth": "key", "proxy_jump": null,
  "log": "C:\\...\\logs\\WORKSTATION\\web-01_2026-09-04_115334.log",
  "alive": true, "offset": 19173, "rows": 30, "cols": 110, "uptime": 412
}
```

A transfer tab's entry replaces `rows`/`cols` with `cwd`, and adds `busy`
(`{op, path, done, total}` while a single file moves) and `job`
(`{files_done, files_total, current}` while a recursive copy runs). Poll
`/api/sessions` for progress — that is where the UI's progress bar comes from.

### Opening a shell tab

```bash
# By saved-host name alone: target, auth, key, cert, port and jump host
# are filled in from hosts.json.
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions -d '{"name":"web-01"}'

# Fully specified, for a host that is not saved.
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions -d '{
  "name": "edge-01",
  "target": "deploy@edge-01.example.com",
  "auth": "key",
  "port": 2222,
  "proxy_jump": "deploy@bastion.example.com",
  "rows": 40, "cols": 120
}'
```

| Field | Meaning |
|---|---|
| `name` | required; `^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`, because it becomes part of a transcript filename |
| `target` | `user@host`; optional if `name` matches a saved host |
| `auth` | `key` (default), `cert`, or `password` |
| `key` / `cert` | paths; `%VAR%` and `~` are expanded. Empty means the configured default key |
| `port`, `proxy_jump` | optional; `proxy_jump` maps to `ssh -J` |
| `password` | for `auth: "password"`; falls back to the vault entry for `name` |
| `rows`, `cols` | initial terminal size |

The response returns immediately with a note that the key needs touching — it
does **not** wait for authentication to finish:

```json
{"ok": true, "name": "web-01", "target": "deploy@web-01.example.com",
 "note": "touch your security key to finish authenticating"}
```

So poll until the session actually answers before you start issuing work:

```python
import time

def wait_ready(cg, name, seconds=90):
    """Block until the shell responds, or give up. The wait is a human
    finding their security key, so it has no useful lower bound."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        r = cg.run(name, "true", timeout=5)
        if r.get("ok") and not r.get("timed_out"):
            return True
        time.sleep(1)
    return False
```

**A note on timing.** The invisible prompt marker is installed by a background
thread once the shell first speaks. A command issued in the very first moment of
a session can win the race and fall back to a *visible* sentinel, which appears
in the operator's terminal as trailing `; __rc=$?; printf ...` noise. Waiting for
readiness as above avoids it.

Opening a transfer tab for a host that already has one returns `409`.

---

## Running commands

| Method | Path | Body |
|---|---|---|
| `POST` | `/api/sessions/<name>/run` | `{cmd, timeout?}` |
| `POST` | `/api/sessions/<name>/batch` | `{cmds[], timeout?, stop_on_error?}` |
| `POST` | `/api/sessions/<name>/exec` | `{cmd}` |
| `POST` | `/api/sessions/<name>/input` | `{data, b64?}` |
| `POST` | `/api/sessions/<name>/resize` | `{rows, cols}` |

### `/run` — the one you want

Blocks until the command finishes and returns **that command's output alone** —
no prompt, no echoed command, no surrounding scrollback.

```bash
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01/run \
     -d '{"cmd":"systemctl is-active nginx","timeout":30}'
```

```json
{"ok": true, "exit_code": 0, "timed_out": false,
 "truncated": false, "lost_bytes": 0, "log": null, "output": "active"}
```

| Field | Meaning |
|---|---|
| `ok` | the call was carried out. **Not** whether the command succeeded |
| `exit_code` | the remote command's status. `null` if it could not be determined |
| `timed_out` | the timeout elapsed before the command finished |
| `truncated` | output overran the 2 MB in-memory window; **the front is missing** |
| `lost_bytes` | how much was lost |
| `log` | transcript path holding the complete output, when `truncated` |
| `output` | stdout and stderr, `\r` stripped, trailing newlines removed |

Check `ok`, `timed_out` and `exit_code` separately — they answer different
questions, and a command that fails cleanly still returns `ok: true`.

```python
r = cg.run("web-01", "systemctl is-active nginx")
if not r["ok"]:
    raise RuntimeError(r.get("error"))          # busy, gone, or refused
if r["timed_out"]:
    raise TimeoutError("nginx check did not finish")
if r["truncated"]:
    print(f"warning: lost {r['lost_bytes']} bytes; full output in {r['log']}")
healthy = r["exit_code"] == 0
```

Default `timeout` is 60 seconds. Raise it for long jobs — `apt upgrade` wants
600 or more.

### `/batch` — prefer this over a loop

```bash
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01/batch -d '{
  "cmds": ["hostname", "uptime", "df -h /"],
  "stop_on_error": true
}'
```

```json
{"ok": true, "requested": 3, "ran": 3, "results": [
  {"ok": true, "exit_code": 0, "output": "web-01", "cmd": "hostname"},
  {"ok": true, "exit_code": 0, "output": " 11:54:43 up 202 days...", "cmd": "uptime"},
  {"ok": true, "exit_code": 0, "output": "Filesystem ...", "cmd": "df -h /"}
]}
```

Each result carries every `/run` field plus the `cmd` it came from. Two reasons
this beats looping over `/run`:

- **The session is held for the whole sequence.** A loop releases the lock
  between commands, so another caller — or the operator's keyboard — can land
  something in the middle of yours. A batch cannot be interleaved.
- **Commands arrive as JSON array elements** and never pass through a shell on
  the way in, which removes the quoting problem entirely.

`stop_on_error` halts at the first non-zero exit or timeout; `ran` versus
`requested` tells you how far it got. At most 100 commands, since a batch holds
the session for its whole run.

### `/exec`, `/input`, `/resize`

`/exec` fires and forgets, returning `{ok, sent, offset_before}` — read the
output yourself from `/text?since=<offset_before>`. Prefer `/run` unless you
specifically want a long-running foreground program.

`/input` writes raw bytes to the pty. Use it to rescue a stuck shell:

```bash
# Ctrl-C is 0x03; base64 "Aw=="
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01/input \
     -d '{"data":"Aw==","b64":true}'
```

```python
cg._call("POST", "/api/sessions/web-01/input", {"data": "Aw==", "b64": True})
```

Without `b64: true`, `data` is sent as UTF-8 text. Remember rule 4: never send
`{"source": "keyboard"}`.

`/resize` returns `{ok, changed, rows, cols}`. It is queued if the prompt hook is
not ready yet, and `changed` is `false` when the size already matched.

---

## Reading output

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/sessions/<name>/text?since=<n>` | `{name, since, offset, alive, text}` |
| `GET` | `/api/sessions/<name>/stream?token=<t>` | SSE, base64 chunks |
| `GET` | `/api/sessions/<name>/log` | the full transcript as a file download |

`/text` gives the ANSI-stripped transcript from an absolute offset; the returned
`offset` is where to resume next time. `/log` reads straight off disk, so
nothing is missing even when the in-memory window has wrapped.

`/stream` is Server-Sent Events, and takes the token as a **query parameter**
because `EventSource` cannot set headers. Every event carries an `id` — the
absolute offset it ends at — so sending it back as `Last-Event-ID` resumes
rather than replaying the whole scrollback.

```python
import base64, urllib.request

def follow(cg, name, since=None):
    """Yield decoded output chunks as they arrive."""
    req = urllib.request.Request(f"{cg.base}/api/sessions/{name}/stream"
                                 f"?token={cg.token}")
    if since is not None:
        req.add_header("Last-Event-ID", str(since))
    with urllib.request.urlopen(req) as r:
        for raw in r:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("data:"):
                yield base64.b64decode(line[5:].strip()).decode("utf-8", "replace")

for chunk in follow(cg, "web-01"):
    print(chunk, end="", flush=True)
```

```bash
curl -N -s "$B/api/sessions/web-01/stream?token=$TOKEN"
```

---

## File transfer over the shell session

These ride the connection you already have, so they cost **no extra key touch**.
The payload is captured, so it never floods the operator's terminal.

| Method | Path | Body |
|---|---|---|
| `POST` | `/api/sessions/<name>/download` | `{path, timeout?}` |
| `POST` | `/api/sessions/<name>/upload` | `{path, b64, timeout?}` |

```python
import base64

r = cg._call("POST", "/api/sessions/web-01/download",
             {"path": "/etc/nginx/nginx.conf"})
if not r.get("verified"):
    print("warning: remote had no checksum tool; bytes were NOT verified")
open("nginx.conf", "wb").write(base64.b64decode(r["b64"]))
```

Download returns `{ok, size, compressed, verified, algorithm, b64}`; upload
returns `{ok, size, path, compressed, wire_bytes, verified, algorithm}`. `size`
is the uncompressed size.

**Check `verified`.** Both directions checksum the real bytes and a mismatch
fails the call outright — but `verified: false` means the remote had neither
`md5sum` nor `sha256sum`, so nothing was checked. The bytes are probably fine;
just do not report them as verified.

Both directions are capped at `max_inline` (64 MB by default) and refuse
anything larger with `413`, before spending the memory. For bigger files use a
transfer tab's `pull`/`push`, which stream through disk and have no ceiling.

---

## Transfer tabs

A transfer tab is a **second connection** to the same host speaking the SFTP
protocol, keyed `<name>-xfer`. It costs its own key touch to open, then nothing
per file — and the shell tab stays fully usable while it works.

Paths never pass through a shell here, so spaces and quotes need no escaping.
Relative paths resolve against the tab's `cwd`.

| Path | Body | Returns |
|---|---|---|
| `/api/sessions/<n>-xfer/ls` | `{path?}` | `{ok, cwd, entries[]}` |
| `/api/sessions/<n>-xfer/cd` | `{path}` | `{ok, cwd}` |
| `/api/sessions/<n>-xfer/get` | `{path, timeout?}` | `{ok, size, b64}` |
| `/api/sessions/<n>-xfer/put` | `{path, b64, timeout?}` | `{ok, size, path}` |
| `/api/sessions/<n>-xfer/mkdir` | `{path}` | `{ok, path}` |
| `/api/sessions/<n>-xfer/rm` | `{path}` | `{ok, path}` |
| `/api/sessions/<n>-xfer/mv` | `{from, to}` | `{ok, from, to}` |
| `/api/sessions/<n>-xfer/pull` | `{remote, local, timeout?, recursive?}` | `{ok, remote, local, files, bytes}` |
| `/api/sessions/<n>-xfer/push` | `{local, remote, timeout?, recursive?}` | `{ok, remote, local, files, bytes}` |

Each `ls` entry is `{name, dir, link, size, mtime, mode}`. Symlinks report the
link's own size, as `ls -l` does.

```bash
curl -s -H "X-Token: $TOKEN" -X POST $B/api/sessions/web-01-xfer/ls \
     -d '{"path":"/etc"}'
```

**Prefer `pull`/`push` whenever a file is going to or coming from disk.** They
move the bytes server-side rather than base64 through the JSON reply, so there
is no size cap and they measure about twice as fast:

```python
cg._call("POST", "/api/sessions/web-01-xfer/pull",
         {"remote": "/var/backups/db.sql.gz", "local": r"D:\backups\db.sql.gz"})

cg._call("POST", "/api/sessions/web-01-xfer/push",
         {"local": r"D:\site", "remote": "/srv/www/site", "recursive": True})
```

`recursive` copies a whole tree and is **required** for a directory — a copy
without it is refused rather than silently doing the wrong thing. One copy at a
time per tab; watch `job` in `/api/sessions` for progress.

**`pull` overwrites its destination without asking**, and `rm` is non-recursive
on both sides by design: a directory goes through `RMDIR`, which fails unless it
is empty. Neither of those is going to change, so write your client to expect
them.

---

## The local disk

The server lists and writes the machine it runs on, because a browser cannot
enumerate its own disk. These need no key touch.

| Path | Body | Returns |
|---|---|---|
| `/api/local/ls` | `{path?}` | `{ok, cwd, parent, machine, home, sep, drives, entries}` |
| `/api/local/mkdir` | `{path}` | `{ok, path}` |
| `/api/local/rm` | `{path}` | `{ok, path}` |
| `/api/local/mv` | `{from, to}` | `{ok, from, to}` |

`mv` refuses an existing destination. `rm` is non-recursive, exactly like the
remote side.

This is real reach — anything holding the token can read a local file. It does
not widen the trust boundary, since the same token already opens an SSH session
to every saved host, but it is worth knowing what you are handing to a script.

---

## Saved hosts and the command library

| Method | Path | Body |
|---|---|---|
| `GET` | `/api/hosts` | — |
| `POST` | `/api/hosts` | `{name, target, auth, key?, cert?, port?, proxy_jump?, theme?, password?, remember_password?}` |
| `DELETE` | `/api/hosts/<name>` | — |
| `GET` | `/api/snippets` | — |
| `POST` | `/api/snippets` | `{name, cmd}` |
| `DELETE` | `/api/snippets/<name>` | — |

`GET /api/hosts` adds `has_saved_password` per entry — a boolean, never the
password itself. Posting the same name overwrites; deleting a host also drops
any saved password. `DELETE /api/snippets/<name>` returns `{ok, removed}`.

**`hosts.json` and `snippets.json` are plaintext and sync between machines.
Never write a credential into either.** A password sent with
`remember_password` goes into the AES-GCM vault instead, and no route reads it
back out.

---

## Status codes and errors

Errors are JSON: `{"error": "<message>"}`, sometimes with extra fields.

| Code | Meaning | What to do |
|---|---|---|
| `400` | bad request — missing field, bad JSON, multi-line `cmd`, or a shell verb aimed at a transfer tab | fix the call; nothing reached the shell |
| `401` | bad or missing token | re-read the token file; it changes on every restart |
| `403` | bad host | address the request to `127.0.0.1`, not a hostname that resolves there |
| `404` | no such session, or no such route | check the name, and check the verb — shell and transfer verbs are separate sets |
| `409` | vault already exists, or a transfer tab for that host is already open | reuse the existing tab |
| `413` | body or file over `max_inline` | use a transfer tab's `pull`/`push` |
| `423` | **locked** — the master password has not been given | ask a human to unlock it in a browser. Do not retry |

Two failure modes arrive as `200 OK` with `ok: false`, so check the field rather
than the status:

- `session busy: another operation is still running` — something else holds the
  session. Wait and retry.
- `timed_out: true` with empty output — the remote is probably still inside a
  command consuming stdin. Send Ctrl-C via `/input`.

```python
try:
    r = cg.run("web-01", "uptime")
except CypherGateError as e:
    if e.status == 423:
        raise SystemExit("CypherGate is locked - unlock it at "
                         "http://127.0.0.1:8765 and re-run")
    if e.status == 404:
        raise SystemExit("session 'web-01' is not open - ask for a tab")
    raise
```

---

## Worked examples

### A health sweep across every open session

Note what this does *not* do: it never opens a session, so it never demands a
key touch. It reports what it could not reach instead.

```python
WANT = ["web-01", "db-01", "edge-01"]

open_shells = {s["name"] for s in cg.sessions()
               if s["kind"] == "shell" and s["alive"]}

for host in WANT:
    if host not in open_shells:
        print(f"{host}: SKIPPED - no session open")
        continue

    r = cg.batch(host, [
        "uptime -p",
        "df -h / | awk 'NR==2 {print $5}'",
        "systemctl --failed --no-pager --plain | wc -l",
    ])
    if not r["ok"]:
        print(f"{host}: {r.get('error')}")
        continue

    up, disk, failed = (x["output"] for x in r["results"])
    flag = "!" if failed.strip() != "0" else " "
    print(f"{flag} {host}: {up}, root {disk}, {failed.strip()} failed units")
```

Quoting note: the `awk` command above contains single quotes, which is exactly
the case that breaks a shell one-liner built with `curl -d`. Passing it as a
JSON array element sidesteps the problem — one more reason to prefer `/batch`.

### Collect a config file from every host

```python
import base64, pathlib

out = pathlib.Path("collected")
out.mkdir(exist_ok=True)

for s in cg.sessions():
    if s["kind"] != "shell" or not s["alive"]:
        continue
    try:
        r = cg._call("POST", f"/api/sessions/{s['name']}/download",
                     {"path": "/etc/ssh/sshd_config"})
    except CypherGateError as e:
        print(f"{s['name']}: {e.message}")
        continue
    (out / f"{s['name']}-sshd_config").write_bytes(base64.b64decode(r["b64"]))
    print(f"{s['name']}: {r['size']} bytes"
          f"{'' if r['verified'] else ' (NOT verified)'}")
```

### A patch run, in bash

```bash
#!/usr/bin/env bash
set -euo pipefail

TOKEN=$(cat "state/$COMPUTERNAME/token")
B=http://127.0.0.1:8765
HOST=${1:?usage: patch.sh <session-name>}

# Build the body with a here-doc rather than inline, so quoting cannot bite.
cat > /tmp/patch.json <<'JSON'
{
  "cmds": [
    "sudo apt-get update",
    "sudo apt-get -y upgrade",
    "test -f /var/run/reboot-required && echo REBOOT || echo clean"
  ],
  "timeout": 900,
  "stop_on_error": true
}
JSON

curl -s -H "X-Token: $TOKEN" -X POST \
     "$B/api/sessions/$HOST/batch" --data-binary @/tmp/patch.json \
     -o /tmp/patch-result.json

# Parse in a quoted here-doc: nothing expands, so no quoting to get wrong.
python - /tmp/patch-result.json <<'PY'
import json, sys

with open(sys.argv[1]) as fh:
    r = json.load(fh)

if not r.get("ok"):
    sys.exit(r.get("error", "failed"))

for x in r["results"]:
    print("$ " + x["cmd"])
    print(x["output"])
    print()

print("ran %d of %d" % (r["ran"], r["requested"]))
if r["ran"] != r["requested"]:
    sys.exit("stopped early")
PY
```

### Watching a long job while it runs

`/run` blocks, which is usually what you want — but if you need to show progress,
start it with `/exec` and follow the stream from the offset it hands back.

```python
r = cg._call("POST", "/api/sessions/web-01/exec",
             {"cmd": "sudo apt-get -y upgrade"})

for chunk in follow(cg, "web-01", since=r["offset_before"]):
    print(chunk, end="", flush=True)
```

Remember that the operator sees all of this in their own terminal as it happens,
with your commands marked as yours. That is a feature: if your script does
something surprising at 2am, there is a record of exactly what and when.
