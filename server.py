#!/usr/bin/env python3
"""CypherGate -- a tabbed SSH console with an HTTP control API.

You watch and type in the browser; a script or an AI agent drives the *same*
sessions over /api/*, and every command it sends is marked as its own. One SSH
connection per named session, so one security-key touch each -- never one per
command.

Authentication stays here. A caller of the API holds a loopback token and a
session name; it never sees a key, a passphrase or a password, and it cannot
unlock the vault. That boundary is the point of the program.

Run:  start.cmd   (or: python server.py)   then open http://127.0.0.1:8765
Stop: Ctrl-C
"""
import base64
import functools
import gzip
import hashlib
import json
import os
import queue
import re
import secrets
import shlex
import shutil
import stat as statmod
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import atexit
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

HERE = os.path.dirname(os.path.abspath(__file__))
# The embeddable interpreter does not put the script's directory on
# sys.path, so local modules need it added explicitly.
# No .pyc alongside the source: __pycache__ would sync with the folder and
# churn on every run for no benefit.
sys.dont_write_bytecode = True
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import vault  # noqa: E402  (must follow the sys.path fix)
HOST = "127.0.0.1"
PORT = int(os.environ.get("CYPHERGATE_PORT", "8765"))   # override if 8765 is taken

# Strictly portable: everything the app writes lives under this folder, so
# copying it takes the whole app with it. Per-machine state is namespaced by
# COMPUTERNAME, because a key path, a token and a live transcript are all
# specific to one box and must not collide across a sync.
MACHINE = os.environ.get("COMPUTERNAME") or "machine"
_state = os.path.join(HERE, "state", MACHINE)
os.makedirs(_state, exist_ok=True)
TOKEN_FILE = os.path.join(_state, "token")
TOKEN = secrets.token_urlsafe(24)
# Sealed with the master password, so it can sync with the folder.
VAULT_FILE = os.path.join(HERE, "secrets.enc")
VAULT = {"passwords": {}}   # filled at startup, held in memory only
# Settings are shared across machines, like hosts and snippets. Paths in
# them are expanded, so %USERPROFILE%/.ssh/key works on every box.
SETTINGS_FILE = os.path.join(HERE, "settings.json")


def _migrate(old, new):
    """One-time move of state from the pre-portable LOCALAPPDATA location."""
    if os.path.exists(old) and not os.path.exists(new):
        try:
            shutil.copyfile(old, new)
        except OSError:
            pass


_legacy = os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
                       "ssh_done_better")
for _name in ("settings.json",):
    _migrate(os.path.join(_legacy, _name), os.path.join(_state, _name))
_migrate(os.path.join(_state, "settings.json"), SETTINGS_FILE)

# SETTINGS_FILE is assigned below, once the local state directory exists.
# No built-in key path: an unset default is an error you can see, not a
# guess that silently picks the wrong key.
FALLBACK_KEY = os.environ.get("SSH_KEY", "")


# The bundled client is the only one used. No search, no fallback: the point
# of carrying it is that behaviour does not vary with what happens to be
# installed on the machine.
SSH_BIN = os.path.join(HERE, "ssh", "ssh.exe")
SFTP_BIN = os.path.join(HERE, "ssh", "sftp.exe")


def ssh_binary():
    return SSH_BIN

def expand(path):
    """Let a shared setting name a per-user location."""
    if not path:
        return path
    return os.path.expanduser(os.path.expandvars(path)).replace("\\", "/")


_settings = {"stamp": None, "data": {}}


def settings():
    """settings.json, re-read only when it has actually changed.

    "Read on every use" is the property that matters -- a change has to
    apply to the next session without a restart -- and an mtime-and-size
    check keeps exactly that for the price of a stat, instead of an open
    and a JSON parse. Both readers below sit on the session-open path, and
    /api/config calls each of them once to build a single reply.
    """
    try:
        st = os.stat(SETTINGS_FILE)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    if stamp != _settings["stamp"]:
        _settings["data"] = load_json(SETTINGS_FILE, {})
        _settings["stamp"] = stamp
    return _settings["data"]


def default_key():
    """Key used by any host that does not name its own.

    settings.json wins, then $SSH_KEY, then the built-in path.
    """
    return expand(settings().get("default_key") or FALLBACK_KEY)

# Host keys live beside the app: $HOME/.ssh is not writable on this machine,
# which is why verification had to be disabled before.
KNOWN_HOSTS = os.path.join(HERE, "known_hosts")

# Saved host definitions. Never holds a password -- see PASSWORDS below.
HOSTS_FILE = os.path.join(HERE, "hosts.json")

# Command library. Text only, no credentials -- this folder may be synced.
SNIPPETS_FILE = os.path.join(HERE, "snippets.json")

# Session transcripts. They live inside the folder because the app is
# strictly portable -- nothing is written outside it. Transcripts can contain
# anything a command printed, so treat the folder with the same care as the
# shell itself, and keep it out of a shared sync if that matters to you.
LOG_DIR = os.path.join(HERE, "logs", MACHINE)
SEED_SNIPPETS = [
    {"name": "APT Upgrade",      "cmd": "sudo apt-get update && sudo apt-get upgrade -y"},
    {"name": "Reboot Required?", "cmd": "test -f /var/run/reboot-required && cat /var/run/reboot-required || echo 'no reboot needed'"},
    {"name": "Disk Usage",       "cmd": "df -h -x tmpfs -x devtmpfs"},
    {"name": "Biggest Dirs",     "cmd": "sudo du -xh / 2>/dev/null | sort -rh | head -20"},
    {"name": "Docker PS",        "cmd": "docker ps --format 'table {{.Names}}\t{{.Status}}'"},
    {"name": "Failed Services",  "cmd": "systemctl --failed --no-pager"},
    {"name": "Listening Ports",  "cmd": "sudo ss -tulpn | grep LISTEN"},
    {"name": "Journal Errors",   "cmd": "sudo journalctl -p err -b --no-pager | tail -40"},
    {"name": "Service Status",   "cmd": "systemctl status {{service}} --no-pager"},
    {"name": "Tail Log",         "cmd": "sudo tail -f {{path}}"},
]

ASKPASS_CMD = os.path.join(HERE, "askpass.cmd")
ASKPASS_CMD_BODY = "@echo off\r\necho %SSH_PASSWORD%\r\n"


def connection_opts(port, proxy_jump, auth, key, cert, password):
    """Options shared by ssh and sftp, so the two cannot drift apart.

    Returns (argv fragment, environment). `sftp` spells the port `-P` where
    `ssh` spells it `-p`, so that one stays with the caller.
    """
    opts = ["-o", "UserKnownHostsFile=" + KNOWN_HOSTS,
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
            "-o", "ServerAliveInterval=30"]
    if proxy_jump:
        # Reaches hosts with no direct route -- one behind a bastion, or on
        # a LAN the overlay network does not cover. Note each hop
        # authenticates, so a touch-required key is one touch per hop.
        opts += ["-J", proxy_jump]

    env = dict(os.environ)
    if auth == "password":
        # ssh reads a password from the tty, and we have no tty -- so route
        # it through an askpass helper instead.
        opts += ["-o", "PubkeyAuthentication=no",
                 "-o", "PreferredAuthentications=password,keyboard-interactive",
                 "-o", "NumberOfPasswordPrompts=1"]
        env["SSH_ASKPASS"] = ASKPASS_CMD
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = env.get("DISPLAY", ":0")
        env["SSH_PASSWORD"] = password or ""
    else:
        opts += ["-i", key, "-o", "IdentitiesOnly=yes"]
        if cert:
            opts += ["-o", "CertificateFile=" + cert]
    return opts, env


def load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def save_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)

ANSI = re.compile(
    rb"\x1b\[[0-9;?]*[ -/]*[@-~]"
    rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    rb"|\x1b[()][0-9A-B]"
    rb"|\x1b[=>]"
    rb"|[\x00\x07\x08]"
)

OSC_MARK = re.compile(rb"\x1b\]777;(\d+);(\d+)\x07")
PROMPT_HOOK = '__cg_n=0; PROMPT_COMMAND=\'__cg_rc=$?; __cg_n=$((__cg_n+1)); printf "\\e]777;%d;%d\\a" "$__cg_n" "$__cg_rc"\''

# A session name lands in a transcript filename, so it must not be able to
# walk out of the logs directory.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")

MASTER_KEY = None
MASTER_SALT = None

# The master password now arrives over the loopback API rather than the
# console, so the socket is bound before the vault is open. Until it is,
# LOCKED makes every route except /api/state and /api/unlock return 423,
# including the ones that never touch the vault: a key-auth session needs
# no secret, so gating only vault work would let a locked server SSH out.
LOCKED = True
UNLOCK_LOCK = threading.Lock()
UNLOCK_TRIES = 0
# Matches the console prompt's old allowance. A cap is safe here precisely
# because unlocking only ever happens with no sessions open -- nothing can
# be created while locked -- so exhausting it costs a restart and no touch.
MAX_UNLOCK_TRIES = 3
# scrypt already costs ~50-100ms a guess; this drops an unthrottled
# attacker to roughly two a second, well under the attempt cap anyway.
UNLOCK_DELAY = 0.4

SESSIONS = {}
LOCK = threading.Lock()
MAX_RAW = 4_000_000
# Chunks queued for one browser before it is considered to have stopped
# reading. Unbounded, this was a slow tab's memory leak; bounded, falling
# behind ends that stream and the browser resumes from its last event id.
MAX_SUB_QUEUE = 256
# In-memory transcript window. The full history lives in LOG_DIR; this is
# only what /text can serve, and text_base keeps offsets absolute.
MAX_TEXT = 2_000_000
# A batch holds the session for the whole run, so the cap is really a cap on
# how long one caller may keep everyone else out.
MAX_BATCH = 100
# Measured ~3.5 MB/s over a pty on the LAN, so this is about 20s of transfer.
# The ceiling is really memory: the payload is held whole, several times over
# (capture buffer, base64 string, JSON body, and again in the browser).
DEFAULT_MAX_INLINE = 64_000_000


def max_inline():
    return int(settings().get("max_inline") or DEFAULT_MAX_INLINE)


class BodyTooLarge(Exception):
    """A request body over the inline ceiling, refused before it is read."""


# How much of an oversized body is still worth reading and throwing away so
# the 413 explaining the refusal actually reaches the caller. Past this the
# connection is dropped instead: at some point the sender is not making a
# mistake, and reading for ever is worse than an unexplained reset.
MAX_DRAIN = 512_000_000


def over_cap(size, what, cap=None):
    """One sentence for every route that has to refuse an oversized payload.

    The ceiling applies to anything held whole in memory, which is both
    directions of the in-band transfer and both directions of the transfer
    tab's get/put -- not to pull/push, which stream through a file on disk
    and are bounded by the disk instead.

    `cap` is passed explicitly by callers that were handed one, so the
    message names the limit that was actually enforced rather than
    whatever settings.json happens to say by the time it is written.
    """
    cap = max_inline() if cap is None else cap
    if size <= cap:
        return None
    return ("%s is %d bytes, over the %d byte inline limit; use pull/push "
            "through a transfer tab, or raise max_inline in Settings"
            % (what, size, cap))


def purge_stale_logs():
    """Drop transcripts no live session owns -- leftovers from a crash."""
    with LOCK:
        live = {getattr(x, "log_path", None) for x in SESSIONS.values()}
    try:
        names = os.listdir(LOG_DIR)
    except OSError:
        return 0
    gone = 0
    for fname in names:
        full = os.path.join(LOG_DIR, fname)
        if full in live or not fname.endswith(".log"):
            continue
        try:
            os.remove(full)
            gone += 1
        except OSError:
            pass
    return gone


class Session:
    """One `ssh -tt` child process, its output buffers, and its subscribers."""

    def __init__(self, name, target, rows=40, cols=120, key=None,
                 auth="key", cert=None, password=None, port=None,
                 proxy_jump=None):
        self.name = name
        self.target = target
        self.auth = auth
        self.key = expand(key) or default_key()
        self.cert = expand(cert)
        self.port = port
        self.proxy_jump = proxy_jump
        self.capture = None       # set while a file transfer is in flight
        self.caps = None          # remote gzip/checksum support, probed once
        self.rows = rows
        self.cols = cols
        self.text_base = 0        # bytes dropped from the front of .text
        self.osc_n = 0            # prompts seen since the hook installed
        self.osc_rc = 0           # exit code reported by the last prompt
        self.osc_at = 0           # text offset where that marker landed
        self._osc_resid = b""     # marker split across a chunk boundary
        self._hook_sent = False
        self.pending_resize = None   # queued until the prompt hook is up
        self.hook_done = False       # the attempt finished, marker or not
        self._saw_output = False
        # Serialises run/upload/download/resize on this session: they all
        # drive the same pty, and interleaving them corrupts both.
        self.cmd_lock = threading.Lock()
        self.raw = bytearray()    # bytes with escapes, replayed to the browser
        self.raw_base = 0         # bytes dropped from the front of .raw
        self.text = bytearray()   # ANSI-stripped, what the API returns
        self.subs = []
        self.lock = threading.Lock()
        self.started = time.time()

        remote = "stty rows %d cols %d 2>/dev/null; exec bash -l" % (rows, cols)
        opts, env = connection_opts(self.port, self.proxy_jump, auth,
                                    self.key, self.cert, password)
        cmd = [ssh_binary(), "-tt"] + opts
        if self.port:
            cmd += ["-p", str(self.port)]
        cmd += [target, remote]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0, env=env,
        )
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d_%H%M%S")
        self.log_path = os.path.join(LOG_DIR, "%s_%s.log" % (name, stamp))
        self.log = open(self.log_path, "ab")
        # A prompt carries no trailing newline, so a delimiter written while
        # one is on screen would land in the middle of it -- breaking the line
        # and, worse, breaking `grep '^--- api'`.
        self._log_bol = True
        header = ("# session %s -> %s" % (name, target) + "\n" +
                  "# opened  %s" % time.ctime() + "\n")
        self.log.write(header.encode())
        self.log.flush()

        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._install_hook, daemon=True).start()

    def _install_hook(self):
        """Teach bash to announce each prompt with an invisible OSC marker.

        Done once, hidden behind capture, so no sentinel is ever typed onto a
        command line again. If the remote shell ignores PROMPT_COMMAND the
        marker never arrives and run() falls back to the old sentinel.
        """
        # With a touch-required key, "wait for the shell" means "wait for the
        # tap", which has no useful upper bound. Give it room.
        deadline = time.time() + 30
        while time.time() < deadline and not self._saw_output:
            time.sleep(0.05)
        time.sleep(0.4)              # let the login shell finish printing
        with self.cmd_lock:
            if not self._take_capture():
                self.hook_done = True
                return
            try:
                self.write((PROMPT_HOOK + "\n").encode())
                deadline = time.time() + 5
                while time.time() < deadline and self.osc_n == 0:
                    time.sleep(0.05)
                time.sleep(0.25)     # absorb the prompt redraw
                # Apply whatever the browser asked for while we were installing,
                # inline so it stays hidden under the same capture.
                pending = self.pending_resize
                self.pending_resize = None
                if pending:
                    baseline = self.osc_n
                    self.rows, self.cols = pending
                    self.write(("stty rows %d cols %d" % pending + "\n").encode())
                    if baseline:
                        self._wait_prompt(baseline, 3)
                    else:
                        time.sleep(0.4)
                    time.sleep(0.25)
            finally:
                self._free_capture()
                self.hook_done = True
        if self.osc_n:
            self.write(b"\n")   # one clean prompt to start from

    def _wait_prompt(self, baseline, timeout):
        """Block until bash prints another prompt. Returns (ok, rc, offset)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                n, rc, at = self.osc_n, self.osc_rc, self.osc_at
            if n > baseline:
                return True, rc, at
            time.sleep(0.03)
        return False, None, 0
    def _pump(self):
        fd = self.proc.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 65536)
            except Exception:
                break
            if not chunk:
                break
            self._saw_output = True
            self._emit(chunk)
        self._emit(b"\r\n[session ended]\r\n", final=True)

    def _emit(self, chunk, final=False):
        with self.lock:
            prev_len = len(self.text)
            scan = self._osc_resid + chunk
            hit = None
            for m in OSC_MARK.finditer(scan):
                hit = m
            if hit is not None:
                self.osc_n = int(hit.group(1))
                self.osc_rc = int(hit.group(2))
                cut = max(0, hit.end() - len(self._osc_resid))
                pre = ANSI.sub(b"", chunk[:cut])
                self.osc_at = self.text_base + prev_len + len(pre)
                self._osc_resid = b""
            else:
                self._osc_resid = scan[-24:]
            # While a transfer is running, remote output is the payload -- keep
            # it out of the scrollback and off the screen.
            if self.capture is not None and not final:
                self.capture.extend(chunk)
                return
            clean = ANSI.sub(b"", chunk)
            self.text.extend(clean)
            try:
                self.log.write(clean)
                self.log.flush()   # survive a crash mid-session
            except Exception:
                pass
            if clean:
                self._log_bol = clean[-1:] in (b"\n", b"\r")
            if len(self.text) > MAX_TEXT:
                drop = len(self.text) - MAX_TEXT
                del self.text[:drop]
                self.text_base += drop
            self._broadcast(chunk)
            if final:
                for q in list(self.subs):
                    try:
                        q.put_nowait(None)
                    except Exception:
                        pass

    def _broadcast(self, data):
        """Append to the replay buffer and hand the same bytes to every
        subscriber, tagged with the offset they end at.

        Everything the browser sees goes through here -- remote output, the
        attribution markers, the transfer notices -- so there is one place
        where `raw` and the subscriber queues can be trusted to agree. That
        agreement is what makes the offset meaningful, and the offset is
        what lets a reconnecting EventSource resume instead of replaying a
        scrollback the terminal already has.

        The caller holds self.lock.
        """
        self.raw.extend(data)
        if len(self.raw) > MAX_RAW:
            drop = MAX_RAW // 4
            del self.raw[:drop]
            self.raw_base += drop
        end = self.raw_base + len(self.raw)
        for q in list(self.subs):
            try:
                q.put_nowait((end, data))
            except queue.Full:
                # This browser has stopped reading. Dropping bytes would
                # corrupt its terminal silently and leave it looking fine,
                # so end the stream instead: EventSource reconnects and
                # picks up from the last id it saw.
                self.subs.remove(q)
                try:
                    q.get_nowait()          # room for the sentinel
                    q.put_nowait(None)      # unblocks _stream's loop
                except Exception:
                    pass
            except Exception:
                pass

    def _raw_since(self, offset):
        """Replay buffer from `offset` on, with the offset it ends at.

        The caller holds self.lock. An offset that has already fallen out of
        the front of the window clamps to what is still held: no worse than
        the full replay this replaced, and the common case -- a blip of a few
        seconds -- is inside the window.
        """
        start = min(max(0, offset - self.raw_base), len(self.raw))
        return bytes(self.raw[start:]), self.raw_base + len(self.raw)

    def _take_capture(self):
        """Claim the output channel. False if something else holds it."""
        with self.lock:
            if self.capture is not None:
                return False
            self.capture = bytearray()
            return True

    def _free_capture(self):
        with self.lock:
            self.capture = None

    def _drain_pending_resize(self):
        pending = self.pending_resize
        self.pending_resize = None
        if pending:
            self.resize(pending[0], pending[1])

    @property
    def alive(self):
        return self.proc.poll() is None

    def write(self, data):
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
            return True
        except Exception:
            return False

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass
        try:
            self.log.close()
        except Exception:
            pass
        # The transcript exists only to be exported while the session is
        # live. A clean close takes it with it.
        try:
            os.remove(self.log_path)
        except OSError:
            pass

    def read_text(self, since=0):
        with self.lock:
            start = max(0, since - self.text_base)
            return bytes(self.text[start:]), self.text_base + len(self.text)

    def dropped_since(self, offset):
        """Bytes that fell out of the front of the window since `offset`.

        read_text() clamps a stale offset to the start of what it still holds,
        so a command whose output overran MAX_TEXT comes back quietly short.
        Callers ask this to find out, rather than reporting a partial answer
        as if it were the whole thing. The transcript on disk is unaffected.
        """
        with self.lock:
            return max(0, self.text_base - offset)

    def resize(self, rows, cols):
        if (rows, cols) == (self.rows, self.cols):
            return False       # no-op resizes would still redraw the prompt
        # Before the prompt hook exists there is no marker to wait on, and the
        # SIGWINCH repaint would leak onto the screen. That window covers every
        # connect, because the shell says nothing until the key is touched.
        if not self.hook_done or not self.cmd_lock.acquire(False):
            self.pending_resize = (rows, cols)
            return False
        try:
            if not self._take_capture():
                self.pending_resize = (rows, cols)
                return False
            baseline = self.osc_n
            self.rows, self.cols = rows, cols
            try:
                self.write(("stty rows %d cols %d" % (rows, cols) + "\n").encode())
                if baseline:
                    self._wait_prompt(baseline, 3)
                else:
                    time.sleep(0.4)
                time.sleep(0.25)          # absorb the SIGWINCH repaint
            finally:
                self._free_capture()
        finally:
            self.cmd_lock.release()
        return True

    LOCK_WAIT = 20        # seconds to wait for another operation to finish
    HARD_CEILING = 900    # no single transfer may hold the session longer

    def _locked(self, fn, *args):
        """Serialise pty work, but never block a caller indefinitely."""
        if not self.cmd_lock.acquire(timeout=self.LOCK_WAIT):
            return {"ok": False,
                    "error": "session busy: another operation is still "
                             "running. Try again, or close the tab if it "
                             "is stuck."}
        try:
            return fn(*args)
        finally:
            self.cmd_lock.release()
            self._drain_pending_resize()

    # ---------- attribution ----------
    #
    # A session is shared, so a command an agent sends is echoed by the pty
    # exactly as a typed one is, and on screen the two are indistinguishable.
    # Twice that has been mistaken for pty corruption. The fix is a marker in
    # two places: an OSC 778 injected into the stream the browser reads, and a
    # delimiter line in the transcript.
    #
    # The OSC goes into `raw` and the subscriber queues only -- never into the
    # pty, which would hand the shell characters to interpret, and never into
    # `text`, which is what /run returns and whose offsets are load-bearing.
    # Terminals ignore an OSC they do not know, so an older browser just sees
    # nothing rather than garbage.
    #
    # The keyboard is deliberately unmarked: you are the default, and the
    # agent is the surprising one.

    API_ON = b"\x1b]778;1\x07"
    API_OFF = b"\x1b]778;0\x07"

    def _note(self, on, label=""):
        """Open or close an attributed stretch of the stream."""
        if on:
            line = "--- api %s%s ---\n" % (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                (" " + label) if label else "")
        else:
            line = "--- end api ---\n"
        with self.lock:
            osc = self.API_ON if on else self.API_OFF
            self._broadcast(osc)
            try:
                if not self._log_bol:
                    line = "\n" + line
                self.log.write(line.encode())
                self.log.flush()
                self._log_bol = True
            except Exception:
                pass

    def note_input(self):
        """Raw keystrokes sent over the API rather than typed.

        There is no command boundary to bracket here -- /input is a byte or
        two, often a Ctrl-C -- so this leaves a line in the transcript and no
        gutter mark. Marking it at all matters because a stray Ctrl-C from an
        agent looks exactly like one from the keyboard.
        """
        with self.lock:
            try:
                line = "--- api sent keystrokes %s ---\n" % time.strftime("%H:%M:%S")
                if not self._log_bol:
                    line = "\n" + line
                self.log.write(line.encode())
                self.log.flush()
                self._log_bol = True
            except Exception:
                pass

    # A cmd with a newline in it is not one command, it is several, and
    # bash prints a continuation prompt for each line after the first. Those
    # prompts are echoed back like anything else, so they land at the front
    # of the output this returns -- "> do", "> done" -- and the caller gets a
    # wrong answer that looks like a right one. Measured on a live session.
    #
    # Refusing is better than stripping them: PS2 is configurable, so any
    # strip would be guessing at the remote's shell config, and /batch
    # already does properly what a multi-line cmd was reaching for.
    MULTILINE = ("cmd contains a newline, so it is more than one command. "
                 "Bash echoes a continuation prompt for each extra line and "
                 "those end up in the output, so this is refused rather than "
                 "answered wrongly. Send one command per call, or pass the "
                 "list to /batch.")

    @staticmethod
    def _one_command(cmd):
        return "\n" not in cmd and "\r" not in cmd

    def run(self, cmd, timeout=60):
        if not self._one_command(cmd):
            return {"ok": False, "error": self.MULTILINE}
        self._note(True)
        try:
            return self._locked(self._run_locked, cmd, timeout)
        finally:
            self._note(False)

    def run_batch(self, cmds, timeout=60, stop_on_error=False):
        """Run several commands under a single acquisition of the session.

        The point is not only the saved round trips: holding the lock across
        the whole sequence means nothing else can slip a command in between
        two of yours, which is exactly what a caller writing a loop over /run
        is quietly hoping for and does not get.
        """
        for c in cmds:
            if not self._one_command(c):
                return {"ok": False,
                        "error": "%s (the offending entry was %r)"
                                 % (self.MULTILINE, c[:60])}
        self._note(True, "batch of %d" % len(cmds))
        try:
            return self._locked(self._batch_locked, cmds, timeout,
                                stop_on_error)
        finally:
            self._note(False)

    def _batch_locked(self, cmds, timeout, stop_on_error):
        results = []
        for cmd in cmds:
            r = self._run_locked(cmd, timeout)
            r["cmd"] = cmd
            results.append(r)
            if not r.get("ok"):
                break                      # session gone; the rest is noise
            if stop_on_error and (r.get("timed_out") or r.get("exit_code")):
                break
        return {"ok": True, "requested": len(cmds), "ran": len(results),
                "results": results}

    def _run_locked(self, cmd, timeout=60):
        """Run cmd, wait for it to finish, return its output and exit code.

        Preferred path: send the command exactly as typed and wait for the
        next prompt marker. Nothing extra is echoed, so the terminal shows
        what you would have typed yourself.
        """
        if self.osc_n:
            with self.lock:
                start = self.text_base + len(self.text)
                baseline = self.osc_n
            if not self.write((cmd + "\n").encode()):
                return {"ok": False, "error": "session is not writable"}
            ok, rc, at = self._wait_prompt(baseline, timeout)
            data, _ = self.read_text(start)
            if ok:
                keep = at - start
                if 0 <= keep <= len(data):
                    data = data[:keep]
            # Drop the echoed command. One line is enough however long
            # it was: readline wraps it visually and puts no break in the
            # stream, so the first newline here is the one Enter produced
            # after the whole echo. Measured on a live session at 60 and
            # 224 columns, up to 3.6x the width -- a matching-based strip
            # was tried and agreed with this in every case.
            nl = data.find(b"\n")
            out = data[nl + 1:] if nl != -1 else data
            lost = self.dropped_since(start)
            return {"ok": True, "exit_code": rc, "timed_out": not ok,
                    "truncated": lost > 0, "lost_bytes": lost,
                    "log": self.log_path if lost else None,
                    "output": out.decode("utf-8", "replace")
                                 .replace("\r", "").rstrip("\n")}

        # Fallback for shells that ignore PROMPT_COMMAND: append a sentinel,
        # built from two literals so the echoed line cannot match it.
        mark = "CCD" + uuid.uuid4().hex[:10]
        head, tail = mark[:3], mark[3:]
        payload = (f"{cmd}; __rc=$?; printf '%s%s %s\\n' '{head}' '{tail}' \"$__rc\""
                   + "\n")
        with self.lock:
            start = self.text_base + len(self.text)
        if not self.write(payload.encode()):
            return {"ok": False, "error": "session is not writable"}
        needle = mark.encode()
        deadline = time.time() + timeout
        while time.time() < deadline:
            data, _ = self.read_text(start)
            idx = data.find(needle)
            if idx != -1:
                end = data.find(b"\n", idx)
                bits = data[idx:end if end != -1 else len(data)].split()
                rc = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else None
                body = data[:idx]
                nl = body.find(b"\n")
                out = body[nl + 1:] if nl != -1 else body
                lost = self.dropped_since(start)
                return {"ok": True, "exit_code": rc, "timed_out": False,
                        "truncated": lost > 0, "lost_bytes": lost,
                        "log": self.log_path if lost else None,
                        "output": out.decode("utf-8", "replace")
                                     .replace("\r", "").rstrip("\n")}
            time.sleep(0.05)
        data, _ = self.read_text(start)
        lost = self.dropped_since(start)
        return {"ok": True, "exit_code": None, "timed_out": True,
                "truncated": lost > 0, "lost_bytes": lost,
                "log": self.log_path if lost else None,
                "output": data.decode("utf-8", "replace")
                              .replace("\r", "").rstrip("\n")}

    # ---------- file transfer ----------
    #
    # Bytes ride the session we already have, base64-encoded, so a transfer
    # costs no new SSH connection and therefore no key touch. `base64` is in
    # coreutils, so this works on very old hosts too. The trade is throughput:
    # a pty is not a bulk pipe. Use scp for anything large.

    def _notify(self, text):
        """Put a synthetic line on screen without it coming from the remote.

        Sent only when it also lands in the replay buffer. Showing a line
        the scrollback does not have would put the subscriber queues and
        `raw` out of step, and the resume offset is only worth anything
        while those two agree.
        """
        with self.lock:
            if self.capture is None:
                self._broadcast(text.encode())

    def _await_marker(self, mark, deadline):
        """Wait for the sentinel. On timeout return what did arrive, so
        the caller can report it rather than discarding the evidence.

        During a transfer the capture buffer *is* the payload, so it grows
        to tens of megabytes. Copying and re-scanning the whole of it every
        poll -- which is what this used to do -- costs more the bigger the
        file gets, twenty times a second: measured at 36ms a poll at the
        64MB ceiling, and quadratic in the file overall. The sentinel can
        only ever arrive at the end, so keep a high-water mark and search
        only what is new. The rewind covers a marker split across two polls.

        The search runs under the lock because the pump thread appends to
        the same bytearray; it is cheap now precisely because it only ever
        looks at the tail.
        """
        needle = mark.encode()
        scanned = 0                     # bytes already ruled out
        while True:
            with self.lock:
                cap = self.capture if self.capture is not None else b""
                idx = cap.find(needle, max(0, scanned - len(needle) + 1))
                scanned = len(cap)
                if idx != -1 or time.time() >= deadline:
                    return bytes(cap), idx
            time.sleep(0.05)

    def _marker(self):
        m = "TRX" + uuid.uuid4().hex[:10]
        return m, m[:3], m[3:]

    # Hash names the remote can produce, mapped to what hashlib calls them.
    HASHES = {"md5": "md5", "sha256": "sha256"}

    def _caps_locked(self):
        """What the far side can do, asked once and remembered.

        Both transfer directions want to know before they start: upload has to
        decide whether to compress *before* it sends anything, and neither can
        verify what it moved without knowing which checksum tool exists. Runs
        inside the capture so the probe never appears in the owner's terminal.
        """
        if self.caps is not None:
            return self.caps
        fallback = {"gzip": False, "hash": None}
        mark, head, tail = self._marker()
        if not self._take_capture():
            return fallback
        try:
            self.write(
                ("__g=n; command -v gzip >/dev/null 2>&1 && __g=y; "
                 "__h=none; command -v md5sum >/dev/null 2>&1 && __h=md5; "
                 "[ \"$__h\" = none ] && command -v sha256sum >/dev/null 2>&1 "
                 "&& __h=sha256; "
                 f"printf '%s%s %s %s\\n' '{head}' '{tail}' \"$__g\" \"$__h\""
                 + "\n").encode())
            buf, idx = self._await_marker(mark, time.time() + 20)
            if idx == -1:
                return fallback           # not cached: worth retrying later
            line_end = buf.find(b"\n", idx)
            bits = buf[idx:line_end if line_end != -1 else len(buf)].split()
            gz = len(bits) > 1 and bits[1] == b"y"
            alg = bits[2].decode() if len(bits) > 2 else "none"
            self.caps = {"gzip": gz, "hash": self.HASHES.get(alg)}
            return self.caps
        finally:
            self._free_capture()

    @staticmethod
    def _digest(alg, data):
        return hashlib.new(alg, data).hexdigest() if alg else None

    def download(self, path, timeout=180, max_bytes=None):
        timeout = min(timeout, self.HARD_CEILING)
        return self._locked(self._download_locked, path, timeout, max_bytes)

    def _download_locked(self, path, timeout=180, max_bytes=None):
        caps = self._caps_locked()
        end, e_head, e_tail = self._marker()
        beg, b_head, b_tail = self._marker()
        quoted = shlex.quote(path)   # the path may contain quotes
        self._notify(f"\r\n[transfer] reading {path} ...\r\n")
        if not self._take_capture():
            return {"ok": False, "error": "session is busy; try again"}
        try:
            alg = caps["hash"]
            # Hash the file as it is on disk, before any compression, so the
            # check covers what the user actually asked for.
            sumcmd = (f"__s=$({alg}sum {quoted} | cut -d' ' -f1); "
                      if alg else "__s=none; ")
            # gzip first where it exists: base64 inflates by a third, and the
            # files that ride this channel are configs and logs, which compress
            # several fold. The pipeline's own status is unreliable (base64
            # happily succeeds on gzip's empty output), so readability is
            # checked up front and the checksum is the real backstop.
            encode = (f"gzip -c {quoted} | base64" if caps["gzip"]
                      else f"base64 {quoted}")
            mode = "gz" if caps["gzip"] else "raw"
            # The size gate runs on the remote, before anything is encoded:
            # refusing after the bytes have crossed the pty would spend
            # exactly the memory the cap exists to protect. __sz is empty for
            # anything wc cannot measure -- /proc, a pipe -- and the test
            # below lets those through, as it did before there was a gate.
            if max_bytes:
                measure = f"__sz=$(wc -c < {quoted} 2>/dev/null); "
                gate = (f"elif [ -n \"$__sz\" ] && "
                        f"[ \"$__sz\" -gt {max_bytes} ]; then "
                        f"__rc=67; __s=$__sz; "
                        f"printf '%s%s\\n' '{b_head}' '{b_tail}'; ")
            else:
                measure = gate = ""
            self.write(
                (measure +
                 f"if [ ! -r {quoted} ]; then __rc=66; __s=none; "
                 f"printf '%s%s\\n' '{b_head}' '{b_tail}'; "
                 f"{gate}"
                 f"else {sumcmd}"
                 f"printf '%s%s\\n' '{b_head}' '{b_tail}'; "
                 f"{encode}; __rc=$?; fi; "
                 f"printf '%s%s %s %s\\n' '{e_head}' '{e_tail}' \"$__rc\" \"$__s\""
                 + "\n").encode())
            buf, idx = self._await_marker(end, time.time() + timeout)
            if idx == -1:
                snippet = buf[-300:].decode("utf-8", "replace")
                return {"ok": False,
                        "error": "timed out reading %s; remote said: %r"
                                 % (path, snippet)}
            line_end = buf.find(b"\n", idx)
            bits = buf[idx:line_end if line_end != -1 else len(buf)].split()
            rc = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 1
            remote_sum = bits[2].decode() if len(bits) > 2 else "none"
            if rc == 67:
                # __s carries the size in this branch, not a checksum.
                size = int(remote_sum) if remote_sum.isdigit() else max_bytes + 1
                return {"ok": False, "error": over_cap(size, path, max_bytes)}
            if rc != 0:
                return {"ok": False,
                        "error": "remote could not read %s (rc=%d): missing "
                                 "file, a directory, or no permission"
                                 % (path, rc)}

            # Slice between the two markers rather than "drop the first line".
            # The echoed command wraps at the terminal width, so a long one
            # spans several lines and the old rule left the tail of it sitting
            # in front of the payload -- where anything in the base64 alphabet
            # would have been welded silently into the file.
            bidx = buf.find(beg.encode())
            if bidx == -1:
                return {"ok": False, "error": "remote never signalled the "
                                              "start of the payload"}
            body_start = buf.find(b"\n", bidx)
            body = buf[body_start + 1:idx] if body_start != -1 else b""
            body = ANSI.sub(b"", body)
            body = re.sub(rb"[^A-Za-z0-9+/=]", b"", body)
            try:
                raw = base64.b64decode(body)
            except Exception as exc:
                return {"ok": False, "error": "could not decode payload: %s" % exc}
            if mode == "gz":
                try:
                    raw = gzip.decompress(raw)
                except Exception as exc:
                    return {"ok": False,
                            "error": "payload did not decompress: %s" % exc}

            verified = False
            if alg and remote_sum != "none":
                local = self._digest(alg, raw)
                if local != remote_sum:
                    return {"ok": False,
                            "error": "checksum mismatch: remote %s %s, got %s "
                                     "-- the transfer was corrupted, the file "
                                     "was not saved" % (alg, remote_sum, local)}
                verified = True
            return {"ok": True, "size": len(raw), "compressed": mode == "gz",
                    "verified": verified, "algorithm": alg,
                    "b64": base64.b64encode(raw).decode()}
        finally:
            self._free_capture()
            self._notify(f"[transfer] done: {path}\r\n")

    def upload(self, path, payload, timeout=300):
        timeout = min(timeout, self.HARD_CEILING)
        return self._locked(self._upload_locked, path, payload, timeout)

    def _upload_locked(self, path, payload, timeout=300):
        caps = self._caps_locked()
        mark, head, tail = self._marker()
        quoted = shlex.quote(path)   # the path may contain quotes
        # Compress before encoding where the far side can undo it. This is
        # decided here, not on the remote, because the bytes have to be shaped
        # before they are sent -- which is why capabilities are probed first.
        alg = caps["hash"]
        wire = gzip.compress(payload, 6) if caps["gzip"] else payload
        mode = "gz" if caps["gzip"] else "raw"
        # A gzip of already-compressed data can come out larger; sending more
        # bytes than we were given would be a silly way to lose.
        if mode == "gz" and len(wire) >= len(payload):
            wire, mode = payload, "raw"
        sink = (f"base64 -d | gunzip -c > {quoted}" if mode == "gz"
                else f"base64 -d > {quoted}")
        shown = len(payload)
        if mode == "gz":
            self._notify(f"\r\n[transfer] writing {shown} bytes to {path} "
                         f"({len(wire)} on the wire) ...\r\n")
        else:
            self._notify(f"\r\n[transfer] writing {shown} bytes to {path} ...\r\n")
        if not self._take_capture():
            return {"ok": False, "error": "session is busy; try again"}
        try:
            # -echo first: without it the remote pty echoes the whole payload
            # back at us, doubling the traffic for nothing.
            #
            # stty applies settings with a flush, discarding whatever is
            # already queued in the pty input buffer. Everything sent in the
            # same breath is silently thrown away -- so wait for the prompt
            # before sending the command that matters.
            #
            # ignoreeof goes on for the duration, remembering what it was. The
            # payload ends in a Ctrl-D, and if anything makes the receiver
            # quit early -- a full disk, a decode error -- the rest of the
            # payload lands at the prompt and that Ctrl-D logs the shell out,
            # which costs a key touch to undo.
            baseline = self.osc_n
            self.write(b"stty -echo; __ieo=$(shopt -po ignoreeof 2>/dev/null); "
                       b"set -o ignoreeof 2>/dev/null\n")
            if baseline:
                self._wait_prompt(baseline, 5)
            else:
                time.sleep(0.4)
            # Bash re-sets the terminal before handing it to a child, which
            # discards type-ahead. Sending the payload immediately after the
            # command loses it -- the file gets created, and stays empty. So
            # have the remote announce that it is about to read, and only
            # then send the bytes.
            #
            # Only announce ready once the target is known to be writable. The
            # redirect failing after the announcement -- a missing directory,
            # say -- used to mean the payload was typed at the prompt and run
            # line by line as commands, then the Ctrl-D logged the shell out.
            # The refusal carries the same token with NO in front, so one wait
            # covers both answers; printf writes it in one go, so the prefix
            # is always there by the time the token is.
            rdy = "RDY" + uuid.uuid4().hex[:10]
            self.write((f"if : > {quoted} 2>/dev/null; then "
                        f"printf '%s%s' '{rdy[:3]}' '{rdy[3:]}'; {sink}; "
                        f"else stty echo; eval \"$__ieo\"; "
                        f"printf '%s%s%s\\n' 'NO' '{rdy[:3]}' '{rdy[3:]}'; fi"
                        + "\n").encode())
            buf, ridx = self._await_marker(rdy, time.time() + 15)
            if ridx == -1:
                return {"ok": False,
                        "error": "remote never signalled ready to receive"}
            if buf[max(0, ridx - 2):ridx] == b"NO":
                return {"ok": False,
                        "error": "cannot write %s on the remote: missing "
                                 "directory, a directory in the way, or no "
                                 "permission; nothing was sent" % path}
            # Lines stay at 76 characters -- canonical mode caps how long a
            # line the remote pty will take -- but there is no reason to
            # spend a write on each of them. A 20MB upload is 350k lines,
            # and sending them one at a time measured 5.6x the cost of the
            # same lines in 32KB blocks. That is a couple of percent of the
            # transfer rather than the reason uploads are slower than
            # downloads, which is the remote's line discipline; it is just
            # free. A large write blocking here is backpressure, and clears.
            blob = base64.b64encode(wire)
            block = bytearray()
            for i in range(0, len(blob), 76):
                block += blob[i:i + 76]
                block += b"\n"
                if len(block) >= 32768:
                    self.write(bytes(block))
                    del block[:]
            if block:
                self.write(bytes(block))
            self.write(b"\x04")                      # EOF -> base64 finishes
            # Checksum the file as it landed, so the answer covers the whole
            # path -- encode, pty, decode and decompress -- not just the count
            # of bytes that arrived. wc -c stays as a cheap second opinion.
            sumcmd = (f"\"$({alg}sum {quoted} | cut -d' ' -f1)\""
                      if alg else "none")
            self.write(
                (f"__rc=$?; stty echo; eval \"$__ieo\"; "
                 f"printf '%s%s %s %s %s\\n' '{head}' '{tail}' \"$__rc\" "
                 f"\"$(wc -c < {quoted} 2>/dev/null)\" {sumcmd}"
                 + "\n").encode())
            buf, idx = self._await_marker(mark, time.time() + timeout)
            if idx == -1:
                said = buf[-300:].decode("utf-8", "replace")
                return {"ok": False,
                        "error": "timed out writing %s; remote said: %r"
                                 % (path, said)}
            line_end = buf.find(b"\n", idx)
            bits = buf[idx:line_end if line_end != -1 else len(buf)].split()
            rc = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 1
            size = int(bits[2]) if len(bits) > 2 and bits[2].isdigit() else -1
            remote_sum = bits[3].decode() if len(bits) > 3 else "none"
            if rc != 0:
                return {"ok": False, "error": "remote write failed (rc=%d)" % rc}
            if size != len(payload):
                return {"ok": False, "error": "size mismatch: sent %d, landed %d"
                                              % (len(payload), size)}
            verified = False
            if alg and remote_sum != "none":
                local = self._digest(alg, payload)
                if local != remote_sum:
                    return {"ok": False,
                            "error": "checksum mismatch: sent %s %s, landed %s "
                                     "-- %s on the remote is corrupt and should "
                                     "not be trusted" % (alg, local, remote_sum,
                                                         path)}
                verified = True
            return {"ok": True, "size": size, "path": path,
                    "compressed": mode == "gz", "wire_bytes": len(wire),
                    "verified": verified, "algorithm": alg}
        finally:
            self._free_capture()
            self._notify(f"[transfer] done: {path}\r\n")

    def info(self):
        return {
            "name": self.name,
            "kind": "shell",
            "host": self.name,
            "target": self.target,
            "auth": self.auth,
            "proxy_jump": self.proxy_jump,
            "log": self.log_path,
            "alive": self.alive,
            # Absolute, like the one read_text hands back: len(text)
            # alone silently stops matching it once the window wraps.
            "offset": self.text_base + len(self.text),
            "rows": self.rows,
            "cols": self.cols,
            "uptime": int(time.time() - self.started),
        }


# ----------------------------------------------------------------- local disk
#
# The browser cannot enumerate the machine it is running on -- a page only ever
# sees what a picker or a drop hands it -- so the local half of the two-pane
# transfer view is served from here instead. This widens what the API can
# reach, to this disk, but not who can reach it: the same token already opens
# an SSH session to every saved host, which is strictly the larger power.


def local_path(raw):
    """A path from the browser, resolved to an absolute local one."""
    p = (raw or "").strip()
    if not p:
        return os.path.expanduser("~")
    return os.path.abspath(os.path.expanduser(p))


def local_drives():
    """Drive roots, so the pane always has somewhere to start from."""
    if os.name != "nt":
        return ["/"]
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        return []
    # A bitmask, not a probe: touching a disconnected network drive to see
    # whether it is there can block for seconds.
    return ["%s:\\" % chr(65 + i) for i in range(26) if mask >> i & 1]


def local_entries(path):
    """One local directory, in the shape the remote listing already uses."""
    out = []
    with os.scandir(path) as it:
        for e in it:
            try:
                st = e.stat(follow_symlinks=False)
                isdir = e.is_dir()
            except OSError:
                continue          # a link to nowhere, or nothing we may read
            out.append({"name": e.name, "dir": isdir, "link": e.is_symlink(),
                        "size": 0 if isdir else st.st_size,
                        "mtime": int(st.st_mtime),
                        "mode": statmod.S_IMODE(st.st_mode)})
    out.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return out


def channel(fn):
    """Serialise one Transfer operation and apply the session's error policy.

    Every operation below opened with `with self.io:` and closed with the
    same three lines: an unexpected exception means the channel is out of
    step -- a half-read reply, a length that did not match -- and nothing
    further on it can be trusted, so the session is marked dead rather than
    left to desynchronise quietly. That policy was right. It was just
    asserted once per method, which is one place per method for the next
    one to forget it.

    Operations return (value, error). `busy` is cleared here too, because a
    transfer that died partway must not leave a progress line running.
    """
    @functools.wraps(fn)
    def guarded(self, *args, **kwargs):
        with self.io:
            try:
                return fn(self, *args, **kwargs)
            except Exception as exc:
                self.busy = None
                self.alive = False
                return None, str(exc)
    return guarded


class Transfer:
    """A file-transfer session: one connection, speaking SFTP on the wire.

    Its own connection, so it costs its own key touch -- but only one, for the
    whole session, however many files move through it. scp would be a touch
    per file; this is a touch per sitting.

    It talks to `ssh -s sftp` rather than driving the `sftp` command, because
    the interactive client is built for humans and behaves like it: over a pipe
    its stdout is line-buffered, so the `sftp> ` prompt -- six bytes with no
    newline -- never arrives until some later output completes a line. There is
    no terminator to wait for. The binary protocol underneath has an explicit
    length on every packet, so there is nothing to guess: read four bytes, then
    read exactly that many. It also returns numeric error codes instead of
    English, and lets this class see every chunk, which is where progress
    comes from.

    A peer of Session, not a mode of it: the shell keeps its pty and stays
    usable while files move, which the in-band transfer cannot do because it
    holds the session lock for the duration.
    """

    # draft-ietf-secsh-filexfer-02, the version OpenSSH speaks.
    INIT, VERSION = 1, 2
    OPEN, CLOSE, READ, WRITE = 3, 4, 5, 6
    LSTAT, FSTAT, SETSTAT = 7, 8, 9
    OPENDIR, READDIR = 11, 12
    REMOVE, MKDIR, RMDIR, REALPATH, STAT, RENAME = 13, 14, 15, 16, 17, 18
    STATUS, HANDLE, DATA, NAME, ATTRS = 101, 102, 103, 104, 105

    OK, EOF, NO_SUCH_FILE, PERMISSION_DENIED = 0, 1, 2, 3
    ERRORS = {1: "end of file", 2: "no such file", 3: "permission denied",
              4: "failure", 5: "bad message", 6: "no connection",
              7: "connection lost", 8: "operation not supported"}

    F_READ, F_WRITE, F_CREAT, F_TRUNC = 0x1, 0x2, 0x8, 0x10
    A_SIZE, A_UIDGID, A_PERMS, A_TIME = 0x1, 0x2, 0x4, 0x8

    CHUNK = 32768            # what OpenSSH's own client uses
    WINDOW = 64              # requests in flight; OpenSSH's client keeps 64 too
    CONNECT_TIMEOUT = 120    # generous: a touch-required key waits on a human

    def __init__(self, name, host, target, key=None, auth="key", cert=None,
                 password=None, port=None, proxy_jump=None):
        self.name = name
        self.host = host
        self.target = target
        self.kind = "transfer"
        self.auth = auth
        self.key = expand(key) or default_key()
        self.cert = expand(cert)
        self.port = port
        self.proxy_jump = proxy_jump
        self.started = time.time()
        self.alive = False
        self.last_error = None
        self.cwd = "."
        self.busy = None          # {op, path, done, total} while a file moves
        # A whole-tree copy spans many files, so its progress cannot live in
        # `busy` -- that is reset per file. `joblock` keeps two of them off the
        # same tab, since they interleave badly and the progress would lie.
        self.job = None           # {op, from, to, files_done, files_total, current}
        self.joblock = threading.Lock()
        self.io = threading.Lock()
        self._id = 0

        opts, env = connection_opts(port, proxy_jump, auth, self.key,
                                    self.cert, password)
        cmd = [ssh_binary()] + opts
        if port:
            cmd += ["-p", str(port)]
        cmd += ["-s", target, "sftp"]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env, cwd=HERE)
        try:
            self._send(self.INIT, struct.pack(">I", 3))
            kind, body = self._recv(self.CONNECT_TIMEOUT)
            if kind != self.VERSION:
                raise OSError("expected VERSION, got packet type %d" % kind)
            self.alive = True
            self.cwd = self.realpath(".") or "."
        except Exception as exc:
            self.alive = False
            self.last_error = self._why(exc)
            # Never leave the attempt running: a failed open otherwise orphans
            # an ssh with nothing tracking it.
            try:
                self.proc.kill()
                self.proc.wait(timeout=5)
            except Exception:
                pass

    def _why(self, exc):
        """Prefer ssh's own complaint over our view of a closed pipe."""
        try:
            err = self.proc.stderr.read().decode("utf-8", "replace").strip()
        except Exception:
            err = ""
        return err or str(exc) or "sftp subsystem did not start"

    # ---------- wire ----------

    @staticmethod
    def _s(b):
        """SFTP strings are length-prefixed, not terminated."""
        return struct.pack(">I", len(b)) + b

    def _send(self, kind, payload=b""):
        pkt = bytes([kind]) + payload
        self.proc.stdin.write(struct.pack(">I", len(pkt)) + pkt)
        self.proc.stdin.flush()

    def _readn(self, n, deadline):
        buf = b""
        while len(buf) < n:
            if time.time() > deadline:
                raise TimeoutError("timed out reading from the sftp channel")
            chunk = self.proc.stdout.read(n - len(buf))
            if not chunk:
                raise EOFError("sftp channel closed")
            buf += chunk
        return buf

    def _recv(self, timeout=60):
        deadline = time.time() + timeout
        (ln,) = struct.unpack(">I", self._readn(4, deadline))
        if ln == 0 or ln > 34_000_000:
            raise OSError("implausible packet length %d" % ln)
        body = self._readn(ln, deadline)
        return body[0], body[1:]

    def _next_id(self):
        self._id = (self._id + 1) & 0xFFFFFFFF
        return self._id

    def _send_req(self, kind, payload):
        """Put a request on the wire and return its id, without waiting."""
        if not self.alive:
            raise OSError("transfer session is not connected")
        rid = self._next_id()
        self._send(kind, struct.pack(">I", rid) + payload)
        return rid

    def _recv_reply(self, timeout=60):
        """One reply, tagged with the id of the request it answers.

        Every reply type -- STATUS, HANDLE, DATA, NAME, ATTRS -- begins with
        that id, and the body is handed back with it still attached, because
        every parser below counts from there.
        """
        rkind, body = self._recv(timeout)
        (rid,) = struct.unpack(">I", body[0:4])
        return rid, rkind, body

    def _request(self, kind, payload, timeout=60):
        """One request, its own reply.

        The channel is a single stream but no longer a strictly alternating
        one: get and put keep a window of requests open. A server may answer
        out of order, so this waits for the id it sent rather than trusting
        the next packet to be its own. The bound stops a confused peer from
        holding the call here for ever.
        """
        rid = self._send_req(kind, payload)
        for _ in range(self.WINDOW * 4):
            rrid, rkind, body = self._recv_reply(timeout)
            if rrid == rid:
                return rkind, body
        raise OSError("sftp channel out of step: no reply to request %d" % rid)

    def _drain(self, pending, timeout):
        """Take the replies to requests we gave up on off the wire.

        A windowed transfer that stops early -- an error, a refusal partway --
        leaves replies still coming. They have to be consumed before anything
        else is sent, or the next operation reads the tail of this one. If
        they cannot be, the channel is no longer trustworthy and the session
        is marked dead rather than left to desynchronise silently.
        """
        left = set(pending)
        while left:
            try:
                rid, _, _ = self._recv_reply(timeout)
            except Exception:
                self.alive = False
                return
            left.discard(rid)

    def _status(self, body):
        code = struct.unpack(">I", body[4:8])[0]
        msg = ""
        if len(body) >= 12:
            (mlen,) = struct.unpack(">I", body[8:12])
            msg = body[12:12 + mlen].decode("utf-8", "replace")
        return code, msg or self.ERRORS.get(code, "error %d" % code)

    def _expect(self, rkind, body, want):
        if rkind == want:
            return None
        if rkind == self.STATUS:
            code, msg = self._status(body)
            return msg if code != self.OK else None
        return "unexpected reply type %d" % rkind

    @staticmethod
    def _attrs(body, off):
        """Parse an ATTRS blob; returns (dict, new offset)."""
        (flags,) = struct.unpack(">I", body[off:off + 4]); off += 4
        a = {}
        if flags & Transfer.A_SIZE:
            (a["size"],) = struct.unpack(">Q", body[off:off + 8]); off += 8
        if flags & Transfer.A_UIDGID:
            off += 8
        if flags & Transfer.A_PERMS:
            (a["perms"],) = struct.unpack(">I", body[off:off + 4]); off += 4
        if flags & Transfer.A_TIME:
            a["atime"], a["mtime"] = struct.unpack(">II", body[off:off + 8])
            off += 8
        if flags & 0x80000000:
            (n,) = struct.unpack(">I", body[off:off + 4]); off += 4
            for _ in range(n * 2):
                (l,) = struct.unpack(">I", body[off:off + 4]); off += 4 + l
        return a, off

    # ---------- paths ----------

    def _abs(self, path):
        if not path:
            return self.cwd
        if path.startswith("/"):
            return path
        return (self.cwd.rstrip("/") + "/" + path) if self.cwd != "." else path

    def realpath(self, path):
        rkind, body = self._request(self.REALPATH, self._s(self._abs(path).encode()))
        if rkind != self.NAME:
            return None
        off = 8                                   # request id + count
        (nlen,) = struct.unpack(">I", body[off:off + 4]); off += 4
        return body[off:off + nlen].decode("utf-8", "replace")

    # ---------- operations ----------

    @channel
    def pwd(self):
        return self.cwd, None

    @channel
    def chdir(self, path):
        target = self.realpath(path)
        if target is None:
            return None, "no such directory: %s" % path
        rkind, body = self._request(self.STAT, self._s(target.encode()))
        if rkind == self.STATUS:
            _, msg = self._status(body)
            return None, msg
        a, _ = self._attrs(body, 4)
        if not (a.get("perms", 0) & 0o040000):
            return None, "not a directory: %s" % target
        self.cwd = target
        return self.cwd, None

    @channel
    def listdir(self, path=""):
        target = self.realpath(path) if path else self.cwd
        if target is None:
            return None, "no such directory: %s" % path
        rkind, body = self._request(self.OPENDIR, self._s(target.encode()))
        err = self._expect(rkind, body, self.HANDLE)
        if err:
            return None, err
        (hlen,) = struct.unpack(">I", body[4:8])
        handle = body[8:8 + hlen]
        entries = []
        while True:
            rkind, body = self._request(self.READDIR, self._s(handle))
            if rkind == self.STATUS:
                code, msg = self._status(body)
                if code == self.EOF:
                    break
                self._request(self.CLOSE, self._s(handle))
                return None, msg
            off = 4
            (count,) = struct.unpack(">I", body[off:off + 4]); off += 4
            for _ in range(count):
                (nlen,) = struct.unpack(">I", body[off:off + 4]); off += 4
                nm = body[off:off + nlen].decode("utf-8", "replace"); off += nlen
                (llen,) = struct.unpack(">I", body[off:off + 4]); off += 4
                off += llen                       # longname, unused
                a, off = self._attrs(body, off)
                if nm in (".", ".."):
                    continue
                perms = a.get("perms", 0)
                entries.append({
                    "name": nm,
                    "dir": bool(perms & 0o040000),
                    "link": (perms & 0o170000) == 0o120000,
                    "size": a.get("size", 0),
                    "mtime": a.get("mtime", 0),
                    "mode": perms & 0o7777,
                })
        self._request(self.CLOSE, self._s(handle))
        entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
        return entries, None

    @channel
    def get(self, path, timeout=900, sink=None, max_bytes=None):
        """Fetch a remote file.

        With `sink` -- any writable binary file that can seek -- chunks are
        written into it as they land rather than gathered in memory, and the
        byte count comes back instead of the bytes. That is what lets a copy
        to disk be bounded by the disk rather than by RAM: the 64 MB ceiling
        is a property of holding the whole file, not of the protocol.
        """
        target = self._abs(path)
        total, bounded = 0, False
        rkind, body = self._request(self.STAT, self._s(target.encode()))
        if rkind == self.ATTRS:
            a, _ = self._attrs(body, 4)
            total = a.get("size", 0)
            if a.get("perms", 0) & 0o040000:
                return None, "%s is a directory" % target
            # A size worth sizing the window by. Without one -- /proc,
            # or a server that does not report it -- the window stays
            # open and EOF is what stops the loop.
            bounded = "size" in a
            # Refuse before opening the file, not after reading it:
            # the ceiling only applies when the bytes are being
            # gathered in memory, which is exactly when sink is None.
            if sink is None and max_bytes and total > max_bytes:
                return None, over_cap(total, target, max_bytes)
        rkind, body = self._request(
            self.OPEN, self._s(target.encode()) +
            struct.pack(">II", self.F_READ, 0))
        err = self._expect(rkind, body, self.HANDLE)
        if err:
            return None, err
        (hlen,) = struct.unpack(">I", body[4:8])
        handle = body[8:8 + hlen]
        self.busy = {"op": "get", "path": target, "done": 0, "total": total}
        # Reads overlap: one 32k request at a time made throughput a
        # function of the round trip rather than the link. Requests are
        # ~30 bytes, so a full window of them cannot fill the pipe to
        # ssh, and the loop takes a reply off the wire every time round
        # -- which is what keeps one thread from wedging against itself.
        pending, chunks, spans = {}, {}, []
        got, next_off, eof, fail = 0, 0, False, None
        try:
            while True:
                while not eof:
                    # Past the size STAT gave, keep just one read in
                    # flight: the file may have grown since, and one
                    # probe settles that without aiming a whole window
                    # at a file that has already ended.
                    room = self.WINDOW if not bounded or next_off < total else 1
                    if len(pending) >= room:
                        break
                    rid = self._send_req(
                        self.READ, self._s(handle) +
                        struct.pack(">QI", next_off, self.CHUNK))
                    pending[rid] = (next_off, self.CHUNK)
                    next_off += self.CHUNK
                if not pending:
                    break
                rid, rkind, body = self._recv_reply(timeout)
                if rid not in pending:
                    continue
                off, want = pending.pop(rid)
                if rkind == self.STATUS:
                    code, msg = self._status(body)
                    if code == self.EOF:
                        eof = True
                        continue
                    fail = msg
                    break
                (dlen,) = struct.unpack(">I", body[4:8])
                if dlen == 0:
                    eof = True
                    continue
                if sink is not None:
                    sink.seek(off)
                    sink.write(body[8:8 + dlen])
                else:
                    chunks[off] = bytes(body[8:8 + dlen])
                # Kept either way: the spans are what prove the file
                # arrived whole, and they cost 16 bytes per chunk
                # rather than the chunk itself.
                spans.append((off, dlen))
                got += dlen
                self.busy["done"] = got
                # A short read is allowed: the server may answer with
                # less than was asked for, and the rest of that span
                # still has to be fetched or the file arrives holed.
                if dlen < want:
                    rid = self._send_req(
                        self.READ, self._s(handle) +
                        struct.pack(">QI", off + dlen, want - dlen))
                    pending[rid] = (off + dlen, want - dlen)
        finally:
            self._drain(pending, timeout)
            if self.alive:
                self._request(self.CLOSE, self._s(handle))
            self.busy = None
        if fail:
            return None, fail
        # Chunks arrive in whatever order the server answered, so the
        # spans are walked in order. A gap is reported rather than
        # closed up: once the hole is gone a short file is
        # indistinguishable from a whole one.
        out, end = bytearray(), 0
        for off, ln in sorted(spans):
            if off != end:
                return None, "hole in %s at offset %d" % (target, end)
            if sink is None:
                out.extend(chunks[off])
            end = off + ln
        return (got if sink is not None else bytes(out)), None

    @channel
    def put(self, payload, path, timeout=900, source=None, size=None):
        """Send a file to the remote.

        With `source` -- a readable binary file -- and its `size`, the bytes
        are read a chunk at a time as the window advances instead of being
        held whole, and `payload` is ignored. Same reason as `get`: a copy
        from disk should not be capped by memory.
        """
        target = self._abs(path)
        rkind, body = self._request(
            self.OPEN, self._s(target.encode()) +
            struct.pack(">II", self.F_WRITE | self.F_CREAT | self.F_TRUNC, 0))
        err = self._expect(rkind, body, self.HANDLE)
        if err:
            return None, err
        (hlen,) = struct.unpack(">I", body[4:8])
        handle = body[8:8 + hlen]
        total = len(payload) if source is None else size
        self.busy = {"op": "put", "path": target,
                     "done": 0, "total": total}
        # Writes overlap the same way reads do. The safety argument is
        # the other way round here: the requests are large but every
        # answer is a 24-byte STATUS, so a full window of unread
        # replies is under 2k and ssh never blocks writing them back.
        # It can block reading our stdin when the far end is slow --
        # that is backpressure doing its job, and it clears.
        pending = {}
        off, acked, fail = 0, 0, None
        try:
            while True:
                while off < total and len(pending) < self.WINDOW:
                    chunk = (source.read(self.CHUNK) if source is not None
                             else payload[off:off + self.CHUNK])
                    if not chunk:
                        total = off      # the file was shorter than stat said
                        break
                    rid = self._send_req(
                        self.WRITE, self._s(handle) +
                        struct.pack(">Q", off) + self._s(chunk))
                    pending[rid] = len(chunk)
                    off += len(chunk)
                if not pending:
                    break
                rid, rkind, body = self._recv_reply(timeout)
                if rid not in pending:
                    continue
                n = pending.pop(rid)
                if rkind != self.STATUS:
                    fail = "unexpected reply type %d" % rkind
                    break
                code, msg = self._status(body)
                if code != self.OK:
                    fail = msg or "write failed"
                    break
                acked += n
                self.busy["done"] = acked
        finally:
            self._drain(pending, timeout)
            if self.alive:
                self._request(self.CLOSE, self._s(handle))
            self.busy = None
        if fail:
            return None, fail
        return total, None
    def _simple(self, kind, payload):
        """A request whose only answer is a STATUS: mkdir, rm, rename."""
        rkind, body = self._request(kind, payload)
        if rkind != self.STATUS:
            return None, "unexpected reply type %d" % rkind
        code, msg = self._status(body)
        return (True, None) if code == self.OK else (None, msg)

    @channel
    def mkdir(self, path):
        target = self._abs(path)
        # Empty attribute block: let the remote apply its own umask.
        return self._simple(self.MKDIR,
                            self._s(target.encode()) + struct.pack(">I", 0))

    @channel
    def remove(self, path):
        """Delete a file, or an empty directory.

        Which opcode to send depends on what the thing is, so it is stat-ed
        first rather than guessed. Directories go through RMDIR, which fails on
        a non-empty one -- deliberately: there is no recursive delete here, so
        a mis-click cannot take a tree with it.
        """
        target = self._abs(path)
        rkind, body = self._request(self.LSTAT, self._s(target.encode()))
        if rkind == self.STATUS:
            _, msg = self._status(body)
            return None, msg
        a, _ = self._attrs(body, 4)
        isdir = bool(a.get("perms", 0) & 0o040000)
        return self._simple(self.RMDIR if isdir else self.REMOVE,
                            self._s(target.encode()))

    @channel
    def rename(self, old, new):
        a, b = self._abs(old), self._abs(new)
        return self._simple(self.RENAME,
                            self._s(a.encode()) + self._s(b.encode()))

    # ---------- whole-tree copies, disk to remote and back ----------
    #
    # These exist because the browser cannot see the disk it runs on. The
    # local half of the two-pane view is served from here instead, and once
    # the server knows both ends there is no reason to route the bytes
    # through the page: a copy is disk -> ssh -> remote, never base64 through
    # a JSON body, and never held whole in memory.

    @channel
    def stat(self, path):
        """ATTRS for one remote path -- size and mode, or an error."""
        rkind, body = self._request(self.STAT,
                                    self._s(self._abs(path).encode()))
        err = self._expect(rkind, body, self.ATTRS)
        if err:
            return None, err
        a, _ = self._attrs(body, 4)
        return a, None
    def _isdir(self, attrs):
        return bool(attrs.get("perms", 0) & 0o040000)

    def _walk_remote(self, path, depth=0):
        """Every directory and every file under `path`, in one pass.

        pull used to count the tree and then copy it: two full sets of
        OPENDIR/READDIR round trips for one operation, and on a deep tree
        over a slow link the count was half the cost of the copy it was
        describing. Both passes wanted the same listing, so it is taken once
        and kept -- a path per entry, which is nothing beside the bytes that
        are about to move.

        The depth bound is what stops a symlink loop, exactly as before.
        Raises OSError so a failure to list is reported rather than silently
        counted as an empty directory.
        """
        if depth > 40:
            raise OSError("directory nesting is deeper than 40 levels")
        entries, err = self.listdir(path)
        if err:
            raise OSError(err)
        dirs, files = [path], []
        for e in entries:
            child = path.rstrip("/") + "/" + e["name"]
            if e["dir"]:
                sub_dirs, sub_files = self._walk_remote(child, depth + 1)
                dirs += sub_dirs
                files += sub_files
            else:
                files.append(child)
        return dirs, files

    def _pull_file(self, remote, local, timeout):
        self.job["current"] = remote
        parent = os.path.dirname(local)
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as exc:
                return None, str(exc)
        # Written beside the target and moved into place, so an interrupted
        # copy leaves no half file wearing the real name.
        part = local + ".part"
        try:
            with open(part, "wb") as fh:
                n, err = self.get(remote, timeout, sink=fh)
            if err:
                os.remove(part)
                return None, err
            os.replace(part, local)
        except OSError as exc:
            try:
                os.remove(part)
            except OSError:
                pass
            return None, str(exc)
        self.job["files_done"] += 1
        return n, None

    def _pull_tree(self, src, local, dirs, files, timeout):
        """Copy a tree that _walk_remote has already listed.

        Directories are made first, all of them, so no file can arrive
        before the directory that is to hold it -- which the old
        interleaved walk guaranteed only by accident of ordering.
        """
        base = src.rstrip("/")

        def local_of(remote):
            rel = remote[len(base):].strip("/")
            return os.path.join(local, *rel.split("/")) if rel else local

        for d in dirs:
            try:
                os.makedirs(local_of(d), exist_ok=True)
            except OSError as exc:
                return str(exc)
        for f in files:
            _, err = self._pull_file(f, local_of(f), timeout)
            if err:
                return err
        return None

    def pull(self, remote, local, timeout=900, recursive=False):
        """Remote -> local disk. `local` is already an absolute local path."""
        if not self.joblock.acquire(blocking=False):
            return None, "a copy is already running on this tab"
        try:
            src = self._abs(remote)
            attrs, err = self.stat(src)
            if err:
                return None, err
            isdir = self._isdir(attrs)
            if isdir and not recursive:
                return None, "%s is a directory -- pass recursive" % src
            self.job = {"op": "pull", "from": src, "to": local,
                        "files_done": 0, "files_total": 1, "current": ""}
            if not isdir:
                n, err = self._pull_file(src, local, timeout)
                return (None, err) if err else ({"files": 1, "bytes": n}, None)
            try:
                dirs, files = self._walk_remote(src)
            except OSError as exc:
                return None, str(exc)
            self.job["files_total"] = len(files)
            err = self._pull_tree(src, local, dirs, files, timeout)
            if err:
                return None, err
            return {"files": self.job["files_done"], "bytes": None}, None
        finally:
            self.job = None
            self.joblock.release()

    def _push_file(self, local, remote, timeout):
        self.job["current"] = local
        try:
            size = os.path.getsize(local)
            with open(local, "rb") as fh:
                n, err = self.put(None, remote, timeout, source=fh, size=size)
        except OSError as exc:
            return None, str(exc)
        if err:
            return None, err
        self.job["files_done"] += 1
        return n, None

    def _push_dir(self, local, remote, timeout, depth=0):
        if depth > 40:
            return "directory nesting is deeper than 40 levels"
        attrs, _ = self.stat(remote)
        if attrs is None:
            _, err = self.mkdir(remote)
            if err:
                return err
        elif not self._isdir(attrs):
            return "%s exists and is not a directory" % remote
        try:
            names = sorted(os.listdir(local))
        except OSError as exc:
            return str(exc)
        for nm in names:
            lp = os.path.join(local, nm)
            rp = remote.rstrip("/") + "/" + nm
            if os.path.isdir(lp) and not os.path.islink(lp):
                err = self._push_dir(lp, rp, timeout, depth + 1)
            else:
                _, err = self._push_file(lp, rp, timeout)
            if err:
                return err
        return None

    def _count_local(self, local):
        n = 0
        for _, _, files in os.walk(local):
            n += len(files)
        return n

    def push(self, local, remote, timeout=900, recursive=False):
        """Local disk -> remote. `local` is already an absolute local path."""
        if not self.joblock.acquire(blocking=False):
            return None, "a copy is already running on this tab"
        try:
            dst = self._abs(remote)
            if not os.path.exists(local):
                return None, "%s does not exist" % local
            isdir = os.path.isdir(local)
            if isdir and not recursive:
                return None, "%s is a directory -- pass recursive" % local
            self.job = {"op": "push", "from": local, "to": dst,
                        "files_done": 0, "files_total": 1, "current": ""}
            if not isdir:
                n, err = self._push_file(local, dst, timeout)
                return (None, err) if err else ({"files": 1, "bytes": n}, None)
            self.job["files_total"] = self._count_local(local)
            err = self._push_dir(local, dst, timeout)
            if err:
                return None, err
            return {"files": self.job["files_done"], "bytes": None}, None
        finally:
            self.job = None
            self.joblock.release()

    def close(self):
        self.alive = False
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

    def info(self):
        return {
            "name": self.name,
            "kind": "transfer",
            "host": self.host,
            "target": self.target,
            "auth": self.auth,
            "proxy_jump": self.proxy_jump,
            "log": None,
            "alive": self.alive and self.proc.poll() is None,
            "offset": 0,
            "rows": 0,
            "cols": 0,
            "cwd": self.cwd,
            "busy": self.busy,
            "job": self.job,
            "uptime": int(time.time() - self.started),
        }


def finish_unlock():
    """Side effects that may only happen once the vault is open.

    The token file is written here, not at startup, so its old meaning
    survives: if the file is there, the server is up *and* usable. An
    agent never has to reason about a half-open server.
    """
    with open(TOKEN_FILE, "w") as fh:
        fh.write(TOKEN)
    with open(ASKPASS_CMD, "w", newline="") as fh:
        fh.write(ASKPASS_CMD_BODY)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    # ---------- helpers ----------

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        """Parse the request body, refusing an oversized one unread.

        The old order checked the size after decoding the payload, by which
        point the memory the cap exists to protect had already been spent
        three times over. Content-Length is base64 inside JSON, so the
        allowance is the ceiling plus a third, plus room for the envelope.
        """
        n = int(self.headers.get("Content-Length") or 0)
        allowed = max_inline() * 4 // 3 + 65536
        if n > allowed:
            # Nothing has been read, so the body is still queued on a
            # keep-alive socket and would be parsed as the next request.
            # Reading it away in 64KB pieces costs no memory -- which is
            # what the cap is protecting -- and it is what makes the 413
            # arrive: closing the socket with the body still in flight
            # reaches the caller as a connection reset instead, which
            # explains nothing.
            if n <= MAX_DRAIN:
                left = n
                while left > 0:
                    piece = self.rfile.read(min(left, 65536))
                    if not piece:
                        break
                    left -= len(piece)
            else:
                self.close_connection = True
            raise BodyTooLarge(over_cap(n, "the request body"))
        return json.loads(self.rfile.read(n) or b"{}")

    def _authorized(self):
        """Gate /api/* so a random web page cannot drive your SSH sessions.

        A cross-origin POST carrying X-Token forces a CORS preflight, which we
        never answer -- so the browser refuses to send it at all. The Host
        check blocks DNS-rebinding onto this port.
        """
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            self._json({"error": "bad host"}, 403)
            return False
        supplied = self.headers.get("X-Token")
        if supplied is None:
            # EventSource cannot set headers, so /stream passes ?token= instead.
            supplied = (parse_qs(urlparse(self.path).query).get("token") or [None])[0]
        if not supplied or not secrets.compare_digest(supplied, TOKEN):
            self._json({"error": "bad or missing token"}, 401)
            return False
        return True

    # /api/state lets the page find out whether to show the unlock panel;
    # /api/unlock is how it stops being locked. Everything else waits.
    OPEN_WHILE_LOCKED = ("/api/state", "/api/unlock")

    def _unlocked(self):
        if not LOCKED:
            return True
        if urlparse(self.path).path in self.OPEN_WHILE_LOCKED:
            return True
        self._json({"error": "locked: the master password has not been "
                             "given yet -- open http://127.0.0.1:%d in a "
                             "browser and unlock it" % PORT,
                    "locked": True}, 423)
        return False

    def _unlock(self, body):
        """Open the vault from a password posted over loopback.

        Mirrors vault.unlock()'s console flow, including creating the vault
        on first run. The password is read out of the body and never echoed:
        failures report only what vault.py raises, which names no secret.
        """
        global VAULT, MASTER_KEY, MASTER_SALT, LOCKED, UNLOCK_TRIES

        with UNLOCK_LOCK:
            if not LOCKED:
                return self._json({"ok": True, "locked": False})
            if UNLOCK_TRIES >= MAX_UNLOCK_TRIES:
                return self._json(
                    {"error": "too many failed attempts; restart the server",
                     "locked": True, "attempts_left": 0}, 429)

            password = body.get("password") or ""
            if not os.path.exists(VAULT_FILE):
                # First run: this call chooses the master password instead
                # of checking it, so it is confirmed rather than counted.
                if len(password) < 8:
                    return self._json(
                        {"error": "use at least 8 characters",
                         "locked": True}, 400)
                if password != (body.get("confirm") or ""):
                    return self._json(
                        {"error": "the two entries did not match",
                         "locked": True}, 400)
                # Claim the filename atomically before sealing. secrets.enc
                # lives in a synced folder, so "it is not there" can mean
                # "sync has not delivered it yet" -- and sealing a fresh vault
                # over a real one is the single unrecoverable mistake this
                # program can make. O_EXCL turns that race into a 409.
                try:
                    os.close(os.open(VAULT_FILE,
                                     os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                except FileExistsError:
                    return self._json(
                        {"error": "a vault appeared while you were typing -- "
                                  "reload the page and unlock it instead",
                         "locked": True}, 409)
                salt = os.urandom(vault.SALT_LEN)
                key = vault.derive(password, salt)
                vault.seal(VAULT_FILE, key, salt, {"passwords": {}})
                VAULT, MASTER_KEY, MASTER_SALT = {"passwords": {}}, key, salt
            else:
                time.sleep(UNLOCK_DELAY)
                try:
                    VAULT, MASTER_KEY, MASTER_SALT = vault.unseal(
                        VAULT_FILE, password)
                except ValueError as exc:
                    UNLOCK_TRIES += 1
                    left = max(0, MAX_UNLOCK_TRIES - UNLOCK_TRIES)
                    return self._json({"error": str(exc), "locked": True,
                                       "attempts_left": left}, 401)
                except OSError as exc:
                    return self._json(
                        {"error": "vault unreadable: %s" % exc,
                         "locked": True}, 500)

            LOCKED = False
            finish_unlock()
            print("vault unlocked; api token written to %s" % TOKEN_FILE)
            return self._json({"ok": True, "locked": False})

    def _session(self, name, kind="shell"):
        """Look up a tab, insisting it is the kind the route can actually use.

        Shell and transfer tabs share one registry so they share the tab bar,
        Alt+1..9 and close semantics. The cost is that /run on a transfer tab
        has to be refused out loud rather than doing something undefined.
        """
        with LOCK:
            s = SESSIONS.get(name)
        if not s:
            self._json({"error": "no such session: %s" % name}, 404)
            return None
        if kind and getattr(s, "kind", "shell") != kind:
            self._json({"error": "%r is a %s tab; that route needs a %s tab"
                                 % (name, getattr(s, "kind", "shell"), kind)}, 400)
            return None
        return s

    def _sse(self, data, event_id=None):
        # HTTP/1.1 needs explicit framing; SSE has no Content-Length, so chunk it.
        # The id is what EventSource sends back as Last-Event-ID when it
        # reconnects on its own, which is how a blip stops costing a replay.
        payload = b"" if event_id is None else b"id: %d\n" % event_id
        payload += b"data: " + base64.b64encode(data) + b"\n\n"
        self.wfile.write(b"%X\r\n" % len(payload) + payload + b"\r\n")
        self.wfile.flush()

    def _static(self, relpath, ctype, substitutions=None):
        try:
            with open(os.path.join(HERE, relpath), "rb") as fh:
                data = fh.read()
        except OSError:
            return self._json({"error": "missing " + relpath}, 404)
        if substitutions:
            for k, v in substitutions.items():
                data = data.replace(k.encode(), v.encode())
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---------- GET ----------

    def do_GET(self):
        u = urlparse(self.path)
        path, query = u.path, parse_qs(u.query)
        parts = path.strip("/").split("/")

        if path in ("/", "/index.html"):
            return self._static("index.html", "text/html; charset=utf-8",
                                {"__TOKEN__": TOKEN})

        if len(parts) == 2 and parts[0] == "static":
            name = parts[1]
            if "/" in name or "\\" in name or name.startswith("."):
                return self._json({"error": "bad path"}, 400)
            ctype = "text/css" if name.endswith(".css") else "application/javascript"
            return self._static(os.path.join("static", name), ctype)

        if not path.startswith("/api/"):
            return self._json({"error": "not found"}, 404)
        if not self._authorized():
            return
        if not self._unlocked():
            return

        if path == "/api/state":
            return self._json({
                "locked": LOCKED,
                "has_vault": os.path.exists(VAULT_FILE),
                "attempts_left": max(0, MAX_UNLOCK_TRIES - UNLOCK_TRIES),
                # Named on the create screen so a server pointed at the wrong
                # folder -- or a stray second instance on another port -- is
                # obvious before anyone types a new password into it.
                "vault_path": VAULT_FILE,
                "port": PORT,
            })

        if path == "/api/sessions":
            with LOCK:
                return self._json([s.info() for s in SESSIONS.values()])

        if path == "/api/config":
            return self._json({"default_key": default_key(),
                               "ssh_bin": ssh_binary(),
                               "port": PORT,
                               "max_inline": max_inline(),
                               "known_hosts": KNOWN_HOSTS})

        if path == "/api/snippets":
            return self._json(load_json(SNIPPETS_FILE, SEED_SNIPPETS))

        if path == "/api/hosts":
            hosts = load_json(HOSTS_FILE, [])
            for h in hosts:
                h["has_saved_password"] = h.get("name") in VAULT["passwords"]
            return self._json(hosts)

        if len(parts) == 4 and parts[:2] == ["api", "sessions"]:
            name, action = parts[2], parts[3]
            s = self._session(name, "shell")
            if not s:
                return
            if action == "text":
                since = int((query.get("since") or ["0"])[0])
                data, offset = s.read_text(since)
                return self._json({
                    "name": name, "since": since, "offset": offset,
                    "alive": s.alive,
                    "text": data.decode("utf-8", "replace"),
                })
            if action == "log":
                # The full transcript, straight off disk -- not the
                # in-memory window, so nothing is missing.
                try:
                    with open(s.log_path, "rb") as fh:
                        data = fh.read()
                except OSError as exc:
                    return self._json({"error": str(exc)}, 404)
                fname = os.path.basename(s.log_path)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition",
                                 'attachment; filename="%s"' % fname)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)

            if action == "stream":
                return self._stream(s)

        self._json({"error": "not found"}, 404)

    def _stream(self, s):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        # A browser that reconnects by itself replays the last id it saw, so
        # it resumes rather than being handed the whole scrollback again --
        # which it already has, and used to draw twice. A page that opens a
        # genuinely new EventSource sends no id and still gets everything.
        try:
            since = int(self.headers.get("Last-Event-ID"))
        except (TypeError, ValueError):
            since = 0
        q = queue.Queue(maxsize=MAX_SUB_QUEUE)
        with s.lock:
            backlog, offset = s._raw_since(since)
            s.subs.append(q)
        try:
            if backlog:
                self._sse(backlog, offset)
            while True:
                item = q.get()
                if item is None:
                    break
                end, chunk = item
                self._sse(chunk, end)
            self.wfile.write(b"0\r\n\r\n")   # terminating chunk
            self.wfile.flush()
        except Exception:
            pass
        finally:
            with s.lock:
                if q in s.subs:
                    s.subs.remove(q)

    # ---------- POST ----------
    #
    # Four families of route live under /api/, and they used to be one 366
    # line method: settings-ish things, opening a tab, this machine's disk,
    # and the two kinds of tab. Splitting them is mostly about being able to
    # read one of them at a time, but it also removes a real hazard. The
    # transfer and shell routes have the same path shape -- four segments
    # beginning api/sessions -- so the old code told them apart by putting
    # the transfer block first and letting it fall through. Nothing said so,
    # and reordering the blocks while tidying would have quietly broken
    # every transfer route. Here the verb decides, and the two sets say it.

    TRANSFER_VERBS = ("ls", "cd", "get", "put", "mkdir", "rm", "mv",
                      "pull", "push")
    SHELL_VERBS = ("run", "batch", "exec", "input", "download", "upload",
                   "resize")

    def _need(self, body, *keys):
        """Required string fields, or a 400 naming the first one missing.

        Returns None having already answered, so a route reads

            got = self._need(body, "from", "to")
            if got is None:
                return
            old, new = got

        Twelve routes were spelling this out by hand, each with its own
        wording for the same mistake.
        """
        out = []
        for k in keys:
            v = (body.get(k) or "").strip()
            if not v:
                self._json({"error": "%s is required" % k}, 400)
                return None
            out.append(v)
        return out

    def _blob(self, body):
        """The b64 field, decoded, or None having answered 400."""
        raw = body.get("b64")
        if raw is None:
            self._json({"error": "b64 is required"}, 400)
            return None
        try:
            return base64.b64decode(raw)
        except Exception:
            self._json({"error": "b64 did not decode"}, 400)
            return None

    def _bad(self, err, code=400):
        """Answer an error string from an operation that returned one."""
        return self._json({"error": err}, code)

    def do_POST(self):
        if not self.path.startswith("/api/"):
            return self._json({"error": "not found"}, 404)
        if not self._authorized():
            return
        if not self._unlocked():
            return
        parts = urlparse(self.path).path.strip("/").split("/")
        try:
            body = self._read_json()
        except BodyTooLarge as exc:
            return self._json({"error": str(exc)}, 413)
        except Exception:
            return self._json({"error": "bad json"}, 400)

        if parts == ["api", "unlock"]:
            return self._unlock(body)
        if parts == ["api", "config"]:
            return self._post_config(body)
        if parts == ["api", "snippets"]:
            return self._post_snippet(body)
        if parts == ["api", "hosts"]:
            return self._post_host(body)
        if parts == ["api", "sessions"]:
            return self._post_open(body)

        if len(parts) == 3 and parts[:2] == ["api", "local"]:
            return self._post_local(parts[2], body)

        if len(parts) == 4 and parts[:2] == ["api", "sessions"]:
            name, action = parts[2], parts[3]
            if action in self.TRANSFER_VERBS:
                return self._post_transfer(name, action, body)
            if action in self.SHELL_VERBS:
                return self._post_shell(name, action, body)

        self._json({"error": "not found"}, 404)

    # ---------- settings, snippets, hosts ----------

    def _post_config(self, body):
        got = self._need(body, "default_key")
        if got is None:
            return
        (newkey,) = got
        current = load_json(SETTINGS_FILE, {})
        current["default_key"] = newkey
        if body.get("max_inline"):
            current["max_inline"] = int(body["max_inline"])
        save_json(SETTINGS_FILE, current)
        return self._json({"ok": True, "default_key": newkey,
                           "exists": os.path.exists(expand(newkey)),
                           "note": "applies to sessions opened from now on"})

    def _post_snippet(self, body):
        got = self._need(body, "name", "cmd")
        if got is None:
            return
        name, cmd = got
        snips = [x for x in load_json(SNIPPETS_FILE, SEED_SNIPPETS)
                 if x.get("name") != name]
        snips.append({"name": name, "cmd": cmd})
        snips.sort(key=lambda x: x["name"].lower())
        save_json(SNIPPETS_FILE, snips)
        return self._json({"ok": True, "name": name})

    def _post_host(self, body):
        # Upsert a saved host. A password is stored only on explicit
        # request, and never in this folder.
        # `theme` is a property of the host, not of the screen you are
        # sitting at: the point of pinning one is that a machine looks the
        # same wherever you reach it from, so it travels in hosts.json.
        # Font size and the global theme stay in the browser, where a 4K
        # desktop and a laptop genuinely want different answers.
        host = {k: body.get(k) for k in
                ("name", "target", "auth", "key", "cert", "port",
                 "proxy_jump", "theme")}
        if self._need(body, "name", "target") is None:
            return
        host["auth"] = host["auth"] or "key"
        hosts = [h for h in load_json(HOSTS_FILE, [])
                 if h.get("name") != host["name"]]
        hosts.append(host)
        save_json(HOSTS_FILE, hosts)
        if body.get("remember_password") and body.get("password"):
            VAULT["passwords"][host["name"]] = body["password"]
            vault.seal(VAULT_FILE, MASTER_KEY, MASTER_SALT, VAULT)
        return self._json({"ok": True, "host": host})

    # ---------- opening a tab ----------

    def _post_open(self, body):
        name = body.get("name")
        target = body.get("target")
        auth = body.get("auth") or "key"
        password = body.get("password")
        key = body.get("key")
        cert = body.get("cert")
        port = body.get("port")
        proxy_jump = body.get("proxy_jump")

        # Fall back to a saved host definition when only a name is given.
        if name and not target:
            for h in load_json(HOSTS_FILE, []):
                if h.get("name") == name:
                    target = h.get("target")
                    auth = h.get("auth") or auth
                    key = key or h.get("key")
                    cert = cert or h.get("cert")
                    port = port or h.get("port")
                    proxy_jump = proxy_jump or h.get("proxy_jump")
                    break
        if auth == "password" and not password:
            password = VAULT["passwords"].get(name)

        if not name or not target:
            return self._json({"error": "name and target are required"}, 400)
        if not SAFE_NAME.match(name):
            return self._json({"error": "name must be letters, digits, dot, "
                                        "dash or underscore (it becomes a "
                                        "filename)"}, 400)
        if auth == "password" and not password:
            return self._json({"error": "password required for this host"}, 400)
        if auth != "password" and not (key or default_key()):
            return self._json({"error": "no key configured: set a default key "
                                        "under Settings, or give this host "
                                        "its own"}, 400)

        if (body.get("kind") or "shell") == "transfer":
            return self._open_transfer(name, target, key, auth, cert,
                                       password, port, proxy_jump)
        return self._open_shell(name, target, key, auth, cert, password,
                                port, proxy_jump, body)

    def _open_transfer(self, name, target, key, auth, cert, password,
                       port, proxy_jump):
        # A transfer tab is its own connection to the same host, so it gets
        # its own registry key -- `web-01` the shell and `web-01-xfer` the
        # transfer live side by side, and closing one leaves the other.
        tname = name + "-xfer"
        with LOCK:
            existing = SESSIONS.get(tname)
            if existing and existing.info().get("alive"):
                return self._json(
                    {"error": "transfer tab for %r already open" % name}, 409)
        # Built OUTSIDE the registry lock. Connecting waits on a human
        # finding their key, and holding the global lock for that froze
        # every other API call -- including the session list the browser
        # polls.
        t = Transfer(tname, name, target, key, auth, cert,
                     password, port, proxy_jump)
        if not t.alive:
            return self._json({"error": "sftp did not connect: %s"
                                        % (t.last_error or "unknown")}, 502)
        with LOCK:
            SESSIONS[tname] = t
        cwd, _ = t.pwd()
        return self._json({"ok": True, "name": tname, "kind": "transfer",
                           "host": name, "target": target, "cwd": cwd})

    def _open_shell(self, name, target, key, auth, cert, password,
                    port, proxy_jump, body):
        purge_stale_logs()
        # Built inside the lock, unlike Transfer above -- and the difference
        # is not an oversight. Transfer's constructor speaks the SFTP
        # handshake, which waits on a human finding their key and can sit
        # there for half a minute. Session's returns as soon as Popen has
        # spawned: the key touch happens afterwards, out in the pump thread,
        # so the lock is held for milliseconds and the check-then-insert
        # stays a single atomic step.
        with LOCK:
            existing = SESSIONS.get(name)
            if existing and existing.alive:
                return self._json({"error": "session %r already open" % name},
                                  409)
            SESSIONS[name] = Session(
                name, target,
                int(body.get("rows", 40)),
                int(body.get("cols", 120)),
                key, auth, cert, password, port, proxy_jump,
            )
        return self._json({
            "ok": True, "name": name, "target": target,
            "note": "touch your security key to finish authenticating",
        })

    # ---------- this machine's disk, the other half of the two-pane view ----

    def _post_local(self, action, body):
        if action == "ls":
            path = local_path(body.get("path"))
            try:
                entries = local_entries(path)
            except OSError as exc:
                return self._bad(str(exc))
            parent = os.path.dirname(path.rstrip("\\/"))
            if not parent or parent == path:
                parent = None                      # already at a drive root
            return self._json({"ok": True, "cwd": path, "parent": parent,
                               "machine": MACHINE,
                               "home": os.path.expanduser("~"),
                               "sep": os.sep, "drives": local_drives(),
                               "entries": entries})

        if action == "mkdir":
            path = local_path(body.get("path"))
            try:
                os.mkdir(path)
            except OSError as exc:
                return self._bad(str(exc))
            return self._json({"ok": True, "path": path})

        if action == "rm":
            # Non-recursive, exactly like the remote side: a directory has to
            # be emptied deliberately before it will go. A file manager that
            # can erase a tree on one mis-click is not wanted here.
            path = local_path(body.get("path"))
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    os.rmdir(path)
                else:
                    os.remove(path)
            except OSError as exc:
                return self._bad(str(exc))
            return self._json({"ok": True, "path": path})

        if action == "mv":
            src, dst = local_path(body.get("from")), local_path(body.get("to"))
            if os.path.exists(dst):
                return self._bad("%s already exists" % dst)
            try:
                os.rename(src, dst)
            except OSError as exc:
                return self._bad(str(exc))
            return self._json({"ok": True, "from": src, "to": dst})

        return self._json({"error": "unknown local action %r" % action}, 404)

    # ---------- transfer tabs ----------

    def _post_transfer(self, name, action, body):
        t = self._session(name, "transfer")
        if not t:
            return

        if action == "ls":
            entries, err = t.listdir(body.get("path", ""))
            if err:
                return self._bad(err)
            return self._json({"ok": True, "cwd": t.cwd, "entries": entries})

        if action == "cd":
            cwd, err = t.chdir(body.get("path", "."))
            if err:
                return self._bad(err)
            return self._json({"ok": True, "cwd": cwd})

        if action == "get":
            got = self._need(body, "path")
            if got is None:
                return
            (path,) = got
            data, err = t.get(path, float(body.get("timeout", 900)),
                              max_bytes=max_inline())
            if err:
                return self._bad(err)
            return self._json({"ok": True, "size": len(data),
                               "b64": base64.b64encode(data).decode()})

        if action == "put":
            got = self._need(body, "path")
            if got is None:
                return
            (path,) = got
            payload = self._blob(body)
            if payload is None:
                return
            too_big = over_cap(len(payload), path)
            if too_big:
                return self._bad(too_big, 413)
            size, err = t.put(payload, path, float(body.get("timeout", 900)))
            if err:
                return self._bad(err)
            return self._json({"ok": True, "size": size, "path": path})

        if action in ("mkdir", "rm"):
            got = self._need(body, "path")
            if got is None:
                return
            (path,) = got
            _, err = t.mkdir(path) if action == "mkdir" else t.remove(path)
            if err:
                return self._bad(err)
            return self._json({"ok": True, "path": path})

        if action == "mv":
            got = self._need(body, "from", "to")
            if got is None:
                return
            old, new = got
            _, err = t.rename(old, new)
            if err:
                return self._bad(err)
            return self._json({"ok": True, "from": old, "to": new})

        # pull and push move the bytes server-side: disk to ssh and back,
        # never through the page. That is why they take a local path rather
        # than a blob, and why neither has a size ceiling.
        got = self._need(body, "remote", "local")
        if got is None:
            return
        remote, local = got
        local = local_path(local)
        timeout = float(body.get("timeout", 900))
        rec = bool(body.get("recursive"))
        if action == "pull":
            res, err = t.pull(remote, local, timeout, rec)
        else:
            res, err = t.push(local, remote, timeout, rec)
        if err:
            return self._bad(err)
        return self._json({"ok": True, "remote": remote, "local": local,
                           "files": res["files"], "bytes": res["bytes"]})

    # ---------- shell tabs ----------

    def _post_shell(self, name, action, body):
        s = self._session(name, "shell")
        if not s:
            return

        if action == "run":
            cmd = body.get("cmd", "")
            if not cmd:
                return self._bad("cmd is required")
            return self._json(s.run(cmd, float(body.get("timeout", 60))))

        if action == "batch":
            cmds = body.get("cmds")
            if not isinstance(cmds, list) or not cmds:
                return self._bad("cmds must be a non-empty list")
            if len(cmds) > MAX_BATCH:
                return self._bad("at most %d commands per batch" % MAX_BATCH)
            if not all(isinstance(c, str) and c for c in cmds):
                return self._bad("every entry in cmds must be a non-empty "
                                 "string")
            return self._json(s.run_batch(
                cmds, float(body.get("timeout", 60)),
                bool(body.get("stop_on_error"))))

        if action == "exec":          # fire-and-forget; read /text yourself
            cmd = body.get("cmd", "")
            _, offset_before = s.read_text(0)
            ok = s.write((cmd + "\n").encode())
            return self._json({"ok": ok, "sent": cmd,
                               "offset_before": offset_before})

        if action == "input":
            data = body.get("data", "")
            data = base64.b64decode(data) if body.get("b64") else data.encode()
            # Anything that does not declare itself the keyboard counts as
            # the API. An agent must not be able to go unmarked by leaving a
            # field out; the browser is the one caller that says so.
            if body.get("source") != "keyboard":
                s.note_input()
            return self._json({"ok": s.write(data)})

        if action == "download":
            got = self._need(body, "path")
            if got is None:
                return
            (path,) = got
            return self._json(s.download(path, float(body.get("timeout", 180)),
                                         max_inline()))

        if action == "upload":
            got = self._need(body, "path")
            if got is None:
                return
            (path,) = got
            payload = self._blob(body)
            if payload is None:
                return
            too_big = over_cap(len(payload), path)
            if too_big:
                return self._bad(too_big, 413)
            return self._json(s.upload(path, payload,
                                       float(body.get("timeout", 300))))

        rows = int(body.get("rows", s.rows))          # resize
        cols = int(body.get("cols", s.cols))
        changed = s.resize(rows, cols)
        return self._json({"ok": True, "changed": changed,
                           "rows": rows, "cols": cols})


    # ---------- DELETE ----------

    def do_DELETE(self):
        if not self.path.startswith("/api/"):
            return self._json({"error": "not found"}, 404)
        if not self._authorized():
            return
        if not self._unlocked():
            return
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "sessions"]:
            with LOCK:
                s = SESSIONS.pop(parts[2], None)
            if not s:
                return self._json({"error": "no such session"}, 404)
            s.close()
            return self._json({"ok": True})
        if len(parts) == 3 and parts[:2] == ["api", "snippets"]:
            name = unquote(parts[2])
            snips = load_json(SNIPPETS_FILE, SEED_SNIPPETS)
            keep = [x for x in snips if x.get("name") != name]
            save_json(SNIPPETS_FILE, keep)
            return self._json({"ok": True, "removed": len(snips) - len(keep)})

        if len(parts) == 3 and parts[:2] == ["api", "hosts"]:
            name = parts[2]
            hosts = load_json(HOSTS_FILE, [])
            remaining = [h for h in hosts if h.get("name") != name]
            save_json(HOSTS_FILE, remaining)
            if VAULT["passwords"].pop(name, None) is not None:
                vault.seal(VAULT_FILE, MASTER_KEY, MASTER_SALT, VAULT)
            return self._json({"ok": True, "removed": len(hosts) - len(remaining)})
        self._json({"error": "not found"}, 404)


class Console(ThreadingHTTPServer):
    """ThreadingHTTPServer that does not shout when a client hangs up.

    With keep-alive on (HTTP/1.1), a browser routinely opens speculative
    sockets it never uses and closes them, and it drops the event-stream
    socket on every reload. Each of those surfaces here as a connection
    error -- WinError 10053/10054 on Windows, EPIPE elsewhere -- raised
    from deep inside socketserver, where the stock handle_error prints a
    full traceback. That is normal client behaviour, not a fault, and the
    noise buries anything that is. Swallow that family only; everything
    else still gets its traceback.
    """

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


def main():
    global VAULT, MASTER_KEY, MASTER_SALT, LOCKED

    if not os.path.exists(SSH_BIN):
        print("Missing %s -- the bundled OpenSSH client is required." % SSH_BIN)
        print("Restore the ssh/ folder from the project, or re-download")
        print("OpenSSH-Win64.zip from github.com/PowerShell/Win32-OpenSSH.")
        raise SystemExit(1)
    if not os.path.exists(SNIPPETS_FILE):
        save_json(SNIPPETS_FILE, SEED_SNIPPETS)

    # The token exists only while the server runs: a folder at rest holds
    # no usable credential. finish_unlock() writes it, so its presence still
    # means "up and usable" rather than merely "up".
    atexit.register(lambda: os.path.exists(TOKEN_FILE) and os.remove(TOKEN_FILE))

    # The console prompt is now the fallback, not the default: asking in the
    # browser is what lets this start without a human at a terminal. Keep the
    # old path one flag away, since a browser that will not load must not be
    # the only way in.
    if "--console-unlock" in sys.argv:
        VAULT, MASTER_KEY, MASTER_SALT = vault.unlock(VAULT_FILE)
        LOCKED = False
        finish_unlock()

    srv = Console((HOST, PORT), Handler)
    srv.daemon_threads = True
    print("ssh console listening on http://%s:%d" % (HOST, PORT))
    print("open that in your browser; Ctrl-C here to stop everything")
    if LOCKED:
        print("waiting for the master password -- give it in the browser;")
        print("nothing else is reachable, and no token is written, until then")
    else:
        print("api token written to %s" % TOKEN_FILE)

    # Opened here rather than from start.cmd because the socket is already
    # bound by this line -- there is no window in which the browser could
    # arrive before the port answers, and nothing to poll for. Opt-in, so an
    # autostart-at-login run does not throw a window at you.
    if "--open-browser" in sys.argv:
        url = "http://%s:%d" % (HOST, PORT)
        threading.Thread(target=webbrowser.open, args=(url,),
                         daemon=True).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        for s in list(SESSIONS.values()):
            s.close()
        print("\nstopped")


if __name__ == "__main__":
    main()
