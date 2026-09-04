"""Master-password vault for CypherGate.

Secrets are sealed with AES-256-GCM. The key comes from scrypt over the master
password, so the sealed file is *portable* -- the same file opens on any machine
given the password. That is the point: it syncs with the folder like everything
else, and is useless to anyone who has the folder but not the password.

Windows' own CNG provides AES; Python's standard library provides scrypt. No
third-party dependency, which is what lets the app stay self-contained.
"""
import base64
import ctypes
import ctypes.wintypes as w
import getpass
import hashlib
import json
import os
import sys

MAGIC = b"CGV1"
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)

_b = ctypes.windll.bcrypt
_VOID = ctypes.c_void_p


class _AuthInfo(ctypes.Structure):
    _fields_ = [("cbSize", w.ULONG), ("dwInfoVersion", w.ULONG),
                ("pbNonce", _VOID), ("cbNonce", w.ULONG),
                ("pbAuthData", _VOID), ("cbAuthData", w.ULONG),
                ("pbTag", _VOID), ("cbTag", w.ULONG),
                ("pbMacContext", _VOID), ("cbMacContext", w.ULONG),
                ("cbAAD", w.ULONG), ("cbData", ctypes.c_ulonglong),
                ("dwFlags", w.ULONG)]


def _aes_key(raw):
    """Returns (provider, key). Both are handles the caller has to release."""
    alg = _VOID()
    if _b.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0) != 0:
        raise OSError("cannot open AES provider")
    try:
        mode = ctypes.create_unicode_buffer("ChainingModeGCM")
        nbytes = (len(mode.value) + 1) * ctypes.sizeof(ctypes.c_wchar)
        if _b.BCryptSetProperty(alg, "ChainingMode", mode, nbytes, 0) != 0:
            raise OSError("cannot select GCM")
        key = _VOID()
        if _b.BCryptGenerateSymmetricKey(alg, ctypes.byref(key), None, 0,
                                         raw, len(raw), 0) != 0:
            raise OSError("cannot build key")
    except Exception:
        _b.BCryptCloseAlgorithmProvider(alg, 0)
        raise
    return alg, key


def _gcm(raw_key, data, nonce, tag=None):
    """Encrypt when tag is None; otherwise decrypt and verify it.

    Takes the raw key bytes and owns the CNG handles for the call. Nothing
    released them before, so every seal and unseal leaked a provider and a
    key -- slow, but one-way, and seal() runs on every host save and every
    host delete.
    """
    alg, key = _aes_key(raw_key)
    try:
        return _gcm_with_key(key, data, nonce, tag)
    finally:
        _b.BCryptDestroyKey(key)
        _b.BCryptCloseAlgorithmProvider(alg, 0)


def _gcm_with_key(key, data, nonce, tag=None):
    """The GCM call itself, once someone else owns the key handle.

    Named for what it takes, not `_gcm_locked`: everywhere else in this
    program a `_locked` suffix means the caller is holding a lock, and
    there is no lock anywhere near this.
    """
    n = ctypes.create_string_buffer(nonce, len(nonce))
    t = (ctypes.create_string_buffer(tag, TAG_LEN) if tag
         else ctypes.create_string_buffer(TAG_LEN))
    info = _AuthInfo()
    info.cbSize = ctypes.sizeof(_AuthInfo)
    info.dwInfoVersion = 1
    info.pbNonce = ctypes.cast(n, _VOID)
    info.cbNonce = len(nonce)
    info.pbTag = ctypes.cast(t, _VOID)
    info.cbTag = TAG_LEN
    out = ctypes.create_string_buffer(max(1, len(data)))
    done = w.ULONG()
    fn = _b.BCryptDecrypt if tag else _b.BCryptEncrypt
    if fn(key, data, len(data), ctypes.byref(info), None, 0,
          out, len(data), ctypes.byref(done), 0) != 0:
        raise ValueError("wrong master password, or the file has been altered")
    return out.raw[:done.value], t.raw


def derive(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT)


def seal(path, key, salt, payload):
    """Write payload as MAGIC | salt | nonce | tag | ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    blob = json.dumps(payload).encode("utf-8")
    ct, tag = _gcm(key, blob, nonce)
    with open(path, "wb") as fh:
        fh.write(MAGIC + salt + nonce + tag + ct)


def unseal(path, password):
    """Return (payload, key, salt). Raises ValueError on a bad password."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw.startswith(MAGIC):
        raise ValueError("not a vault file")
    body = raw[len(MAGIC):]
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = body[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ct = body[SALT_LEN + NONCE_LEN + TAG_LEN:]
    key = derive(password, salt)
    plain, _ = _gcm(key, ct, nonce, tag)
    return json.loads(plain.decode("utf-8")), key, salt


def unlock(path, attempts=3):
    """Prompt at the console until the vault opens. Exits if it cannot.

    Called before the server binds anything, so nothing is reachable until the
    master password has been given.
    """
    if not sys.stdin or not sys.stdin.isatty():
        print("No console to read the master password from.")
        print("Start this with start.cmd, not as a background process.")
        raise SystemExit(1)

    if not os.path.exists(path):
        print("No vault yet. Choose a master password for this app.")
        print("It protects saved SSH passwords and gates the whole console.")
        print("There is no recovery: forget it and the vault is gone.")
        while True:
            first = getpass.getpass("  new master password: ")
            if len(first) < 8:
                print("  too short; use at least 8 characters.")
                continue
            if first != getpass.getpass("  confirm: "):
                print("  they did not match.")
                continue
            break
        salt = os.urandom(SALT_LEN)
        key = derive(first, salt)
        seal(path, key, salt, {"passwords": {}})
        print("  vault created.")
        return {"passwords": {}}, key, salt

    for left in range(attempts, 0, -1):
        try:
            return unseal(path, getpass.getpass("Master password: "))
        except ValueError as exc:
            print("  %s (%d attempt%s left)"
                  % (exc, left - 1, "" if left == 2 else "s"))
        except OSError as exc:
            print("  vault unreadable: %s" % exc)
            raise SystemExit(1)
    print("Too many failed attempts.")
    raise SystemExit(1)
