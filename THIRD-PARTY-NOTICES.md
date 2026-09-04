# Third-party notices

CypherGate is deliberately self-contained: it vendors an interpreter, an SSH
client and a terminal emulator so that a clone runs on a machine with nothing
installed. That means this repository redistributes other people's software,
and their licenses travel with it.

CypherGate's own code — `server.py`, `vault.py`, `index.html` and `start.cmd`
— is MIT, in [LICENSE](LICENSE). Everything below is
somebody else's work, included unmodified.

| Component | Version | License | Text |
|---|---|---|---|
| [CPython](https://www.python.org/downloads/windows/), Windows embeddable package | 3.13.7 | PSF License Agreement (plus bundled component licenses) | [`python/LICENSE.txt`](python/LICENSE.txt) |
| [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/releases), client binaries only | 10.0p2 | BSD | [`ssh/LICENSE.txt`](ssh/LICENSE.txt), [`ssh/NOTICE.txt`](ssh/NOTICE.txt) |
| [xterm.js](https://github.com/xtermjs/xterm.js) + fit, search, web-links addons | 5.x | MIT | [`static/licenses/xterm.js.LICENSE.txt`](static/licenses/xterm.js.LICENSE.txt) |

## Why each is here

**CPython** is the `python/` folder, and it is the *only* interpreter the app
ever runs — `start.cmd` invokes `python\python.exe` by path and the server never
searches `PATH`. The PSF License Agreement grants a "nonexclusive, royalty-free,
world-wide license to reproduce … distribute, and otherwise use Python,"
conditioned on retaining the license text and copyright notice, which
`python/LICENSE.txt` does. Its own appendices carry the licenses of what CPython
in turn bundles — OpenSSL, libffi, and the rest.

**Win32-OpenSSH** is the `ssh/` folder, and likewise the only SSH client used.
Its `LICENSE.txt` opens by summarising that "all components are under a BSD
licence, or a licence more free than that. OpenSSH contains no GPL code."
`NOTICE.txt` is Microsoft's third-party notice for the Windows port.

Only the **client** side is included: `ssh`, `ssh-keygen`, `ssh-add`,
`ssh-agent`, `ssh-sk-helper` (required for FIDO2 `sk-` keys),
`ssh-pkcs11-helper`, `scp`, `sftp` and `libcrypto.dll`. `sshd` and the service
install/uninstall scripts are deliberately excluded — shipping an SSH *server*
and a service installer inside a client application is a liability with no
upside.

**xterm.js** is the terminal in the browser, vendored into `static/` rather than
loaded from a CDN, so the console keeps working on a machine with no route to
the internet and cannot be altered by a third party between releases. The
minifier stripped the banner comment from the `.js` bundles, so the MIT text is
restored alongside them in `static/licenses/`.

## Keeping them current

**Nothing updates these for you.** Python and OpenSSH both ship security fixes;
taking one means replacing the folder contents from a fresh download of the
version named above and committing the result. That is the standing cost of not
depending on what happens to be installed on the machine — see *Vendored
runtimes* in the [README](README.md#vendored-runtimes).
