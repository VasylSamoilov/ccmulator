# ccmulator

A post office server for Lotus cc:Mail mobile clients, written in Python.

It speaks the cc:Mail remote protocol and aims at feature parity with a cc:Mail Router post
office for its clients and peers. It is compatible with:

- cc:Mail Remote 3.40B and RCONNECT 1.00 (DOS) clients;
- the built-in cc:Mail of the HP 200LX palmtop, in normal and interactive mode;
- newer cc:Mail clients that start with the same session (basic mail exchange);
- cc:Mail Router 6.x post offices, as a peer post office (mail routing and directory exchange);
- cc:Mail post office database files (read and write);
- internet mail, through a built-in SMTP gateway.

It does not include, and does not need, any Lotus or HP software.

## Features

- **Connections**: raw TCP (an emulator's modem, a serial bridge, newer clients), Telnet ports
  (modem emulators such as tcpser, terminal servers, RFC 2217 clients), a serial port (local, or
  `rfc2217://` / `socket://` over the network) with a built-in Hayes modem emulator, so a client
  set up for a dial-up modem connects over a null-modem cable, and a real modem of our own that
  answers calls and dials out to peer post offices. See [Connections](#connections).
- **Link layer**: the packet protocol with its error correction, robust on slow and noisy lines
  (tested from 300 bps with bit errors, dropped bytes and bursts).
- **Mail**: upload and download, text and file attachments, priorities, return-receipt tags,
  per-message limits, send order (directory updates, urgent, normal, low), non-delivery reports.
- **Users and passwords**: password change from the client, lockout after repeated failures,
  read-only access for unknown callers (configurable).
- **Code pages**: per-user DOS code pages; messages are tagged on upload and converted for each
  receiver, and the gateway converts to and from internet character sets. Besides the usual DOS
  and Windows pages, 1125 (`866u`, RUSCII, Ukrainian DOS) is built in.
- **Directory**: address book commands; directory update messages for clients; directory exchange
  with peer post offices, so all post offices share one address book.
- **Post office to post office**: mail routing to and from peer post offices, calling them and
  answering their calls.
- **Internet gateway**: SMTP in and out, with the address, header and attachment mapping of
  `spec/smtp-link.md`; gateway aliases (`sales@yourdomain`, or any full address, to a user);
  inbound mail also for users of peer post offices (`Name_at_PO@` or `Name+PO@`) and to
  subaddresses (`name+detail@`); a smarthost with STARTTLS or implicit TLS and a checked
  certificate.
- **Per-user internet mail**: a user's own email address (From, envelope sender, inbound
  matching), the user's own outgoing SMTP server (STARTTLS, SSL), and fetching from the user's own
  POP3, POP3S, IMAP or IMAPS account into the user's cc:Mail mailbox, polled in the background and
  at the start of each call, with persistent state so nothing is fetched twice.
- **HP 200LX interactive mode**: the client browses, reads, files, deletes and sends mail on the
  server during the call.
- **Post office files**: read, and write (deliver, add users, mark read, delete messages) cc:Mail
  post office database files (`ccmail/podb.py`, `tools/ccpodb.py`).

## Requirements

Python 3 (developed and tested on 3.13), standard library only, on a POSIX system such as Linux
(file locking uses `fcntl`). `pyserial` (3.x) is needed for serial ports (`serve --serial`,
`call` with `"dial"`); TCP and Telnet work without it. The TLS tests also use `openssl` (see
[Tests](#tests)).

## Running

    python3 -m ccmail.server serve --data data-test                 # TCP ports 5003 and 3264
    python3 -m ccmail.server serve --data data-test --telnet-port 2323
    python3 -m ccmail.server serve --data data-test --serial /dev/ttyUSB0 --baud 2400 --serial-only

`--data` is the post office directory: `po.json` (configuration) plus what is created at run
time: `mail/<user>/` waiting mail, `received/` uploads, `delivered/<user>/`, `route/<post office>/`
mail for peer post offices, `outbound/` internet mail waiting to go out, then `sent/` or `failed/`,
`inbound/` the original internet mail, `fetch/<user>.json` fetch state, `vim/<user>/` HP 200LX
interactive-mode folders and drafts, `deleted/` (messages deleted in interactive mode, deleted
users), `ade.json` the directory learned from peer post offices. Each message is stored in its
wire form (`.msg`) and as readable text (`.txt`).

`-v` (`--verbose`, before the command: `python3 -m ccmail.server -v serve ...`) logs at debug
level.

Options of `serve` (`serve --help` lists them with examples; the serial and modem options are
described under [Connections](#connections)):

| option | meaning |
|---|---|
| `--port N` | TCP port carrying raw session bytes (repeatable; default 5003 and 3264) |
| `--telnet` | the `--port` ports (or 5003 and 3264) speak Telnet instead of raw bytes |
| `--telnet-port N` | an extra TCP port that speaks Telnet (repeatable) |
| `--host ADDR` | address the TCP ports listen on (default 127.0.0.1) |
| `--line-bps N` | speed of the line behind the connection (modem or serial bridge); needed on slow lines |
| `--serial DEV\|URL` | a serial port: a device or a pyserial URL (`rfc2217://`, `socket://`, `loop://`) |
| `--baud N`, `--framing 8N1`, `--flow ...`, `--rtscts` | port settings (only with `--serial`) |
| `--capture FILE` | record every serial byte (readable with `tools/frames.py`) |
| `--serial-only` | do not listen on TCP at all |
| `--modem`, `--modem-init "..."`, `--modem-autoanswer N` | our own modem on `--serial` answers calls |

`--line-bps` sets the line speed for the link's timers and line clock (`spec/nak-storm.md`): the
retransmit timer counts from when a frame has left the line, so on a slow line (300 bps) it is
needed. With `--modem` the CONNECT speed is used unless `--line-bps` is given.

### Mail and address book

    python3 -m ccmail.server send --data DIR --from user1 --to user --subject Hi --text "Hello" [--attach FILE] [--priority 2]
    python3 -m ccmail.server send --data DIR --from bob --to "user at BRANCH" --to alice --subject Hi --file note.txt
    python3 -m ccmail.server show DIR/received/<id>.msg

    python3 -m ccmail.server user list   --data DIR
    python3 -m ccmail.server user add    --data DIR "Smith, Ann" --password pw [--comments Sales] [--codepage 866]
    python3 -m ccmail.server user set    --data DIR "Smith, Ann" --comments Support
    python3 -m ccmail.server user set    --data DIR "Smith, Ann" --email ann@isp.example     # "" clears it
    python3 -m ccmail.server user passwd --data DIR "Smith, Ann" --password new
    python3 -m ccmail.server user rename --data DIR user2 "Green, Tom"
    python3 -m ccmail.server user del    --data DIR user1 [--yes]           # asks first
    python3 -m ccmail.server unlock      --data DIR user
    python3 -m ccmail.server po list|add|set|del --data DIR BRANCH --password P --call-password C --connect host:port --mode LSEC
    python3 -m ccmail.server po del      --data DIR BRANCH [--force]        # --force: even with mail waiting for it
    python3 -m ccmail.server directory   --data DIR --to user [--to user2] [--delete "Old, Name"]

`send` puts a message into the post office as if a user had written it: `--to` is repeatable and
takes local users, `name at POSTOFFICE` for a peer post office (one copy per post office) and
names learned by directory exchange. The text comes from `--text` or `--file` (UTF-8);
`--attach` is repeatable, `--priority` is 0 (normal), 1 (low) or 2 (urgent), `--folder` names
the receiver's folder the client files the message in (when it has one of that name).

A running server picks up changes to `po.json`. `user add`, `user rename`, `user del`, `po add`
and `po del` queue a directory update with that entry for all users, and `user set` does so when
it sets a comment (`--no-update` to skip); a new user gets the whole directory. The same changes
also go to the peer post offices that exchange directories with us (`"ade"`). `user passwd`,
`po set` and `user set` with only `--codepage` or `--email` change `po.json` only. `directory`
sends the whole directory to the given users, `--delete` also removes an entry from their copy.

Names are unique across users and post offices (and names learned from peers), at most 126
characters, and may not contain `@` or ` at `; passwords at most 63. `user set --email` checks
that the address has the form name@domain and that no other user has it; it keeps the user's
other settings (`smtp`, `fetch`, ...). `po` sets the post office's `password` (what it sends us,
required for `add`), `call_password` (what we send it), `connect` and `mode` (`LSEC`, `HSEC` or
`RAW`; `HSEC` when not set); an empty value removes the key. Calling by modem (`"dial"`) is set
up by editing `po.json` (see [Connections](#connections)).

`user del` first lists what goes: waiting and delivered mail, interactive-mode folders and drafts,
fetch state, the email address, the fetch and SMTP accounts (host and login, never the password),
the gateway aliases pointing to the user, recorded failed logins. Then it asks
`Delete <user>? [y/N]`; `--yes` (or `--force`, kept for scripts) skips the question, and without
a terminal it refuses unless `--yes` is given. The user's entry, its account settings and its
aliases leave `po.json`; its files move to `deleted/<user>-<date>-<time>/`, a new folder for
every deletion, so nothing is destroyed.

### Internet mail

    python3 -m ccmail.server fetch --data DIR                        # fetch every user's account now
    python3 -m ccmail.server fetch --data DIR "Smith, Ann"           # only this user

`fetch` prints what it took per user and exits with status 1 if an account failed. It can run
next to `serve`: one fetch per user runs at a time. `serve` itself polls each account at its
`interval` and also fetches at the start of the user's call (see Configuration).

### Peer post offices

    python3 -m ccmail.server call --data DIR BRANCH                  # call a peer post office now
    python3 -m ccmail.server call --data DIR BRANCH --capture call.bin   # by modem: record the line
    python3 -m ccmail.server ade sync|request|update|list --data DIR BRANCH
    python3 -m ccmail.server ade request --data DIR BRANCH --all     # ask for its whole directory

`call` connects to the post office's `"connect"` address over TCP, or, with `"dial"`, through our
own modem (see [Connections](#connections)). `po list` shows the address or the dial string.
Mail for a peer waits in `route/<post office>/` until we call it or it calls us.

Directory exchange runs with the peers that have `"ade"` set in `po.json`. Their updates and
synchs are kept in `ade.json`: learned users can be addressed by name and are in the directory
our users get. Their synch requests are answered with a synch. The `ade` commands queue a message
that goes at the next call: `sync` a full synch of our directory, `request` a synch request
(`--all`: its whole directory), `update` our users as an update; `list` shows what was learned.

## Connections

Every way in ends in the same call handler; the link layer sees the plain byte stream.

| how the client reaches us | options | code |
|---|---|---|
| TCP, raw bytes (an emulator's modem, a serial bridge, newer clients and peer post offices on 3264) | `--port N` (repeatable; default 5003 and 3264), `--host` | `server.py` |
| TCP, Telnet (tcpser and other modem emulators, terminal servers, RFC 2217 clients) | `--telnet-port N` (repeatable), or `--telnet` for the `--port` ports | `telnet.py` |
| serial port, the client expects a modem (HP 200LX on a cable, a DOS client with a null modem) | `--serial DEV\|URL` and port settings | `modem.py` |
| our own modem on a phone line, answering | `--serial DEV\|URL --modem` and port settings | `hayes.py` |
| our own modem, calling a peer post office | po.json `"dial"`, the `call` command | `hayes.py`, `server.py` |

### TCP and Telnet

    python3 -m ccmail.server serve --data D                           # raw on 5003 and 3264
    python3 -m ccmail.server serve --data D --port 5003 --telnet-port 2323
    python3 -m ccmail.server serve --data D --telnet                  # 5003 and 3264 speak Telnet

Telnet (RFC 854/855): at connect the server asks for BINARY and SGA both ways; it accepts BINARY,
SGA and COM-PORT-OPTION and refuses every other option, and it answers only state changes, so
the two ends cannot loop. IAC IAC is the data byte FFh, and our FFh bytes are doubled. Without
BINARY, CR NUL becomes CR on the way in and CR goes out as CR NUL.

The server also speaks the server side of RFC 2217, so `rfc2217://` clients (pyserial, COM port
redirectors) can open it like a serial port. SIGNATURE, the speed/data bits/parity/stop bits
settings, SET-CONTROL, the two masks and PURGE-DATA are acknowledged. They are only logged: there
is no port behind the server to change. NOTIFY-MODEMSTATE reports CD, DSR and CTS on;
flow-control suspend/resume is logged only; there are no line state notifications and no BREAK.

Unless `--serial-only` is given, the `--port` ports (default 5003 and 3264) always open, raw or,
with `--telnet`, as Telnet, in addition to any `--telnet-port` ports. `--serial-only` opens no TCP
port at all and cannot be combined with `--telnet-port`.

### Serial ports

`--serial` takes a device or a pyserial URL (`ccmail/serialport.py`). Every kind is read by a
thread, so they all behave the same:

| `--serial` | what | port settings |
|---|---|---|
| `/dev/ttyUSB0`, `/dev/ttyS0` | local device, opened exclusively (a second program fails) | applied; DTR and RTS raised |
| `rfc2217://host:port` | network serial server (ser2net, terminal servers) | sent to the remote port, with DTR/RTS; DCD comes from its modem state notifications. URL options: `?ign_set_control` (servers that do not acknowledge SET-CONTROL), `?poll_modem` (ask for DCD when it is read), `?timeout=N` |
| `socket://host:port` | raw TCP to a serial bridge | none: giving any is an error |
| `loop://` | loopback (tests) | none: giving any is an error |

Port settings are accepted only with `--serial`, and are refused when they cannot work:

- `--baud N`: default 9600. It must be a rate the port takes (pyserial's list, the same for RFC
  2217; 300-115200 typical); any other is refused, and the error lists the valid rates.
  - On the cable to a client it is the line speed. A warning is logged when the clients do not know
    the speed (Remote: 300 and 1200-115200; the HP 200LX: 300-19200). The warning names the timers
    that apply: Remote's 6.2 s set, and our 6.2 s timers at every speed with the line clock at N bps.
  - To our own modem it is the DTE speed; the line speed comes from CONNECT.
- `--framing 8N1`: data bits, parity N/E/O/M/S, stop bits 1 or 2.
  - 7 data bits work only in the protocol's ASCII packet mode, so a warning is logged. The client
    must use that mode: Remote `COMM/ASCII`, the HP 200LX AsciiMode (`spec/link-layer.md` §3.1).
  - 5 and 6 data bits cannot carry cc:Mail at all (even ASCII packets use characters 20h-6Fh) and
    are refused.
  - 1.5 stop bits exist only with 5 data bits and are refused.
- `--flow none|rtscts|xonxoff|dsrdtr`: default none; `--rtscts` is the same as `--flow rtscts`.
  XON/XOFF also limits the link to ASCII packets, because binary frames contain 11h/13h; a warning
  is logged.
- `--capture FILE`: every byte on the port, in `tools/proxy.py`'s .bin form (`tools/frames.py`
  reads it).

Wrong settings, a port that cannot be opened and option combinations that make no sense stop
`serve` before it listens anywhere. For example, `--baud` without `--serial`, `--modem-init`
without `--modem`, or `--rtscts` with another `--flow`.

### A client on a cable (modem emulation)

    python3 -m ccmail.server serve --data D --serial /dev/ttyUSB0 --baud 2400 --serial-only
    python3 -m ccmail.server serve --data D --serial rfc2217://ts.example:7001 --baud 9600 --framing 8N1

The server plays a Hayes modem (`ccmail/modem.py`):

- AT commands are answered (echo, verbose or numeric results).
- `ATD...` gets `CONNECT <port speed>`. On socket:// and loop://, which have no speed, CONNECT
  says `--line-bps` or 9600. The clients take their line speed from that CONNECT, and a bare
  CONNECT would mean 300, so the speed is always given.
- The client's `+++ATZ`, or `+++` and a pause, ends the call. The server then goes back to command
  mode for the client's hang-up commands and the next call.
- A client set up for a null modem sends no commands: its link opener (or 80h in raw mode) starts
  the call directly.

The port keeps DTR and RTS on, so a null-modem cable shows the client DSR, DCD and CTS. If the
cable has no handshake lines, set the client's flow control to none.

### Our own modem (answer)

    python3 -m ccmail.server serve --data D --serial /dev/ttyS0 --modem --baud 38400 --flow rtscts --serial-only
    python3 -m ccmail.server serve --data D --serial rfc2217://ts:7002 --modem --modem-autoanswer 2

With `--modem` the port settings are for the link between the server and the modem (the DTE side).

- **Init**: `--modem-init "ATZ;AT E0 V1 Q0 &C1 &D2 S0=0"` (the default). Commands are separated
  by `;`; each must be printable ASCII, start with AT and have at most 40 characters after AT.
  Each command waits 3 s for OK. A failed round escapes (`+++` with guard times), toggles DTR and
  starts again, up to 3 rounds; then the server waits 10 s and tries again. The modem's replies
  are logged.
- **Answer**: `RING` gets `ATA`, and CONNECT must follow within 60 s. With
  `--modem-autoanswer N` (1-255 rings) the init adds `ATS0=N` and the server waits for the modem
  to answer by itself. `NO CARRIER`, `BUSY`, `ERROR`, `NO ANSWER` or `NO DIALTONE` (or their
  numeric codes) end the attempt; the server re-initialises the modem and waits again.
- **CONNECT speed** (the call's line speed):
  - A bare `CONNECT` means 300 bps; `CONNECT 14400/ARQ` means 14400.
  - A `CARRIER 9600` line before CONNECT, from modems set to report it, is the line speed and
    wins over a CONNECT that gives the DTE speed.
  - Many modems report the DTE speed in CONNECT unless told otherwise (for example `ATW2` or
    `S95`; add it to `--modem-init`). When CONNECT equals the port speed, a warning says so.
  - `--line-bps` sets the line speed by hand.
- **During the call** the far end's `+++` is data. The call ends:
  - when the session ends;
  - when DCD drops, watched once it has been seen high in the call, where the port can read it
    (a device, rfc2217://);
  - on `NO CARRIER` at the end of the received data followed by 0.5 s of quiet. A message that
    contains the text does not end the call, and the modem's line is not passed to the session.
- **Hang-up**: 1 s after the session ends (the modem's buffers drain), DTR goes low for 1 s
  (with &D2 the modem hangs up), then `ATH0`; without an OK, `+++` with guard times and `ATH0`
  again. Then the modem is re-initialised for the next RING.
- **Errors**: an error during a call is logged and the modem re-initialised. A port that is gone
  (device unplugged, network connection lost) ends the serial service; there is no reconnect.

### Our own modem (dial-out to a peer post office)

    "post_offices": {
      "BRANCH": {"password": "P", "call_password": "C", "mode": "LSEC",
                 "dial": "ATDT5551234",                  # instead of "connect"
                 "modem": "/dev/ttyS0",                  # or "rfc2217://ts:7002"
                 "baud": 38400, "framing": "8N1", "flow": "rtscts",            # optional
                 "modem_init": "ATZ;AT E0 V1 Q0 &C1 &D2 S0=0"}}               # optional; or a list

    python3 -m ccmail.server call --data D BRANCH [--capture call.bin]

The init, CONNECT parsing and hang-up are the same as when answering. Then the usual call to a
peer post office (`spec/router-to-router.md` 7.2) runs over the line, with the CONNECT speed as
its line speed.

If the call fails (`BUSY`, `NO CARRIER`, `NO ANSWER`, `NO DIALTONE`, `ERROR`, or no CONNECT
within 90 s), the command says
why and exits with status 1. The port settings are checked with the same rules as `--serial`.

The `call` command needs the modem port to itself, so stop a `serve --modem` on the same port
first: a local device is opened exclusively, and the second program fails with "cannot open".
There is no call scheduler yet.

## Configuration (`po.json`)

    {
      "post_office": "MYPOST",
      "codepage": 437,
      "users": {
        "user": "123",
        "Smith, Ann": {"password": "pw", "codepage": 866, "comments": "Sales",
                       "email": "ann@isp.example",
                       "smtp": {"host": "smtp.isp.example", "port": 587, "security": "starttls",
                                "user": "ann@isp.example", "password": "...", "verify_tls": true},
                       "fetch": {"protocol": "imaps", "host": "imap.isp.example",
                                 "user": "ann@isp.example", "password": "...", "folder": "INBOX",
                                 "interval": 300, "after": "keep"}}
      },
      "lock_after": 5,
      "allow_readonly": true,
      "max_msgs": 0,
      "msg_size_kb": 0,
      "post_offices": {
        "BRANCH": {"password": "what it sends us", "call_password": "what we send it",
                   "connect": "host:port", "mode": "LSEC", "ade": true}
      },
      "gateway": {
        "post_office": "INTERNET", "domain": "example.org",
        "listen": "127.0.0.1:2525", "smarthost": "127.0.0.1:2526",
        "security": "none", "verify_tls": true, "username": "", "password": "",
        "peer_address": "at",
        "retry_seconds": 3600, "retry_times": 72,
        "aliases": {"sales": "Smith, Ann", "info@company.com": "user"}
      }
    }

| key | meaning |
|---|---|
| `users` | `"name": "password"`, or `"name": {"password": ..., ...}` with the optional keys below |
| `lock_after` | lock a mailbox after N wrong passwords (default 0 = never); `unlock` clears it. The counts are kept in `failed_attempts` |
| `allow_readonly` | unknown callers get a read-only connection (they may send, not receive); default true, false refuses them |
| `max_msgs`, `msg_size_kb` | messages accepted per call and largest message size in units of 1000 bytes (default 0 = no limit) |
| `codepage`, user `codepage` | the DOS code page of the post office (default 437) and of each user's PC (default the post office's); a number, or a name such as `866u` (= 1125) |
| `ccintl` | path of a `CCINTL.TB` code page table file, if you have one; one in the data directory is used without this key (otherwise Python's codecs are used) |
| `admin` | the mailbox that receives mail addressed to "Administrator" (default `admin`) |
| `ndr_cc_admin` | copy non-delivery reports to the administrator |
| post office `ade` | exchange directory updates with this peer (`true`, or `{"prop": "0x53"}`) |
| post office `password`, `call_password` | what it sends us when it calls, what we send when we call it |
| post office `connect` | `host:port` to call it at over TCP |
| post office `mode` | packet mode when we call it: `LSEC`, `HSEC` (default) or `RAW` |
| post office `dial`, `modem` | call it through our own modem instead: the dial command (`ATDT...`) and the modem's device or `rfc2217://` URL; optional `baud`, `framing`, `flow`, `modem_init` (see [Connections](#connections)) |
| `gateway` | the internet gateway: its `post_office` name in the directory (default `INTERNET`), the mail `domain` of local users (default `localhost`), inbound SMTP `listen` address (none = no listener), outbound `smarthost` (`host:port`), retries every `retry_seconds` (default 3600), `retry_times` (default 72) |
| gateway `security`, `verify_tls` | the smarthost connection: `none` (default, plain SMTP) \| `starttls` (fails if the relay does not offer it) \| `ssl` (implicit TLS, e.g. port 465); `verify_tls` (default true) checks the relay's certificate and name, as for a user's `smtp`. `"starttls": true` is the older spelling of `"security": "starttls"` |
| gateway `username`, `password` | AUTH at the smarthost (in clear text with `security` `none`) |
| gateway `peer_address` | the generated address of a peer post office's user (in the From of that user's mail through this gateway): `at` (default) = `Name_at_PO@domain`, the form of the cc:Mail SMTP gateway and POP3/IMAP servers; `plus` = `Name+PO@domain` (RFC 5233 subaddress style, an option of this server). Inbound accepts both forms either way |
| gateway `aliases` | inbound address -> user: a local part (for the gateway `domain` only) or a full address (any domain); case does not matter |
| user `email` | the user's own internet address: From and envelope sender of the mail the user writes, and inbound mail to it (any domain) reaches the user |
| user `smtp` | the user's own outgoing server: `host`, `port` (default 587, 465 for `ssl`), `security` `starttls` (default) \| `ssl` \| `none`, `user`, `password`, `verify_tls` (default true) |
| user `fetch` | the user's own mailbox to fetch: `protocol` `pop3` \| `pop3s` \| `imap` \| `imaps`, `host`, `port` (default 110/995, 143/993, by `security`), `security` `ssl` \| `starttls` \| `none` (default `ssl` for pop3s/imaps, else `starttls`), `user`, `password`, `folder` (IMAP, default INBOX), `interval` seconds (default 300, at least 10), `after` `keep` (default) \| `seen` \| `delete`, `initial` (default 100: the first fetch takes only the newest 100 messages and leaves the older ones untouched; `0` = all), `verify_tls` (default true) |

`data-test/` and `data-r2r/` are example post offices.

### Per-user internet mail

**Warning: the passwords of external mail accounts (`smtp`, `fetch`) are stored in plain text in
`po.json`**, like the post office passwords. Keep `po.json` readable only by the server's account
(`chmod 600 po.json`; the server keeps the file's mode when it rewrites it) and use
application-specific passwords where the provider offers them.

Every per-user setting is optional; a user without them is handled exactly as before. Where a
user has one, it takes precedence over the shared gateway settings:

- **Inbound matching**, in this order: gateway `aliases` (full address, then the local part when
  the domain is ours), a user's own `email` (or, without one, the user's smtp `user` when that is an
  address), then the generated-name rules of the gateway (`spec/smtp-link.md` §3.3: the exact
  name, `_` or `.` for a space, `First_Last` also for `Last, First`; `postmaster`, `root` and
  `administrator` reach the `admin` mailbox; case does not matter), then the post office forms
  below. Inbound To/Cc addresses that are local users (also by alias or own address) are not
  repeated as internet recipients.
- **Post office forms**: `Name_at_PO@domain` and `Name+PO@domain` are both accepted, whatever
  `peer_address` says. With our own post office's name (`bob_at_MYPOST`, `bob+MYPOST`) they reach
  the local user. With a peer post office, configured in `post_offices` or learned through
  directory exchange (`ade`), the message is queued for that post office (`route/<PO>/`;
  a learned one goes to the partner that reaches it) addressed `Name at PO` as in the directory,
  exactly like a local user's mail to that user, and goes out at the next call. If directory
  entries learned from that post office exist, the name must be one of them (any case, `_` or
  `.` for a space); without them the message is accepted and the peer post office decides (its
  non-delivery report reaches the internet sender only if that post office routes the gateway
  post office back to us, see below). An unknown post office or user is refused with 550 at
  RCPT. `_` in a name is written `__` (`Kit__Walker_at_PO` is "Kit_Walker" at PO); a name with
  a comma is quoted (`"Walker,_Kit+BRANCH"@example.org`). A comment in parentheses is dropped
  and leaves its blank, as the cc:Mail gateway writes it: "Kit Walker (ACME)" at PO is
  `Kit_Walker__at_PO`, which is read back as Kit Walker.
- **Subaddresses** (RFC 5233, as Postfix and Sendmail use `+`): `Ann_Smith+news@example.org`
  reaches Ann; a `+detail` that is not a post office name is dropped. An alias takes its
  subaddresses too (`sales+promo` -> the `sales` alias), and so does a user's own `email`
  (`ann@isp.example` also takes `ann+news@isp.example`). The exact name is tried first, so a user
  whose name contains `+` is still found, and a `+detail` that names a peer post office always
  means that post office (`bob+BRANCH` is bob at BRANCH, never the local bob).
- **From address**: the user's `email`; without it, the smtp `user` if that is an address;
  otherwise the generated `Name@domain`. A user with `smtp` but no usable address has their
  internet mail refused at once with a report in their mailbox, and `serve` logs the configuration
  error at start.
- **Outgoing route**: mail the user writes goes only through the user's own `smtp` server, never
  through the shared smarthost. The route is fixed when the message is queued (`"via"` in
  `outbound/<id>.json`); a failure is retried (`retry_seconds`, `retry_times`) and then reported
  to the user, a 5xx refusal at once. `starttls` fails if the server does not offer it, so the
  password never goes out in clear text. Other users keep using the smarthost.
- **Without a gateway section**: the per-user settings also work without `listen`, `smarthost`
  or a `gateway` section (post office `INTERNET`, domain `localhost`). Then only users with their
  own `smtp` can send to the internet; others are refused at upload, as without a gateway.

Fetching: messages are converted like inbound SMTP mail (the user's code page, author
`Sender <addr> at INTERNET`) and the original is kept in `inbound/`. `serve` polls each account at
its `interval`, and fetches at the start of the user's call during the upload; before sending the
user's mail it waits at most 10 seconds, keeping the line serviced, then goes on with what is there
(the rest comes in the next call). HP 200LX interactive calls start the fetch without waiting. `after`:
`keep` leaves the server untouched (IMAP folders are opened read-only), `seen` sets the IMAP
\Seen flag (for POP3 the same as keep), `delete` removes the message on the server once stored.

Inbound mail that cannot be converted (from the SMTP listener or a fetch) is neither dropped nor
retried: the user gets a notice from `Postmaster at INTERNET`, subject
`Message could not be converted: <subject>`, with where and when it came from (SMTP peer and
MAIL FROM, or the fetch account, folder and UID/UIDL), every header that can still be read (From,
Sender, Reply-To, To, Cc, Date, Subject, Message-ID, Content-Type), the parts with their types,
names and sizes, the first 20 lines of a readable text part, and the reason. The original stays
as `inbound/<id>.eml`. The message counts as taken, so a fetch does not try it again at every
poll, and the SMTP listener still answers 250.

Fetch state, one file per user in `<data>/fetch/<user>.json`, written atomically after each
stored message (a `.lock` file next to it allows one fetch per user at a time, also between
`serve` and the `fetch` command):

- POP3: the UIDLs taken, and the UIDLs the first sync left (`skipped`); UIDLs no longer on the
  server are dropped after each complete listing. A server without UIDL is refused. With
  `delete`, a taken message still on the server is deleted again.
- IMAP: per folder the UIDVALIDITY, the last UID taken and the keys of the taken messages
  (Message-ID, or a hash of Date/From/To/Subject; the last 20000). When UIDVALIDITY changes, only
  the headers are fetched and a message is taken only if its key is unknown, so nothing is
  delivered twice and no old body is downloaded again.
- First sync: with no state yet (a new account or IMAP folder, and after a UIDVALIDITY change)
  only the newest `initial` messages are taken (default 100, `0` = all), newest by server order:
  UID order in the IMAP folder, message number order on POP3. The older ones are recorded as
  known (IMAP: the last UID passes them; POP3: their UIDLs), are never taken later and are left
  untouched on the server, whatever `after` says. Later fetches take every new message.
- Changing the account's `user` or `host`, or between POP3 and IMAP, starts with empty state, so
  the first-sync rule applies again. Renaming a user moves the user's state file and aliases.
- A message counts as taken only once it is stored; then the state is saved, then the server is
  told (seen/delete). A crash between storing and saving can deliver one message twice, never
  lose one.

### Examples: connecting to today's mail

ccmulator stays the post office for the cc:Mail side. It is not an IMAP or POP3 server, so desktop
mail programs do not read its mailboxes. On the internet side it is a mail client (per-user
`fetch` and `smtp`), or it sits behind a real mail server (the `gateway`). Only the parts of
`po.json` that matter are shown; any key not shown keeps its default.

**1. Each user brings their own mailbox (no domain of your own).** This needs no `gateway`
section. Every user fetches mail from the user's provider and sends through its server, under
the user's own address:

    "users": {
      "Smith, Ann": {"password": "pw", "email": "ann.smith@gmail.com",
        "fetch": {"protocol": "imaps", "host": "imap.gmail.com",
                  "user": "ann.smith@gmail.com", "password": "app password", "after": "keep"},
        "smtp":  {"host": "smtp.gmail.com", "port": 587, "security": "starttls",
                  "user": "ann.smith@gmail.com", "password": "app password"}},
      "Jones, Bob": {"password": "pw", "email": "bob@fastmail.example",
        "fetch": {"protocol": "imaps", "host": "imap.fastmail.example", "folder": "INBOX",
                  "user": "bob@fastmail.example", "password": "app password", "interval": 600},
        "smtp":  {"host": "smtp.fastmail.example", "port": 465, "security": "ssl",
                  "user": "bob@fastmail.example", "password": "app password"}},
      "Doe, Carol": {"password": "pw", "email": "carol@isp.example",
        "fetch": {"protocol": "pop3s", "host": "pop.isp.example",
                  "user": "carol", "password": "...", "after": "delete"},
        "smtp":  {"host": "mail.isp.example", "user": "carol", "password": "..."}}
    }

- **Passwords:** ccmulator logs in with a password (IMAP/POP3 LOGIN, SMTP AUTH). Providers that
  use two-step sign-in want an *app password* made for this purpose, and some accounts allow only
  token (OAuth2) sign-in, which ccmulator does not do. For such an account, have the provider
  forward the mail to a mailbox ccmulator can fetch, or to your own domain (example 2).
- **The first fetch takes the newest 100:** of the messages already in the IMAP `folder` (INBOX
  unless set) or the POP3 mailbox, only the newest 100 go to the user's cc:Mail mailbox; the
  older ones are remembered as seen and stay on the server as they are, even with `"after":
  "delete"`. Set `"initial"` to another number, or to `0` to take everything there however old.
  Everything that arrives after the first fetch is taken.
- **Fetch modes:** `"after": "keep"` (the default) leaves the mail on the server untouched: IMAP
  folders are opened read-only, so the messages also stay unread in the provider's web mail;
  ccmulator remembers what it took. `"seen"` marks them read (IMAP only; for POP3 it is the
  same as `keep`). `"delete"` removes them once stored; that suits a POP3 mailbox that should
  not fill up.
- **Ports and security:** `pop3s` and `imaps` use implicit TLS on 995 and 993; `pop3` and
  `imap` default to STARTTLS on 110 and 143 and refuse to log in when the server does not offer
  it (`"security": "none"` allows clear text). `interval` is in seconds (default 300, at least 10);
  `serve` also fetches when the user calls in.
- **Sending:** without `port`, `smtp` uses 587 with `starttls`, or 465 when `"security": "ssl"`
  (implicit TLS, as Bob has). Many providers rewrite or refuse a From that is not the account's
  address, so keep `email` equal to the login address. Carol's smtp `user` is not an address,
  so her `email` is required: without it her internet mail is refused with a report.
- **No `gateway` section** here, so only users with their own `smtp` can send to the internet; a
  user with only `fetch` receives, but that user's outgoing internet mail is refused at upload.
- **A server of your own with a self-signed certificate** (Dovecot, Postfix on the LAN):
  `"protocol": "imap", "security": "starttls", "verify_tls": false` (and `"verify_tls": false` in
  `smtp`). Only do this on a network you trust.
- **Check an account without waiting for a call:**
  `python3 -m ccmail.server fetch --data DIR "Smith, Ann"` (without a name: every user with
  `fetch`). It prints how many messages it took and their senders and subjects, or the error, and
  exits with status 1 if an account failed. The messages wait in `DIR/mail/<user>/` as `.msg`
  with a readable `.txt` copy next to each; `python3 -m ccmail.server show "DIR/mail/Smith,
  Ann/<id>.msg"` prints one.

**A shared mailbox for one user.** `fetch` delivers everything in the account to that user,
whatever the To header says, so a mailbox such as `info@company.example` can be read by one
cc:Mail user. A user has one `fetch` account; for a second mailbox, add a cc:Mail user for it:

    "Info Desk": {"password": "pw", "email": "info@company.example",
      "fetch": {"protocol": "pop3s", "host": "pop.company.example",
                "user": "info@company.example", "password": "...", "after": "delete"},
      "smtp":  {"host": "smtp.company.example",
                "user": "info@company.example", "password": "..."}}

**2. Your own domain, with a mail server in front.** The gateway's SMTP listener has no TLS and
no authentication, so keep it on localhost and let a real MTA (Postfix, Exim) face the internet:
the MX record, spam filtering, TLS. The MTA hands the domain's mail to ccmulator and relays what
ccmulator sends out:

    "users": {
      "Smith, Ann": {"password": "pw", "email": "ann.smith@example.org"},
      "Jones, Bob": {"password": "pw"}
    },
    "gateway": {
      "domain": "example.org",
      "listen": "127.0.0.1:2525",
      "smarthost": "127.0.0.1:25",
      "aliases": {"sales": "Smith, Ann", "bob": "Jones, Bob", "info@company.example": "Smith, Ann"}
    }

Postfix on the same machine, `main.cf`:

    relay_domains = example.org
    transport_maps = hash:/etc/postfix/transport

and `/etc/postfix/transport` (run `postmap /etc/postfix/transport` after editing):

    example.org    smtp:[127.0.0.1]:2525

This setup, the recipient checks and the smarthost notes below were tested with Postfix 3.10
(Debian 13). The transport entry also overrides `relay_transport = error` of Debian's "Local
only" configuration, so mail for the domain reaches ccmulator in either case; but for
ccmulator's outbound mail Postfix itself must deliver to the internet ("Internet Site", or a
`relayhost`): with "Local only" (`default_transport = error`) it accepts that mail and then
bounces it.

- **Addresses that arrive without an alias:** the name rules accept the name with `_` or `.` for
  the space, in any case, and a `Last, First` name also as `First_Last`. So
  `ann.smith@example.org`, `Ann_Smith@example.org` and `bob.jones@example.org` reach Ann and Bob
  as they are, and a user `Kit Walker` gets `Kit_Walker@example.org` or
  `kit.walker@example.org`. Aliases are for other names (`sales`, `bob`) and, as full
  addresses, for other domains the MTA hands over (`info@company.example`). Ann's own `email`
  reaches her as well. There is no catch-all: an address that matches nothing is refused at RCPT.
- **Users of peer post offices** (`post_offices`, or learned by directory exchange) are reached
  as `Kit_Walker_at_BRANCH@example.org` or `Kit_Walker+BRANCH@example.org`: the message waits in
  `route/BRANCH/` for the next call to BRANCH. Their mail out through this gateway has the From
  `Kit_Walker_at_BRANCH@example.org` (the cc:Mail gateway form), or
  `Kit_Walker+BRANCH@example.org` with `"peer_address": "plus"`; replies reach them either way.
  A reply (or a non-delivery report) from BRANCH back to an internet author
  (`Carol <carol@x.example> at INTERNET`) needs BRANCH to route the post office `INTERNET` to
  this post office. Directory exchange sends our users, not that entry, so add `INTERNET` on
  BRANCH as a post office reached through MYPOST. **Subaddresses** of local users work too:
  `ann.smith+news@example.org` reaches Ann.
- **From addresses:** Ann sends from her `email`, `ann.smith@example.org`. Bob, who has no
  `email`, sends from the generated address, which keeps the case, turns spaces into `_` and
  quotes a name with a comma: `"Jones, Bob" <"Jones,_Bob"@example.org>`. Replies to it reach him,
  but people rarely type it, so give him an `email` such as `bob@example.org` (the alias already
  delivers it).
- **Outbound route:** mail of users without their own `smtp` goes to the `smarthost`, with
  whatever From applies (a user's `email` may be on another domain; the relay may refuse that).
  Without a `smarthost` that mail is accepted and waits in `outbound/` until one is set.
- **The smarthost on localhost** is plain SMTP (`security` `none`, the default). Postfix relays
  for it without AUTH because 127.0.0.1 is in its `mynetworks` (the default since Postfix 3.0,
  `mynetworks_style = host`). If you set `"security": "starttls"` towards a local MTA whose
  certificate is self-signed (a distribution's "snakeoil" certificate, made for the host name),
  the connection fails on the certificate check (`CERTIFICATE_VERIFY_FAILED`, and with
  `127.0.0.1` also an IP address mismatch) and the message stays queued: add
  `"verify_tls": false`, or stay plain on localhost.
- **Without a local MTA:** point `smarthost` (`host:port`, the port is required) at your
  provider's relay: port 587 with `"security": "starttls"`, or 465 with `"security": "ssl"`
  (implicit TLS), plus `"username"` and `"password"`. The relay's certificate and host name are
  checked (`verify_tls`, default true), as for a user's own `smtp`; `starttls` fails if the relay
  does not offer it, so the password never goes out in clear text. With `security` `none`, a
  `username` and `password` go out in clear text.
- **The listener** speaks plain SMTP without STARTTLS or AUTH and answers 550 at RCPT for an
  address it does not know. Postfix as above accepts every address of a relay domain (an empty
  `relay_recipient_maps`, the default, accepts all recipients); the 550 from ccmulator then
  turns into a bounce from Postfix, and bounces to forged senders are backscatter. To refuse
  unknown recipients at Postfix's own RCPT, either list the valid addresses in
  `relay_recipient_maps`, or let Postfix ask ccmulator by address verification:

      smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination,
          reject_unverified_recipient
      unverified_recipient_reject_code = 550

  Postfix then asks ccmulator's listener (a probe that stops at RCPT) and answers `550 5.1.1
  ... Recipient address rejected: undeliverable address` for an unknown one, in the same
  session. The check is skipped for clients in `mynetworks`, so test it from outside, not from
  the machine itself. A list is hard to keep complete here (aliases, `_`/`.` variants,
  subaddresses, peer post office users), so verification is the better fit. With
  `recipient_delimiter = +` (Debian's default) a listed `ann.smith@example.org` also admits
  `ann.smith+news@example.org`, but it also admits `ann.smith+BRANCH@`, which ccmulator reads
  as a peer address, while an unlisted `Kit_Walker+BRANCH@` is refused ("User unknown in relay
  recipient table"); verification has no such gaps.
- **Exim** instead of Postfix: a `manualroute` router for the domain,
  `route_list = * 127.0.0.1::2525` with `self = send` and an `smtp` transport, and in the RCPT ACL
  `require verify = recipient/callout=10s,defer_ok` refuses unknown recipients at RCPT by asking
  ccmulator first. Mail from ccmulator to the smarthost is relayed when 127.0.0.1 is in
  `relay_from_hosts`.
- **Test the inbound side from the command line:** `swaks --server 127.0.0.1 --port 2525 --to
  sales@example.org --from you@elsewhere.example --body "hello"` (or any SMTP client; use
  `--port 25` to go through Postfix), then look
  in `DIR/mail/Smith, Ann/` (the `.txt` file, or `python3 -m ccmail.server show` on the `.msg`).
  The original is kept as `DIR/inbound/<id>.eml`; mail for a peer post office's user waits in
  `DIR/route/<PO>/`. For the outbound side, `python3 tools/smtpsink.py 2526 DIR/sink` stands in
  for the smarthost (`"smarthost": "127.0.0.1:2526"`) and stores each message as an `.eml` file.

**3. Both at once.** Most users go through the domain (example 2); a user's own settings take
precedence where the user has them:

- with their own `smtp`: the user's mail goes only through that server, never the smarthost;
- with their own `email` (and any domain): it is the user's From, and mail to it reaches the user
  through the listener when the MTA hands it over (and by the user's `fetch`, if there is one);
- with only `fetch`: the user receives mail from the private mailbox, and sends through the
  smarthost from the generated domain address (or the `email`, if set).

## Specifications

The protocol and formats as implemented, in `spec/`:

| file | contents |
|---|---|
| `link-layer.md` | frames, CRC, windows, acknowledgements, timers, line modes |
| `nak-storm.md` | retransmission behaviour on slow and noisy lines, with measurements |
| `session-layer.md` | login, message transfer, verdicts, header and tags |
| `items.md`, `file-items.md` | message items: text, files, embedded messages |
| `router-answer.md` | the answering post office's behaviour and limits per message |
| `router-to-router.md` | post office to post office exchange, routing, non-delivery reports, directory exchange |
| `directory-updates.md` | directory update messages and requests |
| `limits.md` | size and count limits |
| `codepages.md` | code page tags and conversion |
| `smtp-link.md`, `pop3-imap.md` | the internet mail mapping |
| `negotiation.md`, `newer-client-check.md` | the newer session negotiation and newer clients |
| `hp200lx-check.md` | HP 200LX client: protocol notes and interactive mode |
| `podb.md` | the post office database file format |

## Tests

    python3 -m unittest discover -s tests

The tests use synthetic data only. They write to a temporary directory (`CCMAIL_TEST_DIR` to
choose it). The gateway and fetch tests run small SMTP, POP3 and IMAP servers on localhost; the
TLS tests make a self-signed certificate with `openssl` in that directory and are skipped
without it. The transport tests drive the modem emulator over a pty, `socket://` and
`rfc2217://`, our own modem against a scripted fake modem (`tests/fakemodem.py`; directly, behind
pyserial's RFC 2217 server and behind `socket://`), and the Telnet port with a raw client and
pyserial's RFC 2217 client; they need pyserial, and the pty test needs a system with ptys (both
are skipped otherwise).

Tools: `tools/frames.py` (decode a capture), `tools/proxy.py` (record a call between a client and
a post office), `tools/linesim.py` (simulate a slow, noisy line), `tools/hpclient.py` (a simulated
HP 200LX client for interactive mode), `tools/mobileclient.py` (a scripted newer-client call),
`tools/smtpsink.py` (an SMTP sink for gateway tests), `tools/ccpodb.py` (post office file tool).

## Status

Tested against the original clients and Router post offices, including a real HP 200LX over a
serial cable. The per-user internet mail (own address, own SMTP server, POP3/IMAP fetching, with
and without TLS) is covered by tests against local test servers. The Telnet port, the serial
URLs and our own modem (answer and dial-out) are covered by tests with pyserial's RFC 2217 client
and server, a pty and a scripted fake modem; they are not yet tested with a real modem, ser2net
or tcpser. Not done yet: return receipts generated by the post office, scheduled calls to peer
post offices, bulletin boards and mailing lists, the newer clients' mailbox synchronization.

## License

GNU General Public License, version 2 or (at your option) any later version; see `LICENSE`.
