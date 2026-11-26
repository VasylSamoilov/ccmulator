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
- **Code pages**: per-user DOS code pages; messages are converted for each receiver.
- **Directory**: address book commands; directory update messages for clients; directory exchange
  with peer post offices, so all post offices share one address book.
- **Post office to post office**: mail routing to and from peer post offices, calling them and
  answering their calls.
- **Internet gateway**: SMTP in and out, with the address, header and attachment mapping of
  `spec/smtp-link.md`; gateway aliases (`sales@yourdomain`, or any full address, to a user).
- **Per-user internet mail**: a user's own email address (From, envelope sender, inbound
  matching), her own outgoing SMTP server (STARTTLS, SSL), and fetching from her own POP3, POP3S,
  IMAP or IMAPS account into her cc:Mail mailbox, polled in the background and at the start of her
  call, with persistent state so nothing is fetched twice.
- **HP 200LX interactive mode**: the client browses, reads, files, deletes and sends mail on the
  server during the call.
- **Post office files**: read, and write (deliver, add users, mark read, delete messages) cc:Mail
  post office database files (`ccmail/podb.py`, `tools/ccpodb.py`).

## Requirements

Python 3 (developed and tested on 3.13), standard library only. `pyserial` (3.x) is needed for
serial ports (`serve --serial`, `call` with `"dial"`); TCP and Telnet work without it.

## Running

    python3 -m ccmail.server serve --data data-test                 # TCP ports 5003 and 3264
    python3 -m ccmail.server serve --data data-test --telnet-port 2323
    python3 -m ccmail.server serve --data data-test --serial /dev/ttyUSB0 --baud 2400 --serial-only

`--data` is the post office directory: `po.json` (configuration) plus folders created at run time
(`mail/<user>/` waiting mail, `received/`, `delivered/<user>/`, `route/<post office>/`,
`outbound/`, `inbound/`, `fetch/<user>.json`, ...). Each message is stored in its wire form
(`.msg`) and as readable text (`.txt`).

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
    python3 -m ccmail.server directory   --data DIR --to user

A running server picks up changes to `po.json`. Every user or post office change queues a
directory update with that entry for all users (`--no-update` to skip); a new user gets the whole
directory. Names are unique across users and post offices, at most 126 characters; passwords at
most 63. `user set --email` checks that the address has the form name@domain and that no other
user has it; it keeps the user's other settings (`smtp`, `fetch`, ...).

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

`call` connects to the post office's `"connect"` address over TCP, or, with `"dial"`, through our
own modem (see [Connections](#connections)). `po list` shows the address or the dial string.

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

Unless `--serial-only` is given, the raw ports (default 5003 and 3264) always open, in addition to
any Telnet ports. `--serial-only` opens no TCP port at all and cannot be combined with
`--telnet-port`.

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
- **Answer**: `RING` gets `ATA`. With `--modem-autoanswer N` the init adds `ATS0=N` and the server
  waits for the modem to answer by itself. `NO CARRIER`, `BUSY`, `ERROR` or `NO ANSWER` end the
  attempt; the server re-initialises the modem and waits again.
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
- **Hang-up**: DTR goes low for 1 s (with &D2 the modem hangs up), then `ATH0`; without an OK,
  `+++` with guard times and `ATH0` again. Then the modem is re-initialised for the next RING.
- **Errors**: an error during a call is logged and the modem re-initialised. A port that is gone
  (device unplugged, network connection lost) ends the serial service; there is no reconnect.

### Our own modem (dial-out to a peer post office)

    "post_offices": {
      "BRANCH": {"password": "P", "call_password": "C", "mode": "LSEC",
                 "dial": "ATDT5551234",                  # instead of "connect"
                 "modem": "/dev/ttyS0",                  # or "rfc2217://ts:7002"
                 "baud": 38400, "framing": "8N1", "flow": "rtscts",            # optional
                 "modem_init": "ATZ;AT E0 V1 Q0 &C1 &D2 S0=0"}}               # optional

    python3 -m ccmail.server call --data D BRANCH [--capture call.bin]

The init, CONNECT parsing and hang-up are the same as when answering. Then the usual call to a
peer post office (`spec/router-to-router.md` 7.2) runs over the line, with the CONNECT speed as
its line speed.

If the call fails (`BUSY`, `NO CARRIER`, `NO ANSWER`, or no CONNECT within 90 s), the command says
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
        "starttls": false, "username": "", "password": "",
        "retry_seconds": 3600, "retry_times": 72,
        "aliases": {"sales": "Smith, Ann", "info@company.com": "user"}
      }
    }

| key | meaning |
|---|---|
| `lock_after` | lock a mailbox after N wrong passwords (0 = never); `unlock` clears it |
| `allow_readonly` | unknown callers get a read-only connection (they may send, not receive) |
| `max_msgs`, `msg_size_kb` | messages accepted per call and largest message size (0 = no limit) |
| `codepage`, user `codepage` | the DOS code page of the post office and of each user's PC |
| `ccintl` | path of a `CCINTL.TB` code page table file, if you have one (otherwise Python's codecs are used) |
| `admin` | the mailbox that receives mail addressed to "Administrator" (default `admin`) |
| `ndr_cc_admin` | copy non-delivery reports to the administrator |
| post office `ade` | exchange directory updates with this peer (`true`, or `{"prop": "0x53"}`) |
| post office `connect` | `host:port` to call it at over TCP |
| post office `dial`, `modem` | call it through our own modem instead: the dial command (`ATDT...`) and the modem's device or `rfc2217://` URL; optional `baud`, `framing`, `flow`, `modem_init` (see [Connections](#connections)) |
| `gateway` | the internet gateway: its post office name in the directory, the mail `domain` of local users, inbound SMTP `listen` address, outbound `smarthost` (with `starttls`, `username`, `password`), retries |
| gateway `aliases` | inbound address -> user: a local part (for the gateway `domain` only) or a full address (any domain); case does not matter |
| user `email` | the user's own internet address: From and envelope sender of the mail she writes, and inbound mail to it (any domain) reaches her |
| user `smtp` | her own outgoing server: `host`, `port` (default 587, 465 for `ssl`), `security` `starttls` (default) \| `ssl` \| `none`, `user`, `password`, `verify_tls` (default true) |
| user `fetch` | her own mailbox to fetch: `protocol` `pop3` \| `pop3s` \| `imap` \| `imaps`, `host`, `port` (default 110/995, 143/993), `security` (default `ssl` for pop3s/imaps, else `starttls`), `user`, `password`, `folder` (IMAP, default INBOX), `interval` seconds (default 300), `after` `keep` (default) \| `seen` \| `delete`, `verify_tls` (default true) |

`data-test/` and `data-r2r/` are example post offices.

### Per-user internet mail

**Warning: the passwords of external mail accounts (`smtp`, `fetch`) are stored in plain text in
`po.json`**, like the post office passwords. Keep `po.json` readable only by the server's account
(`chmod 600 po.json`; the server keeps the file's mode when it rewrites it) and use
application-specific passwords where the provider offers them.

Every per-user setting is optional; a user without them is handled exactly as before. Where a
user has one, it takes precedence over the shared gateway settings:

- **Inbound matching**, in this order: gateway `aliases` (full address, then the local part when
  the domain is ours), a user's own `email`, then the generated-name rules of the gateway
  (`spec/smtp-link.md` §3.3). Inbound To/Cc addresses that are local users (also by alias or own
  address) are not repeated as internet recipients.
- **From address**: her `email`; without it, the smtp `user` if that is an address; otherwise the
  generated `Name@domain`. A user with `smtp` but no usable address has her internet mail refused
  at once with a report in her mailbox, and `serve` logs the configuration error at start.
- **Outgoing route**: mail she writes goes only through her own `smtp` server, never through the
  shared smarthost. The route is fixed when the message is queued (`"via"` in
  `outbound/<id>.json`); a failure is retried (`retry_seconds`, `retry_times`) and then reported
  to her, a 5xx refusal at once. `starttls` fails if the server does not offer it, so the password
  never goes out in clear text. Other users keep using the smarthost.
- **Without a gateway section**: the per-user settings also work without `listen`, `smarthost`
  or a `gateway` section (post office `INTERNET`, domain `localhost`). Then only users with their
  own `smtp` can send to the internet; others are refused at upload, as without a gateway.

Fetching: messages are converted like inbound SMTP mail (her code page, author
`Sender <addr> at INTERNET`) and the original is kept in `inbound/`. `serve` polls each account at
its `interval`, and fetches at the start of the user's call while she uploads; before sending her
mail it waits at most 10 seconds, keeping the line serviced, then goes on with what is there (the
rest comes in the next call). HP 200LX interactive calls start the fetch without waiting. `after`:
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

- POP3: the UIDLs taken; UIDLs no longer on the server are dropped after each complete listing. A
  server without UIDL is refused. With `delete`, a taken message still on the server is deleted
  again.
- IMAP: per folder the UIDVALIDITY, the last UID taken and the keys of the taken messages
  (Message-ID, or a hash of Date/From/To/Subject; the last 20000). When UIDVALIDITY changes, only
  the headers are fetched and a message is taken only if its key is unknown, so nothing is
  delivered twice and no old body is downloaded again.
- Changing the account's `user` or `host`, or between POP3 and IMAP, starts with empty state (everything
  there is new). Renaming a user moves her state file and her aliases.
- A message counts as taken only once it is stored; then the state is saved, then the server is
  told (seen/delete). A crash between storing and saving can deliver one message twice, never
  lose one.

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
