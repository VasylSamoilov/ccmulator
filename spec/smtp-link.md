# Internet mail mapping

How cc:Mail messages map to and from Internet mail (RFC 5322 / MIME, sent over SMTP):
addresses, headers, priorities, receipts, items and attachments, code pages and undeliverable
mail.

Compatibility: the mapping follows the conventions of Lotus's cc:Mail SMTP gateway (R8.1), so
that addresses, replies and re-imported messages work the same way between this server, that
gateway and Lotus's POP3/IMAP servers (pop3-imap.md). §1–§6 state the convention; §7 says where
this server (`ccmail/gateway.py`) follows it and where it differs.

Terms: the **gateway** is the program that converts; the **gateway post office** is its entry in
the directory; **host.domain** is the gateway's configured Internet host and domain, lowercased
(the host part may be left out, then it is just the domain); the **relay** is the SMTP host that
outbound mail is handed to. "Peer gateway" marks behaviour of the Lotus gateway that a
compatible implementation must expect but need not copy.

## 1. The gateway in the directory

- The gateway is a post-office entry (location P) in the hub's directory; mail addressed to that
  post office is mail for the Internet. The conventional name is `INTERNET-MAIL`; the entry's
  address field is left blank.
- Other post offices whose directory entry is location `p` with Address = the gateway name are
  **aliases** of the gateway: mail to them is Internet mail too.
- A directory entry can carry an **Internet address** field (the R8.1 POP3/IMAP servers read the
  same field, pop3-imap.md §1). It is used for outbound recipients (§2.1 step 2) and for inbound
  matching (§3.3, FAN). Not determined: which field of the directory entry it is.

## 2. Outbound: cc:Mail → SMTP

### 2.1 Recipients

| Step | Rule |
|---|---|
| 1 | Each To / Cc / Bcc recipient is formed as `name + " at " + PO` (PO = the recipient's post office). |
| 2 | If the PO is the gateway and a directory entry of that name exists, the name is replaced by that entry's Internet address (§1). |
| 3 | PO = text after the **last** " at ". It is the gateway if it equals the gateway name, or is an alias PO (§1). |
| 4 | **Internet recipient** (PO = gateway): address = text before the last " at "; if it has `<...>` the inside is used; a `(...)` comment is blanked and then all spaces removed; a trailing `@` gets the relay host name appended. No domain is added; spaces are kept if there is no comment. |
| 5 | **cc:Mail recipient at another post office** (not the gateway): address generated with the From rule (§2.2). These appear in To / Cc headers but get **no RCPT**. |
| 6 | Envelope: `RCPT TO:<addr>` for each Internet To, then Cc, then Bcc. All refused → RSET; some refused → undeliverable report for those (§4.2). |
| 7 | Limits on inbound-to-cc:Mail are in §3. Optional outbound size limit in KB: `size>>10 >= max` → returned to the sender (§4.3) with "The administrator has limited the message size to %d Kbytes". |

All addresses are converted both ways, including the destination fields (To, Cc, Bcc).

### 2.2 From address

| Step | Rule |
|---|---|
| 1 | Input = `authorName + " at " + authorPO`. Not determined: whether the author PO is the hub's own name for a hub-local author. |
| 2 | If the author contains `<...>` (e.g. mail that came in from SMTP): address = inside of `<>`, quotes / comments removed, spaces removed. |
| 3 | Else look up the lowercased full "name at po" in the address translation table (§6; first non-empty of the slots `name:00..31`; then with " at PO" stripped). |
| 4 | Miss: delete `"..."` and `(...)` and trim spaces, look up again. |
| 5 | Miss again: **generate**. Nothing on this path compares the PO with the hub PO name, so the hub-local form depends on step 1 (not determined): if the author PO is the hub name, local users also get `_at_<hub>`. If the author's PO has a domain translation entry (§6), drop " at PO" and use the subdomain. Then every `_` → `__`, every space → `_`, the result **lowercased**. Address = `local@[subdomain.]host.domain`. " at " is not removed when there is no subdomain, so a remote-PO user becomes `name_at_po@host.domain`. Dots and commas are kept. |
| 6 | Example: "Kit Walker (ACME Corporation)" at POname → `kit_walker__at_poname@host.domain` (the product documentation shows it in mixed case, `Kit_Walker__at_POname@host.domain`; the peer gateway lowercases). |
| 7 | With automatic table additions on, the generated pair is added to the table; with them off, the message is **returned** (§4.3) with "There is no entry in Address Translation Table for "%s"". |
| 8 | Display name (optional): text before " at ", RFC 1522-encoded if 8-bit, wrapped in `"` unless it starts with `"`. The peer gateway writes it **without a space** before `<`: `From: "John Valentine"<john_valentine@host.domain>`; the documented form is `"John Valentine" <jvalentine@silver.com>`. |

### 2.3 Headers and transaction

Lines end in CRLF. The peer gateway sends one message per connection:

```
HELO <host.domain>
MAIL FROM:<from-address>
RCPT TO:<addr>            (per internet recipient: To, then Cc, then Bcc)
DATA
Received: from ccMail by <host.domain> (ccMail Link to SMTP R8.10.00)
    id <last 11 chars of id>; <now: date + zone>
Message-Id: <<id>@<host.domain>>
X-Mailer: ccMail Link to SMTP R8.10.00
Date: <message date + zone>
From: ["display"]<addr>
Return-Receipt-To: <addr>                  (receipt requested and receipt mapping on)
To: <a>,
\t<b>                                      (internet To first, then cc:Mail-PO To)
Cc: <...>                                  (same)
[Encoding: <n> Text, <n> uuencode ...]     (RFC 1154; only if enabled, see §8)
Subject: <subject>
MIME-Version: 1.0
Content-Type: ...                          (multipart/mixed; boundary="simple boundary", or the single part's type)
[Content-Transfer-Encoding: ...]
[Content-Description: ...]

<body>
.
QUIT
```

| Header | Rule |
|---|---|
| Received | `from POP3 Client by` instead of `from ccMail by` for mail from POP3 clients. |
| Message-Id | id = `%y%m%d` of now + first 4 digits of time_t + `.AA` + time_t decimal; time_t bumped by 1 if equal to the previous one. |
| Date | `"%a, %d %b %Y %H:%M:%S "` (`%y` if year < 2000) + `+hhmm` / `-hhmm`, or `GMT` for a zero offset. Value = the cc:Mail stored local date/time; invalid → current time (the product documentation says out-of-range dates come out as 1970). Peer gateway: the zone is the standard offset only, **DST ignored**. |
| Subject | Cut at the first CR/LF. Pure ASCII as is; empty → `No subject given`; any byte ≥ 0x80 → RFC 1522 Q words (B for code page 932), folded at 70 (B: 76) with CRLF SP. **Bytes are not converted**: the charset label is taken from the subject code page via a table: 850, 437, **1252 → "US-ASCII"**, 34193–34201 → ISO-8859-1..9, 932/32769 → ISO-2022-JP, 936 → GB2312. |
| Return-Receipt-To | = From address, when the message requests a return receipt (optional, on by default). |
| Bcc | **never written**; bcc recipients only get RCPT. |
| Not generated | Sender, Reply-To, Errors-To, Importance, X-Priority. Peer gateway: **no priority is mapped either way**; the R8.1 POP3/IMAP servers do map it (pop3-imap.md). |
| Dot-stuffing | Peer gateway: **none** (the body is sent raw). Only indirect protection: text with `\r\n.\r\n` is classed 8-bit → QP, and the QP encoder writes a line-start `.` as `=2E`. |

### 2.4 Items → body

Item types: 1 text, 2 (inferred graphics), 3 file, 4 fax; a file item with a finder-info stream
(24) is a **Macintosh file** and is built as AppleSingle from streams 8 / 40 / 24. Untitled items
are named `TextItem`, `FaxItem`, `FileItem`; a trailing date stamp is removed from titles.

- A text item is read up to **22528 bytes**; longer text is cut (peer gateway).
- Text conversion: from the item code page (or the configured default if none) to its Internet
  code page: 437, 850, 851, 860, 861, 863, 1252, 0 → **34193 (ISO-8859-1)**; 852, 1250 → 34194
  (-2); 865 → 34196 (-4); 866, 1251 → 34197 (-5); 1256 → 34198; 1253 → 34199; 862, 1255 →
  34200; 857, 1254 → 34201; 932 → 32769 (ISO-2022-JP); 1200 → 1201 (codepages.md).
- Charset label from the Internet code page; unknown → `ISO-8859-1`; 32769 ISO-2022-JP 7bit;
  950 / 936 / 949 Big5 / GB2312 / EUC-KR base64; 32770 ISO-2022-KR 7bit. A peer may substitute
  labels by configuration.
- Classifier: > 2 NUL / 0xFF bytes → binary; any byte ≥ 0x80 or `\r\n.\r\n` → 8-bit; else 7bit.
- 7bit text part: `Content-Type: text/plain; charset=<cs>` / `Content-Transfer-Encoding: 7bit` /
  `Content-Description: "cc:Mail Note Part"`; text raw, **no line wrapping**.
- 8-bit text part: `Content-Type: text/plain; charset=<cs>` / `Content-Transfer-Encoding:
  Quoted-Printable` (no Description); QP soft break after 70 chars.
- File items: extensions SAM and LWP always binary; an 8-bit file not ending .TXT → binary; a 7bit
  file → `Content-Type: text/plain; charset=..; name="n"`, 7bit, `Content-Disposition:
  attachment; filename="n"`.
- Binary part: `Content-Type: application/octet-stream; name="n"` (Mac: `application/applefile;
  name="n"`, or `application/mac-binhex40; name="n"` 7bit), `Content-Transfer-Encoding: base64`
  (76-char lines) or `x-uuencode`. **No Content-Disposition** on binary parts. Fax items (type 4)
  are not given a separate Content-Type; their kind shows only in the uuencode preamble ("Fax")
  and the RFC 1154 `EDI X12` count.
- Attachment format: base64 (MIME) by default, uuencode optionally; Macintosh files AppleSingle
  base64 by default, BinHex optionally.
- Domain-based encoding: an optional list of domains (each trimmed, lowercased); an entry matches
  as a substring of the text after the last `@` of a recipient; the first hit forces uuencode
  (BinHex for Mac) for the binary attachments of the whole message.
- uuencode: preamble `The following is an attached <kind> item from cc:Mail.  It contains
  information that had to be encoded to ensure successful transmission through various mail
  systems.  To decode the file use the UUDECODE program.` + `---------------------------------
  Cut Here ---------------------------------`, then `begin 644 <basename>` (`FileItem` if the
  name has 8-bit chars), 45-byte lines, `" \r\nend\r\n"`; in MIME mode under an `x-uuencode`
  part header.
- One item → not multipart: its part headers become the top-level headers (a single 7bit text
  *file* loses its filename). Several items → `multipart/mixed; boundary="simple boundary"`, no
  preamble, each part `\r\n--simple boundary\r\n<headers>\r\n\r\n<data>`, closed by
  `--simple boundary--`. (`MIME.PART.BOUNDARY.=.12345678` is not used here.)
- Forwarded messages: no special handling found. Not determined: how forward history (embedded
  headings) is sent.

## 3. Inbound: SMTP → cc:Mail

### 3.1 SMTP server

Peer gateway behaviour:

- Greeting `220 <host.domain> Service ready`. Commands matched by prefix against HELO, MAIL From,
  RCPT, NOOP, DATA, RSET, SEND, SOML, SAML, VRFY, EXPN, HELP, QUIT, TURN (**no EHLO**; unknown →
  `500 Command unrecognized`).
- Replies: `250 Pleased to meet you `, `250 Sender OK `, `250 Recipient OK `, `354 Start mail
  input; end with <CRLF>.<CRLF> `, `250 Reset state`, `221 ccMail Link to SMTP closing connection
  `, `502 Command not implemented `, `250 Mail accepted`. Errors `554 Unbalanced < or >`, `503
  Sender already specified`, `550 Invalid "Mail From" specified`, `503 No sender specified`, `503
  No recipients specified`, `451 Connection Timed Out`.
- **RCPT is not checked** at RCPT time (stored); unknown users are bounced after DATA (§4.1).
- First HELO adds `Received: from <arg> by <host.domain> (ccMail Link to SMTP R8.10.00)\r\n\t;
  <date+zone>`; MAIL FROM adds `Return-Path: <addr>`.
- DATA ends at `\r\n.\r\n` (or `\n.\n`), dot-unstuffed, LF normalised to CRLF.
- Unsupported address forms: `@host.domain:user@host.domain`, `"user@something"@host.domain`,
  `"user name"@host.domain`. Bang paths are returned.

### 3.2 Header parsing

Repeated header fields are joined with ','.

| Field | Rule |
|---|---|
| MIME? | MIME-Version contains "1.0" and Content-Type does not contain "partial". message/partial → non-MIME path (delivered with the MIME section still encoded). |
| Date | RESENT-DATE:, else DATE:; the zone is ignored (wall-clock time kept as written); 2-digit years > 90 → 19xx; unparsable → now. Stored as the message date (mday, mon+1, year−1900) and time (sec, min, hour). |
| Author source | first non-empty of **REPLY-TO:, RESENT-FROM:, FROM:, RETURN-PATH:** (Reply-To wins). |
| Author form | RFC 1522 decoded; CR/LF/TAB/`,` → space. If it has `<` and `>`: `<value> at <gateway>`; else `"<" + value + "> at " + gateway`. E.g. `John Doe <jd@x.com> at INTERNET-MAIL`, `<jd@x.com> at INTERNET-MAIL`. Length limit 126 incl. " at gateway": first reduce to the bare address, then cut and append `~`. Stored: author name = text before " at gateway", author PO = gateway name. |
| Own bounce returning | a value containing ` (cc:Mail Link to SMTP Administrator)` is cut there; ` at <hub PO>` appended if no " at ". |
| Subject | RFC 1522 decoded, TAB/CR/LF → space, **cut at 60**, missing → `No subject given`; stored with its code page. |
| To | first non-empty of RESENT-TO:, X-ENVELOPE-TO:, TO: |
| Cc | RESENT-CC:, X-ENVELOPE-CC:, CC:, APPARENTLY-CC: |
| Bcc | RESENT-BCC:, X-ENVELOPE-BCC:, BCC:, APPARENTLY-BCC: |
| Apparently-To | → Bcc if there is no To/Cc/Bcc, else → To. |
| Envelope vs header | header recipients matching an RCPT are flagged "was RCPT"; RCPT addresses in no header are added as **Bcc**. Duplicates in RFC 821 and 822 are delivered once. |
| Errors-To / Return-Path | ERRORS-TO:/ERROR-TO: kept (bounce target), RETURN-PATH: kept. |
| Return-Receipt-To | → cc:Mail return receipt requested (optional, on by default). |
| Priority / Importance / Sensitivity | Peer gateway: parsed but **never mapped**; no priority is set. |
| Header > 0x19000 bytes (100 KB) | bounced: "Undeliverable message. The RFC 822 header is over 100k." |
| Loop | Subject contains `cc:Mail Link to SMTP Undeliverable Message` and > 2 "Received from <same first token>" lines in the first 100 → "This is a looping message." |
| Junk mail | optional: author contains a configured junk domain (substring) → deleted or set aside. |

### 3.3 Recipient → cc:Mail user

Local-domain test: the domain after the last `@`, case-insensitive, equals host.domain, the
first label of host.domain, the configured domain, a configured alias domain, or
`<subdomain>.<host.domain>` of a domain translation entry (then rewritten to
`<local>_at_<PO>@<host.domain>`). Inbound messages not addressed to these domains are returned
to the relay host.

Order for a local recipient:

1. Address translation table (§6, SMTP → cc:Mail): the address; address + "." + domain;
   local@host.domain; local@domain; local@first-host-label. A hit "name at PO" is added with
   that PO.
2. Smart Addressing, if on, on the lowercased local part with quotes removed:
   1. contains `_at_`: `_`→space, `__`→`_`, split "name at PO", match; otherwise match the local
      part as is;
   2. all `_` → space, split on " at ", match;
   3. `.` → space, `..` → `.`, split/match;
   4. FLast: first char = initial, rest = last name; exact matches over both "Last, First" and
      "First Last" directory names, then a 7-character prefix match; more than one →
      "The cc:Mail recipient is ambiguous: " and fail;
   5. FAN: match the local part against the entries' Internet address field (§1), take that
      entry's name;
   6. local part starting with `root`, `postmast`, `Administrator` → the post office
      administrator (e.g. `Root@yourcompanyname.com`, `Postmaster@SMTP`);
   7. else not found (→ NDR, §4.1).

   A Smart Addressing match is added to the table (unless the name contains " at " — then
   rejected) and unless the table is write-protected. With Smart Addressing off,
   only users listed in the table receive inbound mail.
3. Directory match on the name, then added as a recipient at its PO. RCPT recipients and
   header-only recipients are added as different recipient classes for To / Cc / Bcc (the
   header-only ones probably "not delivered here"; not determined). Duplicates skipped.
4. **Non-local header recipients** are added as gateway recipients: name = the address, PO =
   gateway, i.e. shown as `x@y at INTERNET-MAIL` (so Reply-All works). There is an exception (a
   name-only add) that depends on POP3 client support and on whether the From had `<>`; not
   determined: the exact condition and its result. Long ones are cut to 126 with `~`. The
   display name is kept unless it has `=?`, `\`, ESC$B, 8-bit bytes or is > 64 chars (then the
   bare address).
5. More than 50 recipients: non-local ones are dropped; still > 50 → "Too many recipients.\r\n\t
   Please send separate messages with less than 50 recipients."

### 3.4 Body → items

- Non-MIME body: all non-uuencode lines → one text item `Text Item`; each `begin NNN name` … `end`
  block → uudecoded file item named from the begin line (RFC 1522 decoded, > 60 chars → 58 +
  `~`); the gateway's own uuencode preamble (§2.4) sets kind Fax / Text / File; AppleSingle /
  Double magic → Mac file. 20+ uuencoded blocks → "Too many file attachments ... less than 20
  attachments".
- Sun `X-Sun-Attachment` bodies: parts split on `----------`; X-Sun-Data-Type text → text item
  `Text item`, else file named by X-Sun-Data-Name; X-Sun-Encoding-Info uuencode decoded;
  X-Sun-Charset kept.
- MIME: base64, quoted-printable, x-uuencode, x-uue decoded; no Content-Type = text/plain;
  US-ASCII.
- File name from Content-Type `name=`, Content-Disposition `filename=`, else Content-Description.
- First part of type text / multipart / message → text item `Text Item` (or its file name); later
  unnamed text part → `FileItem.txt`, a text item only if Content-Description is `cc:Mail Note
  Part` (quoted or not), else a file; non-text → `FileItem` file (Mac AppleSingle / Double → Mac
  file with data / resource / finder streams 8 / 40 / 24). A named text part becomes an
  attachment. multipart/alternative has no special handling (each alternative becomes an item;
  inferred, no other handling was found).
- Charset → stored code page (default 850): US-ASCII → 850; ISO-8859-1..9 → 34193..34201;
  ISO-2022-JP → 32769; GB2312 family → 936; EUC-KR family → 949; ISO-2022-KR → 32770; Big5 →
  950; EUC-TW → 1204; UTF-7 → 1201; UTF-8 → 1202. Only **transformation** code pages (1201–1204,
  32769–32770) are converted (1201/1202 → 1200, 1203 → 34193, 32769 → 932, 32770 → 949, 1204 →
  950); others are stored **unconverted**, tagged with that code page (codepages.md). No charset →
  the configured default code page, no conversion.
- A text item over 20480 bytes becomes a file item `TextItem.txt`; > 80 items → refused; empty
  files or files of only CRLF skipped.
- RFC 822 header item (optional, on by default): the whole header, RFC 1522-decoded, minus Bcc
  lines (and Apparently-To when used as Bcc), attached as **file** `RFC822.TXT`.
- Size: optional inbound limit in KB (0 = any) → refused with "You can send messages if the size
  is less than N Kbyte."

## 4. Undeliverable mail

### 4.1 Inbound recipient not found → SMTP message to the sender

- To: Errors-To / Error-To, else Return-Path (without `<>`), else From.
- From: `<PO admin> at <PO name>` through the From rule (§2.2). Subject:
  `cc:Mail Link to SMTP Undeliverable Message`. Date now.
- Body, multipart `simple boundary`, part 1 `Content-Type: text/plain; charset=US-ASCII`,
  `Content-Transfer-Encoding: 7bit`:
  `Message is undeliverable.\r\nReason: User "<addr>" is not found in the cc:Mail Directory.\r\nOriginal text follows:\r\n---------------------\r\n`;
  part 2 the complete received original.
- Optionally a copy to `postmaster@<relay host>` (the configured SMTP administrator; the
  documentation speaks of the destination post office's administrator, the peer gateway
  addresses the SMTP administrator).
- No local recipient at all and the author not in our domain: warning to the cc:Mail
  administrator: `No recipients at this domain.` / `Partial RFC 821 transaction:` /
  `---------------------------` / `   FROM:` `   TO:` `   CC:` `   BCC:` /
  `Original RFC 822 header:` / `-----------------------` / header.

### 4.2 Outbound refused by the relay → message into cc:Mail

- Triggers: RCPT refusals; any error reply except 452, no retry; connection failures after the
  configured number of retries; 452 stops sending ("Reason: Out of disk space for temp files on
  the Mail-Relay Host"). Replies not starting 1/2/3 are errors.
- An RFC 822 message is built and imported like inbound mail:
  `From: <PO admin> (cc:Mail Link to SMTP Administrator)`, `Date`, `Message-Id`,
  `To: <display><sender>` (+ `,\r\n\t<admin>` if administrator copies are on), `Subject: cc:Mail
  Link to SMTP Undeliverable Message`, `MIME-Version: 1.0`, original Content-Type; body
  `Message is undeliverable.` + `Reason: <relay reply>` lines + `Original text follows:` +
  `---------------------` + rebuilt header (Received, Date, From, Return-Receipt-To, Message-Id,
  To, Cc, Subject; **no Bcc**) + the original parts.

### 4.3 Outbound rejected before sending → cc:Mail message

- Reasons: no table entry with automatic additions off (§2.2 step 7), or the size limit (§2.1
  step 7).
- Author `<admin> at <PO> (cc:Mail Link to SMTP Administrator)`; to the original sender (+ PO
  admin if administrator copies are on); Subject `cc:Mail Link to SMTP Undeliverable Message`;
  text item `Text Item`: `Message is undeliverable.\r\n<reason>`; original items re-attached
  (max 19).

## 5. Options that change the mapping

| option | effect |
|---|---|
| gateway post office name | PO of inbound authors and non-local recipients; outbound test (§2.1) |
| hub post office name, administrator | author of undeliverable reports and warnings (§4) |
| host name (or none), domain, alias domains | host.domain (§2.2), local-domain test (§3.3) |
| relay host, SMTP administrator | outbound relay; appended to recipients ending in `@`; NDR copy (§4.1) |
| junk domains, delete or set aside | §3.2 |
| Smart Addressing, table write-protect | §2.2 step 7, §3.3 |
| administrator copies of undeliverable mail | §4 |
| POP3 client support | relaying of POP3/IMAP clients' mail; `Received: from POP3 Client` (§2.3); §3.3 step 4 |
| display name in From | §2.2 step 8 |
| return receipts out / in | §2.3, §3.2 |
| attachment format, Macintosh attachment format, domain-based encoding | §2.4 |
| retries and retry interval | §4.2 |
| outbound / inbound message size limits | §2.1 step 7, §3.4 |
| default code page out / in | §2.4; §3.4 and the code page of NDR text |
| RFC 822 header item | §3.4 |

## 6. Address translation table

- Four maps: cc:Mail name slot → SMTP address; SMTP address → name slot; PO → subdomain;
  subdomain → PO. Name slots are `<lowercase name>:NN`, NN = 00..31: up to 32 SMTP addresses
  per cc:Mail name.
- Adding: both sides trimmed and lowercased; **"Last, First" stored as "First Last"**; an SMTP
  address without `@` gets `@host.domain`; refused: a space outside quotes ("Invalid SMTP
  address"), an SMTP address that is not unique, > 32 per name, a cc:Mail name not in the
  directory.
- Text import/export: `.ADR` lines `ccname<=>smtp`, `.TXT` lines `ccname<TAB>smtp`; separator
  exactly once per line; export sorted lowercase, CRLF.
- With Smart Addressing an entry is added automatically whenever an inbound message finds a name
  match (§3.3). Besides the generated forms, `First.Last` and `First_Last` are accepted.

## 7. This server

| # | Convention (§1–§6) | `ccmail/gateway.py` |
|---|---|---|
| 1 | From local part: table lookup, else `_`→`__`, space→`_`, lowercased; other PO → `name_at_po@host.domain` (or `name@subdomain.host.domain` with a domain translation entry). POP3/IMAP agree on `_`/`__` and `_at_PO` (case kept, specials quoted). Not determined: whether a hub-local user also gets `_at_<hub>` (§2.2 step 5). | `(...)` and quotes removed, `_`→`__`, space→`_`, **case kept**, characters outside the RFC atom set removed, quoted when it has a comma; other PO → `Name_at_PO@domain`; home users without a PO. No translation table, no subdomains. |
| 2 | Display name optional, written `"Name"<addr>`. | Always `Name <addr>` (with the standard space); a bare address when the author is at the gateway. |
| 3 | Internet recipient = text before the last " at " if the PO is the gateway (or an alias PO); `<...>` taken, comment stripped; no syntax check. | Last path PO = gateway: `<...>` taken, `(...)` and quotes removed, spaces removed. Also a bare `x@y.z` with no path (routed to the home PO by the client). Alias POs not implemented. |
| 4 | cc:Mail recipients at other POs listed in To/Cc (generated addresses), no RCPT. | Same; RCPT only for gateway recipients. |
| 5 | Bcc never in headers (POP3/IMAP do write `bcc`, but they serve the owner's copy). | Never written. A client appends a tag-03 entry for every pending cc **and bcc** on the wire (session-layer.md §4.3 step 3), so To leaves out every name that also has a cc (0B / 0C) or bcc (11 / 12) entry. |
| 6 | Date with the standard offset (DST ignored). | Local time with DST. |
| 7 | Message-Id `<yymmddNNNN.AAtime_t@host.domain>`, new per send; POP3/IMAP use `<msgno@domain>`. `X-Mailer: ccMail Link to SMTP R8.10.00`; `Received: from ccMail by ...`. | Random Message-ID at the domain; `X-Mailer: ccMail Link to SMTP R8.10.00 compatible (ccmail-server)`; `Received: from ccMail by <domain> (ccmail-server)`. |
| 8 | **No priority headers** either way. POP3/IMAP always emit `Importance: normal\|low\|high` and `Priority: normal\|non-urgent\|urgent`; IMAP APPEND maps both back. | Always `Importance` + `Priority` with the POP3/IMAP values. Inbound: high / urgent or `X-Priority` 1–2 → urgent; low / non-urgent → low. |
| 9 | Receipt → `Return-Receipt-To: <from>`; inbound Return-Receipt-To → receipt. POP3/IMAP agree (`Return-receipt-to: <author>`); none writes Disposition-Notification-To. | Same: `Return-Receipt-To` when the message has a tag 0E; inbound `Return-Receipt-To` → receipt requested. No Disposition-Notification-To. |
| 10 | Text: item code page → ISO-8859-x (§2.4); 7bit or QP; no wrapping; `Content-Description: "cc:Mail Note Part"` on 7bit text. | Decoded with the message's code page; ISO-8859-1 when the text fits, else UTF-8; `Content-Description: "cc:Mail Note Part"` on every text part, so a peer re-imports it as a text item. |
| 11 | One item → single-part message; several → multipart/mixed, each text item its own part. | One text item and nothing else → single part; otherwise multipart/mixed with one text/plain part per text item (an empty text part when there is none) and the other items as attachments. |
| 12 | Files: `application/octet-stream; name="title"` base64 (or uuencode), no Content-Disposition; 7bit text files as text/plain with Content-Disposition; Mac files AppleSingle; fax as file. | Files and Mac files: the title without its date stamp as file name (untitled: `FILEn.DAT`), MIME type from the extension, base64, `Content-Disposition: attachment`. Fax with a PCX header → `FAXnn.PCX` (`image/x-pcx`); other items `ITEMn.<type>` octet-stream (file-items.md). |
| 13 | Text item > 22528 bytes is cut on read. | No cut. |
| 14 | Inbound author `Display <addr> at GATEWAY` or `<addr> at GATEWAY`, from Reply-To, Resent-From, From, Return-Path; 126 with `~`. | Same order and forms; over the limit: `<addr>`, else cut + `~`. |
| 15 | Non-local header recipients added as `addr at GATEWAY`; RCPT-only recipients → Bcc. | Non-local To / Cc kept as tag 04 / 0C ("sent") entries at the gateway; RCPT recipients delivered. |
| 16 | Recipient lookup: table, `_at_`, `_`→space, `.`→space, FLast, FAN, postmaster/root → admin; host, alias and subdomain domains. RCPT never refused; unknown users bounced after DATA. | Domain must equal the configured domain; `_at_<own PO>` stripped; postmaster / root / administrator → admin; then the name as is, `_`→space (`__`→`_`), `.`→space. No table, FLast or FAN. Unknown users get **550 at RCPT** (no NDR). |
| 17 | Subject cut to 60, RFC 1522 decoded. | Decoded, cut to 60. |
| 18 | Inbound Date: wall-clock time stored, zone ignored. | Converted to local time. |
| 19 | MIME parts → items (§3.4). | Text: the text/plain part, else text/html with tags removed; attachments → file items with DOS 8.3 names, the original names listed at the end of the text; text over 60000 chars cut with `[truncated]`. |
| 20 | Non-transformation charsets stored unconverted with the matching code page; UTF-8/7, ISO-2022 converted. | Converted to each recipient's code page (a DOS client reads its own code page only). |
| 21 | RFC 822 header as file item `RFC822.TXT` (on by default), Bcc removed. | Not implemented. |
| 22 | NDR to Errors-To / Return-Path / From; outbound relay refusal → cc:Mail message to the sender with the relay reply. | 5xx and refused recipients reported at once into the sender's mailbox (subject `cc:Mail Link to SMTP Undeliverable Message`); temporary failures retried every `retry_seconds` (3600) up to `retry_times` (72), then reported. |
| 23 | Loop: own-bounce subject + > 2 Received from the same host → dropped. | More than 30 `Received:` lines → `554 too many hops (mail loop)`. |
| 24 | Peer gateway: no EHLO, no dot-stuffing on send. | EHLO accepted; dot-unstuffing on receive; standard SMTP client (dot-stuffing) on send. |
| 25 | Over 50 recipients / 20 uuencode blocks / 80 items refused. | Not implemented. |

## 8. Open points

1. Not determined: which directory entry field is the Internet address (§1); the author PO for a
   hub-local author (§2.2 step 1); the recipient classes for header-only recipients (§3.3 step
   3); the meaning of item type 2.
2. Not determined: when the RFC 1154 `Encoding:` header is emitted (§2.3).
3. Not determined: forwarded messages (embedded headings): how they are sent.
4. Not determined: the subject of the "No recipients at this domain" warning.
5. Not determined: whether message/partial parts are ever reassembled (no reassembly was found).
6. Not determined: Japanese (code page 932) handling when it is not automatic.
