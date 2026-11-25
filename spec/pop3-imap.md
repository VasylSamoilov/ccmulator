# cc:Mail messages over POP3 and IMAP4: mapping rules

Compatibility: these rules give feature parity with the Lotus cc:Mail R8.1 POP3 and IMAP4
servers in how cc:Mail messages, names and states appear to POP3/IMAP clients. Companion to
`smtp-link.md`. Where the two reference servers differ, both renderings are given.

Neither service sends mail: outgoing mail of POP3/IMAP clients goes through the SMTP link
(`smtp-link.md`).

Options named below (with their defaults): directory lookup (on), Internet address format
(underscores; or dots), Internet domain name (DName), move deleted POP3 messages to Trash, IMAP
folder delimiter (`/`), translate spaces to underscores in folder names, folder prefix, exact
RFC822.SIZE, SMTP gateway post office name.

## 1. Address of a cc:Mail name

1. Name contains `@` (not first) with a `.` after it → used verbatim; display name dropped; the
   " at PO" (e.g. INTERNET-MAIL) is dropped.
2. Else, unless directory lookup is off — and always for names with bytes > 0x7E/0x7F — look
   the name up in the directory and read the entry's Internet address field; if it is an
   address, use it.
3. Found but no address → the name; not found or lookup off → `name + " at " + PO`. With lookup
   off the expected form is "Firstname_lastname@domain.com" (no PO), which fits only if the PO
   is empty for hub-local names: not determined, same question as `smtp-link.md` §2.2 step 5.
4. Spaces → `_` and `_` → `__`, or `.` / `..` with the dot address format.
5. Local part quoted `"..."` (escaping `\ " CR`) if it contains `\ " CR ( ) < > @ , ; : [ ]`,
   space, or a byte outside 0x20..0x7E.
6. `%s@%s` with DName.

Results: `Kit Walker` → `Kit_Walker@dom`; at another PO, not in the directory →
`Kit_Walker_at_PO2@dom`; `Last, First` → `"Last,_First"@dom`.
Header entry: ` <phrase> <addr>` (phrase = cc:Mail name, RFC 2047-encoded if 8-bit), or the bare
address; entries joined by `",\r\n   "`.

## 2. Headers (same order in both)

| Header | POP3 | IMAP |
|---|---|---|
| Date | `"%3s, %02d %3s %02d %02d:%02d:%02d %-5s"`, 4-digit year, zone `%+02.2i%02.2i` = the server's local zone incl. DST; stored local time unconverted | same |
| To / cc / bcc | header names literally `To`, `cc`, `bcc`; **bcc written** | same; Bcc written whenever bcc recipients are present |
| From, Sender, Reply-To | all three = the author | same |
| Importance | always: `normal` / `low` / `high` from priority 0/1/2 | same |
| Priority | always: `normal` / `non-urgent` / `urgent` | same |
| Return-receipt-to | `Return-receipt-to: <author address>` if the message requests a receipt | same |
| Disposition-Notification-To, Sensitivity | never | never |
| Message-Id | `<%lu@%s>` = message number, DName | `<%lu@%s>` |
| Subject | the subject cut at CR/LF, RFC 2047 if needed | same |
| MIME-Version | `1.0` | `1.0` |
| Multipart | only with ≥ 2 items: `multipart/mixed`, boundary `MIME.PART.BOUNDARY.=.<%08lx time()>`; one item → its part headers at top level | boundary `MIME.PART.BOUNDARY.=.%08lx` (message number) |

## 3. Items

All items of the message's item list are rendered, one MIME part each.

| Rule | POP3 | IMAP |
|---|---|---|
| Content-Type | type 1 → `text/plain; charset=<cs>`; every other type → `application/octet-stream` | type 1 or item named `TextItem.txt` → TEXT/PLAIN; else APPLICATION/OCTET-STREAM `name=` |
| File name | only type 3 (File): title minus trailing date/time; `; name="..."` and `Content-Disposition: attachment; filename="..."` | non-text items: title minus date/time stamp |
| Content-Id | `%lu-%u@%s` (msg number, part index, domain) | same |
| Content-Description | the item title, every titled part | not determined |
| Encoding | non-text `base64`; text per charset (7bit / QP for ISO-8859-x / base64 for Big5, EUC-KR) | non-text `base64`; text 7bit or charset descriptor; BODYSTRUCTURE `7BIT` for US-ASCII, `8BIT` otherwise |
| Fax / graphics | `application/octet-stream`, no filename | `APPLICATION/OCTET-STREAM` |
| Text charset | **converted** from the item code page (the session code page if 0) to the Internet code page: 850/437/1252 → ISO-8859-1, 866/1251 → ISO-8859-5 ...; labels ISO-8859-1..9, US-ASCII (34374), ISO-2022-JP, ISO-2022-KR/EUC-KR, Big5, GB2312, else ISO-8859-1 | **not converted** (raw item bytes); label from code page: 1252/34193 → ISO-8859-1, 1250/34194 → -2, ... 1200 → UTF-8, 932 → ISO-2022-JP, **anything else incl. 850 and 437 → US-ASCII** |
| Dot-stuffing | lone `.` lines doubled for 7bit/8bit | n/a (IMAP literal) |
| Forwarded messages | not determined | not determined |

## 4. Mailboxes and state

POP3:
- Only the Inbox is served. LIST reports the stored size, not the rendered size.
- RETR/TOP mark the message read.
- QUIT with deletions: moved to Trash if "move deleted messages to Trash" is on, else deleted.
- Login name formats: First_Last, "First Last", "Last, First", First.Last; `__` = literal `_`.

IMAP:

| cc:Mail | IMAP |
|---|---|
| Inbox | `INBOX`, `(\Noinferiors)` |
| Folders | mailboxes by name, hierarchical; delimiter by option (default `/`); a delimiter char inside a cc:Mail name shown as `.` (or `/`); spaces shown as `_` with the space option; the folder prefix stripped; names > 0x4F refused |
| Drafts, Message Log, Trash | created at login as ordinary folders |
| Outbox | not exposed |
| Bulletin boards | not exposed |
| Subscriptions | "OK All mailboxes always subscribed" |
| UIDVALIDITY / UID | folder ID / message ID |
| `\Seen` | the read state (read and STORE) |
| `\Answered \Flagged \Deleted \Draft \Recent` | in memory per session only; PERMANENTFLAGS `(\Seen)` |
| EXPUNGE | delete (no Trash) |
| COPY | the existing message added to the target folder |
| INTERNALDATE | `"%2u-%s-%u %.2u:%.2u:%.2u %c%.2u%.2u"` from the stored date/time (whether it equals the message date: not determined) |
| RFC822.SIZE | size × 1.36 + 900 unless the exact-size option is on |

## 5. IMAP APPEND (inverse mapping)

- From in DName → local part decoded (`_`→space, `__`→`_`, or dots) and looked up by name, then
  by the Internet address field; else author `phrase <addr>` (127-char limit) with PO = the SMTP
  gateway post office name.
- To/cc/bcc → To/cc/bcc recipients via the gateway.
- Date converted to local time.
- Importance low/high and Priority non-urgent/urgent → priority 1/2.
- Subject cut to 60, in the server's ANSI code page.
- text/* parts → text items with the code page from the charset; others → file items named by
  filename/name.
- The message is stored into the selected folder.

## 6. What follows for gateway.py (in addition to `smtp-link.md` §7)

What `gateway.py` does today: local address non-alnum → `.`, case kept, `@domain`; other PO
user `name%po@domain`; display name always; From only; no Bcc header; local zone incl. DST;
4-digit year; make_msgid; X-Priority + Importance (non-normal only);
Disposition-Notification-To for receipts; text converted cp850 → UTF-8; several text items
joined into one part; file items `itemN-type.bin`; inbound author `addr at INTERNET`,
Importance/X-Priority → priority, date converted to local, subject 120 chars, charset converted
to cp850.

1. Where the POP3, IMAP and SMTP link mappings agree and we differ: local part with `_` for
   space and `__` for `_` (we use `.`); other POs as `name_at_po` (we use `%`); one MIME part per
   text item; item titles as file names; Return-Receipt-To for receipts.
2. Where they disagree, pick per purpose: for mail leaving through SMTP follow the SMTP link
   (no Bcc header, From only); for a future POP3/IMAP view follow §2–§4 (Bcc shown to the
   owner, Importance + Priority, `<msgno@domain>` as a stable Message-Id).
3. The directory Internet address field (used by §1 and the SMTP link's inbound match) would map
   naturally to a per-user `internet_address` in our book.

## 7. Not determined

1. Which directory field is the Internet address of §1 (the administrator's "Address" field
   is a candidate).
2. That POP3 serves exactly the Inbox and that the read flag is Message_Seen (both inferred);
   IMAP RECENT.
3. INTERNALDATE source versus the message date.
4. Whether raw item reads return text in its stored code page (IMAP relies on raw bytes).
5. Bcc visibility for non-authors.
6. Forwarded/embedded messages. Known: only the item list of the message is rendered; there is
   no message/rfc822 output.
7. Quoting of display names with specials (the RFC 2047 writer).
8. IMAP Content-Description and single-item layout.
