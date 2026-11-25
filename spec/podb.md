# cc:Mail post office database (DB 8.x): file format

Compatibility: post office files written by these rules are accepted by the Lotus cc:Mail DB 8
post office programs (the DOS Router 6.10, ADMIN, the message manager, ANALYZE, RECLAIM and the
Remote 3.40B client through the Router; §14). The same format is used by the Windows programs of
that generation.

Samples: "orig" = the test post office MYPOST as it was found; "run" = the same post office after
two more messages were delivered into it by the original post office software.
Reader, writer and checker: `ccmail/podb.py`, command line `tools/ccpodb.py` (section 11);
writer operations section 12, compatibility results section 14.

**[checked]** marks a claim that was also checked by decoding the sample files (or, where said,
files written by our writer and read by the original programs). "Not determined" marks open
points.

## 0. Overview

```
CCDATA/
  CCPODD.00    data dictionary: field/record/value definitions, list of PO files   (kind 01)
  CCPODS.00    public directory: Dir_Root, Dir_Entry, Dir_Member, ...              (kind 02)
  CCPOMBOX.00  template mailbox, copied for every new mailbox                      (kind 03, number 0)
  U<hex7>.nn   one mailbox per directory entry that has one (users, PO, bboards)   (kind 03, number n)
  CCPOMI.00    message index: Message_Index (one per stored message), free space   (kind 04)
  CCPOMS.00    message data, a stream of 504-byte units, no records                (kind 05)
  CCPODD.BK    backup copy of the dictionary; not needed to read or write the database
  CCINTL.TB    code-page and collation tables (used in sections 4 and 10)
  CCVER.TB     allowed client versions, checked at every open (section 9)
  CCNFT.LG     text error log; NFTCHECK = 512 random bytes, written and verified at every open
  TRANSIT.LOG  session log (128-byte records), not part of the database
```

Every database file is a set of 512-byte pages, each with a CRC and encrypted (section 1). The
logical byte stream (the pages without their 8-byte headers) holds variable-length records
(section 2), described by the dictionary in CCPODD (section 3). B-tree indexes over the records
live in pages of the same file (section 4). A message is stored once in CCPOMS, listed once in
CCPOMI, and pointed to by one Message_Pointer record per mailbox (sections 6–7).

## 1. Container layer [checked: every page of every sample passes its CRC]

### 1.1 File ids and names

A file id is a dword: `kind << 24 | number`.

| kind (id & 0x7F000000) | name |
|---|---|
| 0x01000000 | `CCPODD.nn` |
| 0x02000000 | `CCPODS.nn` |
| 0x03000000, number 0 | `CCPOMBOX.00` (fixed name) |
| 0x03000000, number n | `U` + n in lowercase hex, zero-padded to 7, + `.nn` |
| 0x04000000 | `CCPOMI.nn` |
| 0x05000000 | `CCPOMS.nn` |

- `.nn` is the file's generation byte as two decimal digits, or `.tmp`.
- A reader starts at the expected generation and steps through generations 0..1 for CCPODD and
  0..99 for the others. The next generation is tried when the file is missing or its File_Root
  has flag 0x200 File_Switched.
- CCPOMS is always generation 0. Message_File records in CCPOMI list CCPOMS.00..03 (record ids
  0x190..0x193); their use is not determined (only .00 exists).
- File names are case-insensitive (DOS/Windows). A reader matches them case-insensitively;
  lower-case `U000000a.00` names are accepted by the original DOS programs on a case-sensitive
  host (§14).

### 1.2 Pages

| file offset | content |
|---|---|
| 0..511 | random bytes written at creation; also the lock region (section 8) and, in owner-stamp mode, a 0x4A-byte owner stamp |
| 512..1023 | header page (section 1.4) |
| (n+2)*512 | page n, n >= 0 |

Page header (8 bytes):

| offset | content |
|---|---|
| +0 word | CRC: `~CRC16(0xFFFF, bytes 511 down to 2)` with the CRC-CCITT table (poly 0x1021, MSB first). Check: the CRC over all 512 bytes backwards = 0x1D0F. CCPOMS pages hold 0 and are never checked. |
| +2 word | page type: 1 = record data, 2 = index internal node, 6 = index leaf (a reader requires `type & wanted`). CCPOMS: 0. |
| +4 dword | data page: copy of page 0's dword +4, which is 0. Index page: the index id. CCPOMS: the Message_Number that owns the page. |
| +8..511 | 504 logical bytes |

Logical address L lives in page `L / 504`, at byte `8 + L % 504`.
Records may cross from one data page into the next page.

### 1.3 Encryption

Key state S, 96 bytes:

| bytes | content |
|---|---|
| S[0] | mode: 0 = clear, 1 = stream cipher only, 2 = FEAL then stream |
| S[1] | tag (unused) |
| S[2..91] | key material |
| S[92..95] | file offset of the current chunk |

A 66-byte key K is expanded by `setup(K)`:

```
S[0]=K[0]; S[1]=K[1]; S[2]=0; v=K[0x18]*K[0x37]
for i=88..0:  v=v*0x41C64E6D+0x3039 (32 bit); S[3+i]=v>>24
for j=0..63:  S[3+j]^=K[2+j];  S[28+j]^=K[2+j]
B=S+2; di=89; si=38; repeat 7921: B[di]+=B[si]+1; di-- (0->89); si-- (0->89)
```

Cipher, applied per 512-byte chunk with `off` = the file offset of the chunk:

- **Stream**:
  - `v=((off>>9)*0xC49D+1)&0xFFFF`
  - `s` = 45 words `S.word[1+i]^v` (90 bytes)
  - `j=((off>>16)^v)%89+1`; `k=j-51` (+89 if <=0)
  - 256 times: `s[j]+=s[k]; T[i]=s[j]; j--, k-- (0->89)`; then `last=T[255]`
  - per byte: `e=T[last]; s[j]+=s[k]; T[last]=s[j]; last=e; j--, k--; byte^=e`
- **FEAL-8** on 8-byte blocks; the subkeys are taken directly from S[2..33]:
  - 16-bit K0..K7 at S+2..S+16, the 32-bit whitening masks at S+18, S+22, S+26, S+30
  - f-function with the S-box rot-left-2
  - Reading: FEAL decrypt then stream. Writing: stream then FEAL encrypt.
- The CRC is computed over the plain page before encryption.
- Test vector for the write direction [checked]: re-encrypting the decrypted pages (stream,
  then FEAL encrypt) gives back the raw file bytes, for all CCPOMS pages, the U1/U4/U7 headers
  and pages, and the CCPODS header.

Keys [checked]:

| what | key state |
|---|---|
| header page of CCPODD, CCPODS, CCPOMI, CCPOMBOX.00 | `setup(FIXED)` with S[0]=2; FIXED = 66 bytes: `01 40 c6 54 21 e3 c6 09 78 26 42 de 6b e3 7d a2 d4 46 ec 80 61 7b 18 4f 1e c4 ec 56 1e 21 43 99 51 f0 df e0 a9 23 da 88 17 0c d5 7e c1 56 36 f8 dd 2b 0e 04 17 d4 6c 59 98 7f 98 41 33 c4 fb 64 56 dc` |
| header page of a U file | `setup(S_dd)` with S[0]=2. S_dd = the expanded data-page key state of CCPODD. |
| data pages | `setup(K_file)`, where K_file is the 66-byte key in the file's header (below) |
| CCPOMS (no header read) | S_dd copied as is, with S[0]=2 |

K_file is stored twice in the header page:
- (a) at `hdr[0x3E..0x7F]`: the copy used for kinds 1, 2, 4 and the template;
- (b) at `hdr[hdr[510]+158+i] ^ FIXED[66-i]`, i=0..65: the copy used to open U files.

In a mailbox with a password (header flags bit 0x100, section 1.4), copy (a) has bytes
`[2 .. 2+len)` XORed with the encoded password. The password check works by unmasking (a) with
a candidate password and testing the CRC of page 0 (section 10). Copy (b) stays plain; a reader
opens U files with it. Verified on every sample U file: (a) XOR (b) = `00 00 7b ad 0e 00…` =
enc_pw("123") for U1/3/4/7/8 and all zero for U2/U6 [checked]. All sample K_file have K[0]=1
(stream only) and K[1]=0x40.

### 1.4 Header page (plain text after decryption)

| offset | content |
|---|---|
| 0 | CRC word (as for pages) |
| 2..7 | 0 |
| 8 word | 0 |
| 10 word | 4 |
| 12 | mini-record: word 0xF001, word 0, dword 0, dword flags, then 6-byte fields: (0x1F Failed_Login_Count, 0), then in CCPODD (0xED Post_Code_Page=437), (0xEF Post_Language_Code="en") = the File_Descriptor (tag 0x1E: 237, 239, 31) |
| 18..21 (0x12) | flags dword (the "byte 0x13" seen in samples = bit 0x100). 0x100 = the mailbox has a password and key copy (a) is masked (set and cleared by a password change). 0x200 = mailbox locked after too many failed logins (also set by directory updates); a locked mailbox cannot be opened. Set in U1, U3, U4, U7, U8; clear elsewhere [checked]. |
| 22..27 | field (0x1F Failed_Login_Count, counter): incremented on a wrong password when Sec_Max_Login_Tries != 0, cleared on success |
| 62..127 | K_file copy (a) |
| hdr[510]+158 .. +223 | K_file copy (b), XORed with FIXED reversed |
| everything else | random fill |

File creation [checked]:
1. The whole 512 bytes at offset 0 are random, then written.
2. The key is built: K_file = the first 66 bytes of `setup(S_parent)` (setup copies
   S_parent[0..1] into K[0..1], so a `1, 0x40` stored there before is overwritten), then two
   bytes randomised (K[36], K[65]). For a mailbox S_parent = S_dd. Checked: K_file of U1, U4 and
   U8 equals `setup(S_dd)[0:66]` except bytes 36 and 65 [checked].
3. The header buffer is filled with random bytes, then word 0 at +2, dword 0 at +4, word 0 at
   +8, word 4 at +10, word 0xF001 at +12, dword 0 at +14, dword 0 (flags) at +18, word 0x1F at
   +22, dword 0 at +24; both key copies are written, the CRC is set, and the page is encrypted
   with `setup(S_parent)` mode 2 and written at 512.
4. A mailbox's pages are then copied from CCPOMBOX.00: each 512-byte chunk from 1024 on is
   decrypted with the template key (= `setup` of the template header's key copy (a), read with
   the fixed key) and encrypted with the new data key at the same offset. The CRCs stay valid.

## 2. Record layer [checked]

The logical stream holds records back to back.

**Field record** (word 0xF001):

| offset | content |
|---|---|
| +0 word | 0xF001 |
| +2 word | len = 10 + 6*n (bytes after this word, without the trailer) |
| +4 word | record tag: the dictionary tag of the record type, e.g. 0xD2 = Dir_Entry |
| +6 dword | ID_Number, unique in the file; new id = ++File_Root.ID_Count (field 2) |
| +10 dword | flags (below) |
| +14 | n fields of 6 bytes: word tag, dword value. Empty slots = tag 0 (Unused_Field), value 0. |
| +4+len | trailer word: `~CRC16(0xFFFF, record bytes from +0, forward)`, little-endian |

**Data record** (word 0xF007; 0xF00F when the field is Data_Length_Long): holds the value of a
pointer field (strings, binary).
- +2 word = data length; for strings this includes the NUL.
- The data is padded to an even length, then the same CRC trailer follows.
- The field's value is the logical offset of this record (Pointer_To_Data).
- Strings are stored in the post office code page (Post_Code_Page, 437 in the sample). The
  Comp_Unicode types hold compressed Unicode (the compression is not described here).

**Continuation.** When a record has no free slot, a field 0x28 (Extension_Field) is added. Its
value is the offset of another F001 record (tag 0x28) whose fields continue the first. Sample:
user's Dir_Entry 0x1008 → Extension_Field 0x1017, which holds Dir_Comments and
Msg_Formats_Read. admin's comment is inline: its record had a free slot. The continuation
records have their own ids (0x1017..0x1019) but are **not** in ID_INDEX (CCPODS
Index_Entry_Count 0x28 = 40 = the records without the three continuations) [checked]. A writer
that sizes records as in section 12 needs no continuations; our writer never creates them and
refuses a field that does not fit.

**Data record CRC** [checked]: over the header, the data and the pad byte: `4 + len + (len & 1)`
bytes for F007, `6 + len + (len & 1)` for F00F; all 53 string records of run CCPODS pass.

**Setting fields**: an existing field is replaced in its slot; an absent one takes the first slot
with tag 0; with none free, a continuation is made. A pointer-type field (strings, Binstr)
always gets a new data record (the old one is not freed). Strings are stored with their NUL
(strlen + 1). On a record that is not new (no bit 1), the indexes whose key fields changed are
updated at once (old entry out, new entry in), and then bit 2 is set. Bit 2 is never cleared
again except at the first commit, so it stays on disk: every folder of every sample, the
template's folders and MYPOST's Dir_Entry have it [checked].

**Flags.**
- Low byte, database level: bit 0 = deleted; bit 1 = new, not yet committed (cleared by
  commit); bit 2 = changed.
- Bits 8..31 are application flags, set through the pseudo-field 199 (which keeps the low
  byte). Their names are Value_Defn records whose "field" is the record tag (table below).
- Deleting a record sets bit 0, removes its entries from the other indexes, and adds its size to
  File_Root.Deleted_Space (field 15). ID_INDEX keeps the entry: the deleted 'mobile' 0x100a is
  still in CCPODS ID_INDEX but in no name/hash/member index. So readers must test bit 0
  themselves. Deleted space is not reused by writers; only compaction (RECLAIM) recovers it.

Application flags (from the sample dictionary):

| record | flags |
|---|---|
| File_Root (1) | 0x100 File_Reclaim, 0x200 File_Switched |
| Univ_Index (0x46) | 0x100 BTree_Index, 0x200 Primary_Index, 0x400 Bool_Var_In_Key, 0x800 Duplicate_Keys, 0x1000 Under_Construction |
| Dir_Entry (0xD2) | 0x100 Visibility_Restricted, 0x200 Remote_Status, 0x400 Forwarding_Enabled |
| Dir_Member (0x104) | 0x100 Public_Member, 0x200 Propagation_Enabled |
| Message_File (0x136) | 0x100 Msg_CRC_Enabled |
| Message_Index (0x140) | 0x100 Message_Stored, 0x200 Message_Delivered, 0x400 Message_Past_Eof, 0x800 Message_Translated, 0x1000 Message_Member |
| Mailbox_Root (0x190) | 0x100 Local_Login, 0x200 Mobile_Login, 0x400 Disable_Lost_Pswd |
| Folder_Entry (0x1B8) | 0x100 Shared_Folder, 0x200 System_Folder, 0x400 Moveable_Folder, 0x800 Last_Queue_Exists, 0x1000 Synchronize_Folder |
| Message_Pointer (0x1C2) | 0x100 Message_Seen, 0x200 Message_Dg_Seen, 0x400 Msg_Receipt_Req, 0x800 Msg_Notread_Once, 0x1000 Msg_priority_Lo, 0x2000 Msg_Priority_Hi, 0x4000 ADE_Message, 0x8000 Bboard_Message, 0x10000 Rule_Message, … 0x400000 Msg_Author_Local |

**Page 0, logical 0: File_Root** (tag 1, id 1). Fields:

| field | name |
|---|---|
| 2 | ID_Count |
| 6 | Next_Record_Offset (end of the record area: the next record goes here) |
| 7 | Next_Index_Offset (end of allocated space; always a page boundary) |
| 0x0F | Deleted_Space |
| 0x3C | Index_Root (offset of the Index_Root record) |
| 0x11 | Index_Version_Number |
| 8 | Database_Version_Number (0x80000066) |
| 9, 0x0A | File_Creation_Date / Time |
| 0x0B | File_Version_Number |
| 0x0C..0x0E | Last_Reclaim_Date / Time / Eof |

A writer re-reads fields 6, 7 and 17 after every lock (another program may have changed them).

**Allocation** [the samples agree]. There are two frontiers: R = field 6 (Next_Record_Offset),
the end of the record stream, and X = field 7 (Next_Index_Offset), the end of the last index
page. Either can be the larger: in CCPODS R=0x3898 > X=0x3330, and in run U4 R=0x27fc > X=0x2760.
The file holds `max(ceil(R/504), X/504)` pages.

A record of size n (6*fields+16, or 4+len+pad+2 for a data record) starts at position p:
- **If X > R** (index pages were added after the last data page):
  - p = R if R is inside a page and the record fits in it: `R%504 != 0` and
    `R%504 + n <= 504`;
  - otherwise p = X + `(504-14)%6` = X+4, on a fresh page.
- **Else (X <= R)**, the records are at the end of the file: p = R.
  - If `R%504 + n - 2 > 504`: when fewer than 14 bytes are left in the page, skip to the next
    page start; then, if it still crosses, add `(504 - R%504 - 14) % 6`.
  - So a record that crosses a page boundary breaks there on a field boundary.
- Then R = p + n.

The rule above is for field records (F001). Data records (F007/F00F: size `len + 6` or
`len + 8`, rounded up to even) use another rule:
- R inside a page (`R%504 != 0`): p = R, except p = X when the record does not fit in the rest
  of the page (`R%504 + n > 504`) and X > R. So a data record **may cross** into the next page.
- R on a page boundary: p = X if X > R, else R.

An index page goes at X if X >= R, else at R rounded up to a page; then X = page + 504. Either
way it is always a new page.

A field record's id is taken when it is created: `++File_Root.ID_Count`, and it is written with
flags 2 and all slots zero (tag 0 = Unused_Field). Its CRC is rewritten on every write.

Every page newly added to the page count is zeroed. It gets type 1 for a record allocation, or
6 / 2 (leaf / internal) for an index page, and dword +4 = page 0's dword +4. When a record starts
inside an existing page, the rest of that page's slot is zeroed first.

Dates are `day | month<<8 | (year-1900)<<16`; times are `sec | min<<8 | hour<<16`, the same as
on the wire.

## 3. Dictionary (CCPODD) [checked]

CCPODD holds only definition records, so the format describes itself:

| record | fields |
|---|---|
| Record_Defn (tag 0x8C) | 0x68 Tag_Number; 0x8D Data_Type; 0x8E Data_Length; 0x8F Universal_Name (string); 0x93 Record_Field (one per member, for record types) |
| Value_Defn (0xA0) | 0x68 field tag; 0xA1 value; 0x8F name. Names enumerations and flag bits. |
| Post_Office_File (0x78) | one per file: PO_File_Number (file id), PO_File_Name, PO_File_Template, Physical_Page_Size 0x200, Logical_Page_Size 0x1F8 |
| Univ_Index (0x46) | index definitions (section 4) |

Data_Type values: 1 Inherit, 2 Bool, 3 32Bit, 4 ULong, 5 Date, 6 Time, 7 ID_Number, 8 Version,
9 Record, 0xA 4Byte_Binstr, 0xB Bool_Expr, 0xC Charstr, 0xD Long_Charstr, 0xE Binstr,
0xF Long_Binstr, 0x10 Unicode, 0x11 Long_Unicode, 0x12 Comp_Unicode, 0x13 Long_Comp_Unicode.

`ccpodb.py records CCPODD.00` prints all 206 field definitions. The ones used here:

| record (tag) | fields (tag) |
|---|---|
| Dir_Root (0xC8), id 0x28 in CCPODS | Mailbox_Count 0xC9 (= the last mailbox file id, e.g. 0x3000008), Number_Local_Users 0xCB, Univ_Post_ID 0x131, Local_Post_ID_Number 0xCC, Local_Admin_ID_Number 0xCD |
| Dir_Entry (0xD2) | Dir_Name 0xD7 (string), Dir_Type 0xD8 (1 User, 2 Post, 3 Domain, 4 Bboard, 5 Mlist, 6 Group), Dir_Comments 0xD9, ccMail_Address 0xDD, Aliased_Entry_ID 0xD4, Home_Post_ID 0xD5, Mailbox_Number 0xCA (file id), Mailbox_Version 0xDC, ACL and security fields for the post office entry |
| Dir_Member (0x104) | Member_Type 0x105 (1 Home_Post, 3 Bboard, 4 Mlist, 6 Alias, 8 Manager, …), Parent_ID 4, Parent_Dir_Name 0x106, Parent_Dir_Type 0x107, Child_ID 5, Child_Dir_Name 0x108, Child_Dir_Type 0x109, Admin_Rights 0x10C |
| Mailbox_Root (0x190), id 0x28 in a U file | Mailbox_ID_Number 0x147 (= the owner's Dir_Entry id), Mailbox_Password 0x191 (Binstr), Prev_Mailbox_Password 0x192, Mbox_Pswd_Chng_Date 0x193, Call_Password 0x195, Last_Access_Date/Time 0x199/0x19A, Univ_Post_ID 0x131 |
| Mailbox_Dir_Root (0x1A4) id 0x29; Mailbox_Folder_Root (0x1AE) id 0x2A; Mailbox_Mobile_Root (0x1D6) id 0x46 | — |
| Folder_Entry (0x1B8) | Parent_ID 4, Folder_Name 0x1B9, Entry_Count 0x1BA, Number_Msgs 0x138, Size_Msgs 0x139, Number_New_Msgs 0x1BB, Size_New 0x1BC, Number/Size_Hier 0x1BD/0x1BE, Number/Size_New_Hier 0x1BF/0x1C0, Univ_Object_ID 0x1C4, Univ_Post_ID 0x131 |
| Message_Pointer (0x1C2) | Parent_ID 4 (folder id), Entry_Number 0x1C3, Message_Number 0x12E, Message_Length 0x142, Univ_Post_ID 0x131, Univ_Object_ID 0x1C4, 0x1C5..0x1CA (mobile, MAPI) |
| Msg_Index_Root (0x12C), id 0x28 in CCPOMI | Message_Count 0x12D (the last Message_Number), Univ_Post_ID, Dir_Post_ID |
| Message_File (0x136), ids 0x190.. in CCPOMI | Universal_Name 'CCPOMS.00', Next_Msg_Offset 0x137, Number_Msgs 0x138, Size_Msgs 0x139, Number/Size_Free_Space 0x13A/0x13B |
| Message_Index (0x140) | Message_Number 0x12E, PO_File_Number 0x66 (0x5000000), Message_Offset 0x141, Message_Length 0x142, Msg_Stored_Date/Time 0x145/0x146, Msg_Format_Type 0x143, Univ_Post_ID 0x131, Univ_Object_ID 0x1C4, Mailbox_ID_Number 0x147 (repeated: one per holder) |
| Free_Space (0x154) | PO_File_Number 0x66, Free_Offset 0x155, Free_Length 0x156 |
| Shared_Folder_Entry (0x15E) | bulletin-board state per board |

## 4. Indexes [checked]

Index_Root record (tag 0x3C, File_Root field 0x3C) holds repeated triples:
0x3D Index_ID_Number, 0x3E Index_Root_Node (page number, 0 = empty and no tree), 0x3F
Index_Entry_Count (real entries, not counting the sentinel).

Univ_Index (tag 0x46, record id = index id) defines each index:

| field | meaning |
|---|---|
| 0x47 | Idx_Name |
| 0x48 | Idx_Container: only records whose Parent_ID is this |
| 0x4A | Idx_Record (repeated): record tags covered |
| 0x49 | Idx_Values: a boolean expression; sparse index condition |
| 0x4B / 0x4D / 0x8D / 0x8E | per key part: field, flags (1 Ascend, 2 Case_Sens, 4 Code_Page, 8 Alt_Field, 0x10 Hash_Value), data type, length |

The index's own record flags carry Duplicate_Keys (0x800).

| file | indexes |
|---|---|
| CCPODS | ID_INDEX 3, DIRECTORY_NAME 0xA, DIRECTORY_HASH 0xE, DIRECTORY_TYPE 0xB, MAILBOX_FILE 0xC, DIRECTORY_ADDRESS 0xD, MEMBER_LIST 0x11, REFERENCE_LIST 0x12, CALL_LIST 0x13, CALL_LIST_NUMBER 0x14, UNICODE_NAME 0x10, UNIV_OBJECT 0x1C, CONTAINER 5, INDEX_INDEX 4, TRANSACTION 0x1F |
| U file | ID_INDEX 3, FOLDER_MSGS 0x1B (Parent_ID, Entry_Number), MAPI_THREAD 0x20, FOLDER 0x1D (Parent_ID, Folder_Name/16), UNIV_OBJECT 0x1C (Univ_Post_ID, Univ_Object_ID), SHADOW 0x1E, DIRECTORY_* (personal directory), CONTAINER 5, INDEX_INDEX 4, TRANSACTION 0x1F |
| CCPOMI | ID_INDEX 3, MESSAGE_NUMBER 0x15, MESSAGE_OFFSET 0x16 (PO_File_Number, Offset, Length), MESSAGE_MEMBER 0x17, FREE_OFFSET 0x18, FREE_LENGTH 0x19, SHARED_MEMBER 0x21, SHARED_FOLDER 0x1A, CONTAINER 5, INDEX_INDEX 4, TRANSACTION 0x1F |

- ID_INDEX (id 3) is the locator: record id → logical offset.
- TRANSACTION_INDEX (0x1F) takes no entries on insert. Its role is not determined; it is empty
  in all samples.

**Nodes** (page type 2 internal, 6 leaf; page dword +4 = index id):

| offset | content |
|---|---|
| +8 word | count, including the final sentinel entry |
| +10 | leaf entries: `key, dword record id, dword record offset` |
| +10 | internal entries: `key, dword child page` |

- The sentinel key is all 0xFF (strings: below); it has id 0 and offset 0xFFFFFFFF in a leaf.
- An internal key = the largest key of its child.
- First insert into an empty index (Index_Root_Node 0):
  1. Allocate a leaf page (type 6), dword +4 = index id, count 1, sentinel key, id 0, offset
     0xFFFFFFFF.
  2. Then allocate an internal page (type 2), count 1, sentinel key → leaf page.
  3. Set Index_Root_Node to the internal page.
  - So the root is always internal, and the leaf is the page before it. Matches U4 run:
    FOLDER_MSGS leaf 0x12 / root 0x13, UNIV_OBJECT leaf 0x10 / root 0x11. The template
    CCPOMBOX.00 has roots 0 for FOLDER_MSGS and UNIV_OBJECT, so the first delivery into a fresh
    mailbox takes this path.

Key bytes:
- ULong, ID and Date types: the dword, little-endian.
- Strings (classes 2..5): one byte = length | 0x80 when truncated, then the text, zero-padded
  to Data_Length bytes. A NUL counts toward the length check; with Sort_Code_Page set, the text
  is cut at a character boundary (and the 0x80 bit set).
- Normalisation, case folding and the hash: see section 10.
- Keys sort as unsigned little-endian dwords, e.g. UNIV_OBJECT leaf of U4 [checked]. The string
  comparison rule: below.

**Which records an index holds** (at commit) [checked]:
- ID_INDEX (3) takes every committed record, whatever its tag; TRANSACTION_INDEX (0x1F) takes
  none; every other index takes a record whose tag is one of its Idx_Record.
- If the index has Idx_Values, the program must give true.
- A key part whose field is absent makes the record stay out of that index, unless the part has
  flag 8 and the alternate field (0x4C Idx_Alt_Field_Number, 0x4E Alt_Data_Type) is present. A
  pointer field that is present with value 0 (or an empty data record) also counts as absent.
  Field 3 is the record id.
- Idx_Container plays no part in an insert. FOLDER_MSGS has container 0x2A but holds pointers
  whose Parent_ID is 0x2B.
- So MAILBOX_FILE has no maillist, DIRECTORY_ADDRESS and UNIV_OBJECT in CCPODS are empty (no
  user has 0xDD / 0x131), MAPI_THREAD is empty (no 0x1C9), MESSAGE_MEMBER is empty (Message_Index
  has no field 0x144). Rebuilding every index of every sample file from its records with these
  rules gives exactly the stored entries and Index_Entry_Count [checked].

**Part class**: 1 = 32-bit (ULong, ID, Date, Time, 32Bit), 2 = Charstr, 3 = Binstr,
4 = Comp_Unicode, 5 = Unicode. A hash part (flag 0x10) is class 1. The key length of a part is
4 for class 1, else Data_Length (the index key length is the sum). This mapping from Data_Type
to class is inferred; how the class is set exactly is not determined.
Every sample index has parts of types 4, 6, 7, 0xC, 0xE or 0x12 only.

**Idx_Values** [checked]: the value is an F007 record holding words; the program runs to the end
of its data on a stack of (value, valid) pairs:

| opcode | does |
|---|---|
| 0x115 + dword | push (constant, valid) |
| 0x116 + word tag | push the field's value; valid = the field is present |
| 0x117 / 0x118 | push the record tag / the record flags |
| 0x10A..0x10F | `<  <=  >  >=  ==  !=` (unsigned); 0x113 logical and, 0x114 logical or |
| 0x110 / 0x112 | bitwise and / or; valid = both valid |
| 0x101 | logical not |

A comparison or logical operator with an invalid operand gives (0, valid). The result is the
bottom of the stack. Any other opcode is an error. The sample programs are
`116 D8, 115 1, 10F` = "Dir_Type != 1" (DIRECTORY_TYPE, CCPODS and U files) and
`116 105, 115 0xB, 10E` = "Member_Type == 11" (CALL_LIST, CALL_LIST_NUMBER).

**Comparison**: the search side is the record's *value* (as fetched for the key), the other side
a stored key. Parts are compared in order; the first non-zero result decides; > 0 means the
value sorts after the key.
- Class 1: unsigned dwords.
- Strings: the key's text is `key[1 : 1 + (key[0] & 0x7F)]`. With flag 4: the collation compare
  (below) in the PO code page (class 2) or 1200 (classes 4, 5), flags `0x30` if the key is
  truncated (0x80), plus 2 if the header collation flag (below) is set. Without flag 4: memcmp
  on the shorter length; when it is equal and the key is not truncated, the longer side's
  remaining bytes decide, if any is non-zero.
- A truncated key that compares equal is compared again against the full value fetched from the
  entry's record.
- Part flag bit 1 clear (descending) negates the result.

**Collation compare**, single-byte and 1200 code pages [checked]:
- Each character becomes U (the cp → 1200 table of CCINTL.TB; 1200 takes words as they are).
- Its weight is `W[U]` from the locale table, or 4095 if U is past the table.
- The locale is chosen by the post office language and `flags & 3`.
  - The language and code page come from the CCPODD header: the field 0xED word at +30 (437)
    and the field 0xEF chars at +36 ("en"); default 437 / "EN".
  - The header collation flag is set when CCPODD header byte 19 has bit 0x10; it is 0 in the
    sample. So keys use "en" variant 0: CCINTL.TB offset 0xAAEFC, 806 bytes = 403 weights, no
    expansion or contraction tables. A–Z and a–z get the same weight; `'` (3) and `-` (4) sort
    before space (5).
- Comparing two characters: a lower weight is smaller. Equal weights where one is 4095 and the
  characters differ: the smaller U is smaller.
- When one side ends: with flag 0x10 (or 0x20) the rest of the other side is ignored, otherwise
  any non-zero byte left makes that side larger.
- Weights with bit 0x8000 (0xC000 expansion, 0xA000 contraction) and the second "fold" pass that
  follows an expansion are not described here (our writer refuses them).
- Checked: every sample index with string parts is in this order (DIRECTORY_NAME, UNICODE_NAME,
  MEMBER_LIST, REFERENCE_LIST, DIRECTORY_TYPE, FOLDER, INDEX_INDEX, CONTAINER of every file,
  CCPODD's RECORD_NAME with 0x19b entries) [checked].

**Sentinel key** (descending parts = zeros): class 1 → 0xFFFFFFFF; strings → `[L-1]` + (L-1) × c,
where c = the highest character (cp, flags 2) with flag 4, else 0xFF. Highest character: 0xFF
for 1200; else the byte 0x80..0xFF whose U has the highest weight in locale variant **2** (a U
past the table counts as 4095); 0xFE for 437/en.

Insert (at commit, for each index that covers the record's tag and whose Idx_Values condition
holds):
1. Search (with the record id when Duplicate_Keys, else without):
   - Descend from the root, taking in each node the first entry whose key is >= the value
     (binary search), or the last entry when there is none.
   - Then walk forward through the leaves (past a leaf's end to entry 0 of the next leaf) while
     the value is greater. The sentinel (id 0) stops the walk.
   - With Duplicate_Keys, also walk past equal keys whose record id is smaller. So equal keys
     are ordered by record id, and the new entry can land at entry 0 of the next leaf.
   - Without Duplicate_Keys, an equal key is an error (duplicate key).
2. Build the entry: key + id + offset.
3. Insert it into the leaf.
4. Index_Entry_Count += 1 (the 0x3F field after the 0x3D triple of this index in Index_Root,
   record rewritten).

Remove: find the entry by value and record id, take it out of its node. The entries after it
are moved down; the old bytes of the last entry stay behind the new end (they are not cleared;
needed for byte-identical pages, §14). A leaf left empty is abandoned (Deleted_Space += 512)
and its entry is removed from the parent the same way. Parent keys are not updated. Deleting a
record sets bit 0, adds `6 * slots + 16` to Deleted_Space and removes its entries from every
index except ID_INDEX.

Leaf and internal insert:
- If `entry_size * (count+1) > 502` the node is split; otherwise the entries from the insert
  position on are shifted and the new one is put in.

Split:
- Let n = the node's count and p = the insert position.
- The right part gets `1` entry if `p == n-1` (appending just before the sentinel), else
  `n/2`. The left part gets the remaining first entries.
- Where the left part goes depends on a split mode:
  - mode on (what the original post office software does, and our writer): the left part goes
    to a **new** page, allocated before the right page; a non-root old page is abandoned with
    Deleted_Space += 512. The 0x6400 Deleted_Space of the sample CCPODD (50 pages) fits this.
  - mode off and not the root: the left part stays in the old page.
- The right part always gets a new page of the same type (at Next_Index_Offset, dword +4 =
  index id).
- The new entry goes left if `p < left count`, else right at `p - left count`. The keys passed up
  are the last keys after the insert.
- In the parent, the entry that pointed to the node becomes `(left last key → left page)`
  followed by `(right last key → right page)`; that is one parent insert, which may split
  recursively.
- Root split: both halves go to new pages and the root page becomes a 2-entry internal node in
  place, so Index_Root_Node does not change.
- Depth is limited to 10.

Test vector: CCPODS ID_INDEX leaf page 5 already holds 41 entries (2+41*12=494), so the next
directory record splits it [checked].
- The new Dir_Entry's id is the largest, so p = n-1. The right part is [new, sentinel] and the
  left part keeps the 41 old entries.
- Both go to new pages. Page 5 is abandoned (Deleted_Space 0x74 → 0x274), and root page 6
  becomes 2 entries.

## 5. Directory (CCPODS) [checked]

`ccpodb.py <PO> dir` on both copies (identical):

```
    id type       name                   mailbox    flags / comments
  1001 Dir_Post   MYPOST                 U0000001
  1002 Dir_Bboard #Directory Updates     U0000002
  1005 Dir_User   admin                  U0000003    comments='admin comment'
  1008 Dir_User   user                   U0000004    comments='local user'
  100c Dir_Mlist  maillist
  1010 Dir_Bboard board                  U0000006
  1013 Dir_User   user1                  U0000007    comments='user 1'
  1015 Dir_User   user2                  U0000008    comments='user 2'
```

- Not shown: Dir_Entry 0x100a 'mobile' (flags 0x201 = deleted + Remote_Status, Mailbox_Number
  0x3000005, no U0000005 file) and its Dir_Member 0x100b (flags 1). They are deleted, although
  they are still in ID_INDEX.
- The location letter (L/P/R...) is not stored; it is derived. In directory update items
  (`Name:/Locn:/Addr:/Cmts:/Pswd:`; letters L R A P M B C, with a 'D' prefix for delete,
  directory-updates.md) the letters map to stored entries like this:

  | letter | stored as |
  |---|---|
  | L | Dir_Type 1, Home_Post = the local PO |
  | R | Dir_Type 1 + flag 0x200 Remote_Status |
  | A | Dir_Type 1 + Aliased_Entry_ID + a Member_Alias Dir_Member |
  | P | Dir_Type 2 |
  | B | 4 |
  | M | 5 |
  | C | Dir_Type 1 (default); meaning not determined |

  - A user whose Home_Post_ID is another post office is a user "at" that post office.
  - How the letter is derived for display from the stored fields is not determined.
- Mailing list "maillist" = Dir_Entry type 5 plus Dir_Member records with Member_Type 4
  (parent = list, child = member); the sample members are user and admin.
- Bulletin board = Dir_Entry type 4 with a mailbox whose Inbox has flag 0x100 Shared_Folder,
  plus Member_Bboard (3) records (parent = board, child = PO), plus a Shared_Folder_Entry in
  CCPOMI.
- Aliases = Dir_Member Member_Alias (6) / Aliased_Entry_ID.
- Every entry has a Member_Home_Post Dir_Member (parent = MYPOST 0x1001).
- admin also has Member_Manager with Admin_Rights 0x3FF (Local_Admin_ID_Number = 0x1005).
- Password storage and hashing: section 10.

## 6. Mailboxes (U files) [checked]

- A copy of CCPOMBOX.00 (section 12.2) holds Mailbox_Root (id 0x28), Mailbox_Dir_Root 0x29,
  Mailbox_Folder_Root 0x2A, eleven system folders and Mailbox_Mobile_Root 0x46.
- The folders: 0x2b Inbox, 0x2c Outbox, 0x2d Message Log, 0x2e Drafts, 0x2f Rules,
  0x30 Session Log, 0x31 Trash, 0x33 Views, 0x34 STATIONERY, 0x35 Preferences, 0x3c Folders.
  Their Parent_ID is 0x2A, except Message Log and Drafts, whose parent is 0x3C.
- User folders are Folder_Entry records under 0x3C (not determined exactly: none in the
  samples).
- A message in a folder = Message_Pointer: Parent_ID = folder id, Entry_Number = position
  (Entry_Count+1 at delivery), Message_Number → CCPOMI, flags = state (Message_Seen 0x100 =
  read).
- Folder counters (Number_New_Msgs, Size_New_Msgs, Number_New_Hier, Size_New_Hier) count only
  pointers without 0x100.
- The Hier counters are added up the parent chain until the folder root 0x2A.
- Personal directory and lists: Dir_Entry/Dir_Member records in the U file (DIRECTORY_*
  indexes with container 0x29). None in the samples.

`ccpodb.py <run> mailboxes` (only the Inbox shown; the other ten folders are empty in all files):

```
U0000001.00: owner 'MYPOST' (Mailbox_ID_Number 0x1001), password '123' (blob 7bad0e748ab52617..), header flags 0x100, last access 2026-11-24
   folder 0x2b 'Inbox' msgs=0 size=0 new=0 System_Folder Synchronize_Folder
U0000002.00: owner '#Directory Updates' (Mailbox_ID_Number 0x1002), password None (blob -), header flags 0x0, last access -
   folder 0x2b 'Inbox' msgs=0 size=0 new=0 Shared_Folder System_Folder Synchronize_Folder
U0000003.00: owner 'admin' (Mailbox_ID_Number 0x1005), password '123' (blob 7bad0e74123a5d2d..), header flags 0x100, last access -
   folder 0x2b 'Inbox' msgs=0 size=0 new=0 System_Folder Synchronize_Folder
U0000004.00: owner 'user' (Mailbox_ID_Number 0x1008), password '123' (blob 7bad0e7407fb4190..), header flags 0x100, last access 2026-11-24
   folder 0x2b 'Inbox' msgs=4 size=7056 new=0 System_Folder Synchronize_Folder
   msg #1 in 'Inbox': Message_Number 2 len 0x1f8 Message_Seen
   msg #2 in 'Inbox': Message_Number 4 len 0x1f8 Message_Seen
   msg #3 in 'Inbox': Message_Number 5 len 0xdc8 Message_Seen
   msg #4 in 'Inbox': Message_Number 6 len 0x9d8 Message_Seen
U0000006.00: owner 'board' (Mailbox_ID_Number 0x1010), password None (blob -), header flags 0x0, last access -
   folder 0x2b 'Inbox' msgs=0 size=0 new=0 Shared_Folder System_Folder Synchronize_Folder
U0000007.00: owner 'user1' (Mailbox_ID_Number 0x1013), password '123' (blob 7bad0e74a99a9979..), header flags 0x100, last access 2026-11-24
   folder 0x2b 'Inbox' msgs=2 size=1008 new=0 System_Folder Synchronize_Folder
   msg #1 in 'Inbox': Message_Number 1 len 0x1f8 Message_Seen
   msg #2 in 'Inbox': Message_Number 3 len 0x1f8 Message_Seen
U0000008.00: owner 'user2' (Mailbox_ID_Number 0x1015), password '123' (blob 7bad0e747437b5a0..), header flags 0x100, last access 2023-12-05
   folder 0x2b 'Inbox' msgs=0 size=0 new=0 System_Folder Synchronize_Folder
```

## 7. Message store (CCPOMI + CCPOMS) [checked]

- **One copy per message.** Message_Index in CCPOMI: Message_Number = ++Msg_Index_Root.
  Message_Count, Message_Offset / Message_Length in CCPOMS, and one Mailbox_ID_Number field per
  mailbox that holds a pointer to it. These fields are the reference count.
- **Removing a reference** (§12.3): the holder's Mailbox_ID_Number (327) slot is re-tagged
  Mailbox_ID_Deleted (328), same value, in place. When no 327 is left, the Message_Index record
  is deleted, its space is freed (merged with free neighbours, or given back to
  Next_Msg_Offset), and the Message_File counters are updated.
- **Space**:
  - Message_Length = `ceil((size+8)/504)*504`.
  - A Free_Space record with Free_Length >= the need is used first (FREE_LENGTH_INDEX), and
    its remainder is kept.
  - Otherwise the message goes at Message_File.Next_Msg_Offset, which advances.
  - Number_Msgs and Size_Msgs are updated.
- **CCPOMS page**: header word 0, word 0, dword Message_Number, then 504 data bytes. No CRC.
  Encryption as in section 1.3. A partly used last page is zero-filled. Pages are written in
  place at `(L/504+2)*512`.
- **Stored bytes at Message_Offset**:
  - 6-byte prefix: word = Msg_Format_Type (chosen by the writer; the same value goes into
    field 0x143; 1 in all samples), then dword = Message_Offset.
  - Then the message file exactly as on the wire (spec/session-layer.md 4) and in a client's
    stored message file (items.md §4): part 1 (header bytes [0,32) and [32,part1_len)
    transposed as two separate segments), body (items; text items transposed by themselves),
    addressing part [addr_off,total) transposed (the same segment split as on the wire).
  - Zero padding to the end of the unit.
- **Tag 0x22 in the message**:
  - If the addressing part has a TLV 0x22 (8 bytes), its two dwords are used as Univ_Post_ID
    and Univ_Object_ID for the Message_Index.
  - Otherwise a writer may append `22 08` + 8 zero bytes at the end of the header record
    (total += 10) and, after storing, fill them with (Msg_Index_Root.Univ_Post_ID, the new
    Univ_Object_ID).
    - Both forms occur: message 6 has the tag (last TLV, after 0x1D); message 5 does not
      [checked]. When the tag is expected is not determined.
    - Our writer stores the message unchanged by default (like message 5), and appends and
      fills the tag with `add_univ_tag=True` (like message 6).
  - Word 12 of the header (copies) is set to 1 if it was 0.
  - **Header dword +14 = the message's Univ_Object_ID** (tag 0x22's second dword when present,
    else the new one), written into the stored header. Every message stored by the original
    post office software in the live PO has it [checked]. A message without it is reported
    unreadable by the original check tool (ANALYZE) and deleted by compaction (RECLAIM) (§14).
- **Message_Index record**: `9 + n + n` slots for n recipients (9 fixed fields + the n
  Mailbox_ID_Number fields + n spare); flags 2 at creation. The flags 0x300 (Message_Stored |
  Message_Delivered) are set later, in a separate CCPOMI transaction, after the local deliveries
  have succeeded.
- **Space with free records**:
  - A query on FREE_LENGTH_INDEX for `PO_File_Number == 0x5000000 and Free_Length >= need`
    takes the first match.
  - When there is one, Message_Offset = its Free_Offset. If space is left, the record is updated
    to `(offset + need, length - need)`, which re-keys it in the FREE indexes. If not, it is
    deleted.
  - The Message_File counters then change: Number_Msgs + 1, Size_Msgs + need,
    Number_Free_Space − (1 if the record was deleted), Size_Free_Space − need.
  - With no match: Message_Offset = Next_Msg_Offset, Next_Msg_Offset += need, Number_Msgs + 1,
    Size_Msgs + need.
  - How Free_Space records are created and merged: §12.3.
- **Univ_Object_ID** of a new record [checked]:
  `~zlib.crc32(pack('<IIII', time, date, rec_id, file_id))`, where time and date are the
  current ones and (file_id, rec_id) is the new record (for a message, the Message_Index).
  Checked: messages 5 and 6 → 0xf2a6cb86 and 0xa437056d.

`ccpodb.py <run> messages user` (long text bodies cut here):

```
=== user / Inbox #1  Message_Number 2  CCPOMS offset 0x1f8 (prefix 1, 0x1f8)  stored 2023-11-08  holders ['0x1008']  flags Message_Seen
From: user1 / To: user / Subject: test 1 / Date: 2023-11-08 20:23:50   item 2 text: "my test message"
=== user / Inbox #2  Message_Number 4  CCPOMS offset 0x5e8 ... stored 2023-12-05
From: user2 / To: user / Subject: HP 200LX CC:mail message / Date: 2023-12-05 23:19:48
   "This is CC:MAIL test message from December 2023!\r\nLine 2\r\nLine 3\r\nend."
=== user / Inbox #3  Message_Number 5  CCPOMS offset 0x7e0 ... stored 2026-11-24
From: user / To: user / Subject: test message one / Date: 2026-11-24 22:16:46   2991-byte text, "Line 001: the quick brown fox ..." .. "END-OF-TEST-MESSAGE"
=== user / Inbox #4  Message_Number 6  CCPOMS offset 0x15a8 ... stored 2026-11-24
From: user1 / To: user / Subject: hello from user1 / Date: 2026-11-24 22:29:42   1912-byte text, "Row 01: ABC..." .. "END-OF-USER1-MESSAGE"
```

`ccpodb.py <run> messages user1`:

```
=== user1 / Inbox #1  Message_Number 1  CCPOMS offset 0x0  stored 2023-10-21  holders ['0x1013']
From: user / To: user1 / Subject: subject / Date: 2023-10-21 11:56:38   "Hellow world"
=== user1 / Inbox #2  Message_Number 3  CCPOMS offset 0x3f0  stored 2023-11-08
From: user / To: user1 / Subject: test 1 / Date: 2023-11-08 20:26:52   "test message recieved"
```

- admin and user2 have no messages; the orig copy gives messages 2 and 4 for user.
- Every message has item 1 = an empty text item (the attribute layer) and item 2 = the text,
  as in `ccmail.message.compose` (items.md §5).
- Each decoded header record passes `Message(...)`'s size checks.

## 8. Locking and coordination

- **The lock.** Each file is locked by an exclusive byte-range lock on bytes 0..511 of that
  file (on Windows: LockFileEx, exclusive, fail immediately). There are no lock files and no
  shared read lock.
- **Writer rules**:
  - Acquiring the lock is retried every 200 ms for up to 60 s (5 s in some interactive
    cases), then the change fails.
  - After locking, page 0 is re-read and any cached page is stale; if Index_Version_Number
    changed, cached index pages are stale too.
  - A commit writes the changed pages, page 0 (File_Root) last, flushes, then unlocks. Unlock
    is retried 300 × 200 ms.
  - A writer may flush and keep the lock between two steps of one change (§12.3).
- **CCPOMS** is not locked itself; it is written under the CCPOMI lock.
- **Readers** check that each CCPOMS page header dword is the expected Message_Number;
  otherwise they abort and retry. `ccpodb.py` makes the same check.
- **Delivery lock order**: recipient U file → CCPOMI (bboards only) → unlock U. The
  Message_Index/CCPOMS writes take CCPOMI by themselves. The order of a whole delivery
  transaction is not determined.
- **Owner-stamp mode** (when Post_ACL bit 0x2000 Lock_Access_Prot is set; it is off in MYPOST,
  Post_ACL 0x2d): after locking, a 0x4A-byte stamp beginning "la" is written in plain text at
  offset 0.
- **NFTCHECK**: every open writes 512 random bytes under the lock, reads them back and
  compares; a mismatch fails the open.
- **CCNFT.LG**: append-only text log, one line per event:
  `/D=yy/mm/d hh:mm:ss /S=Err|Warn /E=<name> /U= /A= /V= /F= /O= /P= /R= /T=Y|N`.
  The event names include None, Read, ReadCRC, Write, Verify, VerifyCRC, Lock, Unlock, …
  All sample lines are `Warn NAP2`.
- **CCPODOWN** present → every open fails. This is the shutdown notice; content
  `<minutes> [hh mm][ p]`.
- Interop note: on Linux, fcntl locks are not seen by Windows LockFileEx through
  Samba/DOSBox. The way to share a live post office with the original programs is not
  determined; it depends on the deployment.

## 9. Version stamps

- **CCVER.TB** (INI-like: VERSION/VERSIONS, PROGRAM(S), PLATFORM(S)) is checked at every open.
  A missing file is accepted.
  - Entries are `VERSIONn=type,platform,program,v1..v6`: type 0 = minimum, 1 = excluded,
    2 = allowed; platform 127 and program 1023 mean "all".
  - An opener is identified by platform, program and version; for example platform 3
    (Win32), program 102 (Medb), version 8.0.0.2.1.10.
  - A writer leaves the file alone.
- **Database_Version_Number** 0x80000066 is in every File_Root. Copy it unchanged. Whether any
  reader checks it is not determined.

## 10. Passwords and key normalisation [checked]

**Encoding.** Let `KS` = the stream of section 1.3 with key state `setup(FIXED)`, at offset 0,
and `norm(pw)` = the normalisation below in the PO code page, after translation from the client
code page (`strlen + 1 > 64` is refused).

Normalisation, single-byte path:
- U = cp → 1200 table[b]. If U < 403 (the size of the 806-byte table at CCINTL.TB header
  0x14/0x18, CCINTL.TB offset 0xAA83A), V = fold[U] and the byte becomes the 1200 → cp encoding
  of V (direct byte below 0x100, else a binary search of the pairs, '?' if absent). The byte is
  replaced only if that is not '?' or V is '?'.
- The fold table lower-cases A–Z, U+00C0..00DE and Latin Extended-A (limits.md §2).
- So **passwords are stored lower-case and compare case-insensitively** (limits.md agrees).
- The hash normalisation is the same, except that a U ≥ 403 keeps the byte itself as V. Our
  writer's password "Secret1" is stored "secret1", and the key-unmask login check accepts
  "SECRET1" [checked, our files].

```
Mailbox_Password (0x191, 64-byte F007) = (norm(pw) + NUL + random fill to 64) XOR KS[0:64]
enc_pw(pw) = norm(pw) XOR KS[0:len]      (no NUL); masks header key copy (a) bytes 2..
```

- `7b ad 0e 74` = "123\0" XOR KS[0:4]; the rest is the random fill.
- `ccpodb.py mailboxes` decodes "123" for MYPOST, admin, user, user1 and user2 [checked].
- The Mailbox_Password field is not what the login checks.

**Login**:
1. Find the user by name (follow Aliased_Entry_ID 0xD4) and read Mailbox_Number and
   Mailbox_Version (= the file's generation byte).
2. Read header key copy (a) and unmask it with each candidate: `K[2+i] ^= enc_pw(pw)[i]`.
3. `setup(K)` and test the CRC of page 0. A good CRC means the password is right; otherwise
   the login is refused.
4. Wrong password: header Failed_Login_Count += 1; at Sec_Max_Login_Tries set header flag 0x200
   (locked).
5. Right password: clear the counter, set Last_Access_Date/Time, then check Sec_Pswd_Expiration
   against Mbox_Pswd_Chng_Date (password expired) and Sec_Min_Pswd_Length (password too
   short).
   - Sample policy (MYPOST Dir_Entry): Sec_Max_Login_Tries 3, Sec_Min_Pswd_Length 1,
     Sec_Pswd_Expiration 0.

**Changing a password**:
1. Header flags: clear 0x200 (locked), set 0x100 if there is a new password, else clear it.
2. With an old password, unmask copy (a): `K[2+i] ^= enc_pw(old)[i]`. Check that
   `setup(copy a)` equals the open key (else the old password is wrong).
3. Mask it with the new one: `K[2+j] ^= enc_pw(new)[j]`, j < strlen.
4. With an old password, move the old 0x191 to 0x192 (Prev_Mailbox_Password).
5. Write the new 0x191: a new 64-byte F007 as above, or 0 when the password is cleared. Set
   0x193 Mbox_Pswd_Chng_Date = today, commit, and rewrite the header (CRC, encrypted with
   setup(S_dd) mode 2 for a U file).
6. For a post office mailbox (owner Dir_Type 2) a further step follows; not determined.

A new mailbox has no old password, so steps 2 and 4 are skipped (§12.2).

Call_Password (0x195) is not set in the samples. Its format is not determined.

**Index keys** (every key of CCPODS indexes 0xA, 0xE, 0xB, 0xC, 0x11, 0x12, 0x10 and U4 indexes
0x1D, 0x1B, 0x1C rebuilt from the records with these rules matches the stored key [checked]):

| key type | bytes (L = Data_Length) |
|---|---|
| ULong / ID / Date / Time | 4-byte little-endian |
| Charstr (stored case kept) | `n = len(value incl. NUL)`; if `n == L` and the last byte is NUL, `n -= 1`. If `n < L`: `[n] + value[:n] + zeros to L`. Else `[(L-1) \| 0x80] + value[:L-1]` (cut at a character boundary when flag 4). |
| Unicode (UTF-16LE) | the same with 2-byte units, `m = L if L odd else L-1` |
| Hash (flag 0x10, DIRECTORY_HASH_INDEX) | `zlib.crc32(lower(name)+b'\0') ^ 0xFFFFFFFF` (standard CRC-32 table, case fold by the hash normalisation) |
| alternate field (flag 8) | if the Unicode field is absent, Dir_Name as UTF-16LE (UNICODE_NAME_INDEX) |

Sentinel keys: strings `[L-1]` + (L-1)×0xFE (the highest character, CP437) with flag 4, else
0xFF; ULong 0xFFFFFFFF.

Comparison:
- Dwords compare unsigned.
- Strings with flag 4 use the collation compare with the CCINTL.TB weights, which is
  case-insensitive (observed order `#Directory Updates, admin, board, maillist, MYPOST, user,
  user1, user2`); otherwise memcmp.
- A truncated (0x80) key compares as a prefix, then the full value is fetched from the record.
- Flag bit 1 clear means descending.

Sparse indexes: Idx_Values is a bytecode program; the opcodes are in §4. For example
DIRECTORY_TYPE_INDEX holds only Post/Bboard/Mlist entries (`Dir_Type != 1`), not users.

The full comparison, the collation compare, the sentinel and the insert walk are in §4.

## 11. Implementation and consistency rules: ccmail/podb.py, tools/ccpodb.py

`ccmail/podb.py` holds the reader, the writer (§12) and a checker. `tools/ccpodb.py` is the
command line. Reading never writes to PO_DIR. Writing happens only with `--write`; without it,
the change is computed in memory and reported.

```
python3 tools/ccpodb.py PO_DIR dir
python3 tools/ccpodb.py PO_DIR mailboxes
python3 tools/ccpodb.py PO_DIR messages USER [--out DIR]   # text; --out writes ccmail .msg files
python3 tools/ccpodb.py PO_DIR records FILE                # every live record of one file, named
python3 tools/ccpodb.py PO_DIR check                       # every check of podb.verify
python3 tools/ccpodb.py PO_DIR deliver --from A --to B [--to C] --subject S --text T [--univ-tag] [--write]
python3 tools/ccpodb.py PO_DIR adduser NAME PASSWORD [--comments C] [--write]
python3 tools/ccpodb.py PO_DIR markread USER MESSAGE_NUMBER [--write]
python3 tools/ccpodb.py PO_DIR delete USER MESSAGE_NUMBER [--pointer ID] [--write]
python3 tools/ccpodb.py PO_DIR purge USER [--folder ID] [--write]
```

A consistent post office satisfies (`check`, `podb.verify`):
- page CRCs, and the page count against File_Root;
- the CRC of every F001 record in the record stream and of every string/binary data record it
  points to; no record left flagged new;
- every index equals a rebuild from the records with the §4 rules: entries, keys,
  Index_Entry_Count, the order by the §4 comparison, page types, index id in the page header,
  internal keys = the last key of each child, the sentinel in the last leaf;
- folder counters equal a recount of the pointers (Hier counters up to 0x2A), Entry_Count, the
  holders of each Message_Index against the pointers (Message_Copied pointers counted once per
  mailbox), Message_File Number/Size_Msgs, no overlapping CCPOMS spans, Mailbox_ID_Number =
  owner, Mailbox_Count, and every message readable, with header dword +14 = its
  Univ_Object_ID;
- free space (§12.3): Free_Space count and sum against Message_File, Size_Msgs +
  Size_Free_Space = Next_Msg_Offset, no overlaps, no adjacent or trailing free block;
- no live Message_Index without a 327, no deleted one with a 327.

States that files written by the original post office software can be in, and that a reader
must accept:
- an internal key above its child's last key (after removals; parents are not updated);
- a pointer Message_Length below the Message_Index length (the message total instead of the
  unit length);
- Message_Index records without flags 0x300, with holders but no pointers (cause not
  determined; an interrupted store is one guess). `verify` skips them.

Both samples pass with no finding.

Reading: open CCPODD with the fixed key, CCPODS and CCPOMI the same way, and U files with the
key derived from CCPODD; decrypt every page and check its CRC; walk ID_INDEX to find the live
records (deleted ones skipped) and follow Extension_Field continuations; name fields and flags
from the dictionary; decode Mailbox_Password (section 10); go Message_Pointer → Message_Index →
CCPOMS units (checking the page owner) → untranspose the segments → `ccmail.message.Message`.

## 12. Writer operations

Common to every change of a file F (section 8):
1. lock F
2. re-read page 0
3. make the changes
4. update File_Root
5. write the changed pages: plain bytes, then CRC, then encrypt with the file key at
   offset (n+2)*512; page 0 last
6. unlock

Changing a record means rewriting its bytes and its CRC trailer. A new record is allocated per
section 2 and flagged 2 until it is committed. On commit, clear bit 1 and insert the record into
every index that covers its tag; Index_Entry_Count++ for each.

Notation: **R** = seen changed in the cumulative orig→run diff (two deliveries to user by the
original post office software, plus logins). **C** = not observed in the samples.

### 12.1 Deliver a new message to a local mailbox

0. Before storing: word 12 (copies) 0 → 1; tag 0x22 read or appended (§7). The recipients'
   Dir_Entries are read from CCPODS without a lock.
1. **CCPOMI, under its lock** (space first, then the count):
   1. Allocate CCPOMS space (details in §7): need = `ceil((total+8)/504)*504` with total =
      dword 0 of the message file. Use a Free_Space record if one fits (shrink or delete it);
      else take Message_File(0x190).Next_Msg_Offset and advance it by need. Number_Msgs += 1;
      Size_Msgs += need (or minus the free space taken). R: Next_Msg_Offset 0x7e0 → 0x1f80,
      Number_Msgs 4 → 6, Size_Msgs = Next_Msg_Offset.
   2. Msg_Index_Root.Message_Count += 1; that value is the new Message_Number. R: 4 → 6.
   3. Create Message_Index (tag 0x140), new id = ++File_Root.ID_Count, `9 + 2n` slots, flags 2.
      Fields: Message_Number, PO_File_Number 0x5000000, Message_Offset, Message_Length = need,
      Msg_Stored_Date/Time = now, Msg_Format_Type 1, Univ_Post_ID and Univ_Object_ID (from tag
      0x22, or the PO's id and a new section-7 value), then one Mailbox_ID_Number (327) per
      recipient's Dir_Entry id, so every holder is listed at creation. R: ids 0x1007 and 0x1008
      at 0x2610 and 0x2662, each with Mailbox_ID_Number 0x1008 and one Unused slot.
   4. Commit: insert into ID_INDEX, MESSAGE_NUMBER_INDEX (key = Message_Number) and
      MESSAGE_OFFSET_INDEX (key = 0x5000000, offset, length). MESSAGE_MEMBER_INDEX gets
      nothing (its Idx_Values condition is not met — R: count stays 0).
      R: Index_Entry_Count 3: 0x18→0x1a, 0x15: 4→6, 0x16: 4→6.
2. **CCPOMS**, written after the CCPOMI transaction has committed the space (no lock of its
   own). Readers find the space reserved, and pages not yet written fail the owner check
   (section 8). Then the per-recipient deliveries:
   - write `01 00` + dword offset + the message file (segments transposed) + zeros, into
     504-byte units at the offset;
   - each page gets the header (0, 0, Message_Number), is encrypted with S_dd mode 2, and is
     written at `(unit+2)*512`. R: pages 4..15 of run CCPOMS.
3. **Recipient U file, under its lock**:
   1. Find the mailbox from the recipient's Dir_Entry Mailbox_Number.
   2. Folder: the Inbox 0x2b, or the folder named by a tag 0x1B in the message (not
      implemented; our writer always uses the Inbox). Counters (each change adds only a
      non-zero delta):
      - Entry_Count 0x1BA += 1 (the new Entry_Number), Number_Msgs 0x138 += 1,
        Size_Msgs 0x139 += need;
      - not Message_Seen: Number_New 0x1BB += 1, Size_New 0x1BC += need;
      - Number_Hier 0x1BD += 1, Size_Hier 0x1BE += need, and when not Seen, Number_New_Hier
        0x1BF / Size_New_Hier 0x1C0 likewise;
      - the folder record is committed; then the Hier counters are repeated on the parent
        while Parent_ID is neither 0 nor 0x2A.
      R: Inbox 2→4 messages, size 0x3f0 → 0x1b90.
   3. Create Message_Pointer (tag 0x1C2), new id = ++ID_Count, with 10 spare slots. Fields:
      Parent_ID = folder, Entry_Number, Message_Number, Message_Length = need, flags,
      Univ_Post_ID, Univ_Object_ID = the message's. R: ids 0x1003 and 0x1004 at 0x2764 and
      0x27b0, each with 4 Unused slots.
   4. Flags:
      - recipient entry type byte == 3 (3 is the To tag in session-layer.md) and a receipt
        requested → 0x400 Msg_Receipt_Req (where the request comes from is not determined)
      - priority 1 → 0x1000 Msg_priority_Lo; >= 2 → 0x2000 Msg_Priority_Hi
      - kind 1 → 0x4000 ADE_Message; 2 → 0x8000 Bboard_Message
      - the names come from Value_Defn; the sources of priority and kind are not determined
      - **Author rule** — Message_Seen 0x100 when the author is the recipient, per recipient:
        - only when the message has no tag 0x32 (decimal 50); with one, Seen
          (`dword +4 & 0x100` of the tag data) and the folder (dword +12, else a lookup by the
          dwords +16/+20) are taken from it, and the author rule is skipped;
        - author = the last 02 item, else the first 01 item, searched from offset 32 of the
          header record; "Administrator" never matches; the item's length byte must equal the
          Dir_Name length (stored bytes with the NUL, '#' first for types 4/5); then the names
          are compared with the collation compare in the PO code page, flags 4, +2 when a
          collation flag is set (which setting sets it is not determined; flag 4 is not used
          on the single-byte / 1200 path), and again with the two halves of a `Last\0First`
          name swapped;
        - and the recipient is local: Home_Post_ID (213) is the local PO, no record flag 0x200
          (pseudo-field 199), no Aliased_Entry_ID (212), Dir_Type is not 2;
        - effect: flags |= 0x100, flags &= ~0x400; the New counters then stay;
        - without this rule the author is later sent its own copy (§14);
        - when the delivery comes from a mobile-protocol client at level ≥ 200 the pointer
          also gets field 454; that is session state, a writer has nothing to set.
      - A pointer also becomes Seen when the message is downloaded in a client session:
        R: both pointers are 0x100; message 5 (user → user) is the author rule, message 6
        (user1 → user) was marked on download [checked; U4 pointers 0x1006/0x1007 went
        0 → 0x100 during user's call, §14].
   5. Commit: ID_INDEX, FOLDER_MSGS_INDEX (key Parent_ID, Entry_Number), UNIV_OBJECT_INDEX
      (key Univ_Post_ID, Univ_Object_ID). R: Index_Entry_Count 3: 0x24→0x26, 0x1b: 2→4,
      0x1c: 0xd→0xf.
4. **Bulletin board** (Dir_Type 4): also update its Shared_Folder_Entry in CCPOMI (fields 442,
   353, 312, 443, 444, 313). C; our writer refuses bulletin boards.
5. **CCPOMI again**: after all local deliveries, Message_Index flags |= 0x300, under the CCPOMI
   lock.
6. Also seen in R but not part of the delivery: Mailbox_Root Last_Access_Date/Time (login), and
   user1's Mailbox_Root flag 0x100 Local_Login.

`podb.Writer.deliver` does steps 0–5 in this order, one transaction per file (CCPOMI, CCPOMS
without a lock, each U file, CCPOMI). Its pointers get the caller's flags (default 0, new and
unread), plus the author rule. A message with tag 0x32 is refused (not implemented). Two
deliveries into a copy of orig (message 5 user → user, message 6 then marked read) give the
same changed record kinds, fields and index counts as orig→run in CCPOMI, CCPOMS and U4 (the
Mailbox_Root login fields excluded), with the same field order and slot use in Message_Index and
Message_Pointer, and the same offsets (message 5 at 0x7e0).

### 12.2 Add a local user

1. **CCPODS, under its lock** (held to the end of step 4):
   1. Dir_Root.Number_Local_Users += 1 for a local user (Dir_Type 1, home = the local PO, not
      remote, not an alias).
   2. Create Dir_Entry (tag 0xD2) with 6 slots for a user (7 for a bboard, 3 for a list, 20
      for a post office). Fields in this order: Dir_Name 215 (string with its NUL), Dir_Type
      216 = 1, Home_Post_ID_Number 213 = the local PO entry (0x1001), then optionally
      Aliased_Entry_ID 212, Dir_Comments 217 (strlen+1), ccMail_Address 221, and flag 0x200 for
      a remote entry. With comments, a user's 6 slots are full after Mailbox_Number and
      Mailbox_Version: no continuation is needed.
2. **Create the mailbox**:
   1. New file id = Dir_Root.Mailbox_Count + 1, under the CCPODS lock (100+1 if the count was
      0). Write it back. Mailbox_Count holds the whole file id (0x3000008 → 0x3000009).
   2. Create `U%07x.00`: offset 0 = random, header per section 1.4 with a new K_file derived
      from S_dd. The hex digits are lower case: `U000000a.00` for mailbox 10. DOS and Windows
      ignore the case.
   3. Copy every page of CCPOMBOX.00 from offset 1024: decrypt with the template key, encrypt
      with the new key. The CRCs stay valid.
   4. Under the new file's lock:
      - File_Root.File_Creation_Date/Time = now;
      - Mailbox_Root (0x28).Univ_Post_ID = Dir_Root's.
3. **Fill the mailbox** (under the U file's lock):
   - File_Root fields 9/10 = today/now again, committed;
   - Mailbox_Root fields 305 Univ_Post_ID (the post office's) and 327 Mailbox_ID_Number (0x147)
     = the Dir_Entry id, committed;
   - every Folder_Entry found by the query `Parent_ID == 0x2A` on FOLDER_INDEX (0x1D; in index
     order, i.e. by collated name) gets field 452 Univ_Object_ID = the §7 function over (U file
     id, its own id), then field 305 Univ_Post_ID, then a commit. Each set re-keys
     UNIV_OBJECT_INDEX, which is empty in the template: the first one creates its leaf and root
     (§4).
   - The time and date in the folders' Univ_Object_ID are the plain 3-byte values. Checked:
     U8's Inbox 0xb1a75708 = the function with time 0x0b332c, date 0x7b0a15, rec 0x2b, file
     0x3000008 [checked]. A writer stores 0 in the top byte of File_Creation_Time; U8's
     0xa00b332c has a non-zero top byte, so U8 was made by other software.
   - for a bboard, Inbox (0x2b) flag |= 0x100.
   - U8 and U4 have Drafts (0x2e) under 0x3C, while the template has it under 0x2A. Adding a
     user does not move it; other software did. Our writer leaves the template's parents.
   - Password, per the change-password steps (section 10, steps 2 and 4 skipped): mask header
     key copy (a) with enc_pw, set header flag 0x100, rewrite the header page (CRC, encrypt with
     setup(S_dd) mode 2), and write Mailbox_Password (0x191) + Mbox_Pswd_Chng_Date (0x193).
     A login can be checked either by decoding 0x191 or by the key unmask (section 10).
4. **Back in CCPODS:**
   1. Dir_Entry.Mailbox_Number = the file id and Mailbox_Version = 0.
   2. Commit, inserting into these indexes (keys per section 10):
      - ID_INDEX
      - DIRECTORY_NAME (name, L=12)
      - DIRECTORY_HASH (crc32 of the lower-cased name)
      - MAILBOX_FILE (Mailbox_Number)
      - UNICODE_NAME (L=17, Dir_Name as UTF-16LE through the alternate field)
      - not DIRECTORY_TYPE for a user (sparse; the samples hold only Post/Bboard/Mlist)
      - DIRECTORY_ADDRESS and UNIV_OBJECT only when those fields exist (none of the sample
        users has them).
   3. Then Dir_Member Member_Home_Post (tag 0x104, 8 slots). It is created only if MEMBER_LIST
      has no such entry yet. Fields in order: 261 Member_Type 1, 264 Child_Dir_Name, 5
      Child_ID, 265 Child_Dir_Type, 262 Parent_Dir_Name, 4 Parent_ID, 263 Parent_Dir_Type.
      Names of types 4/5 lose a leading '#'.
   4. Commit: ID_INDEX, MEMBER_LIST (Parent_ID, Member_Type, Child_Dir_Name),
      REFERENCE_LIST (Child_ID, Member_Type, Parent_Dir_Name).
   5. A further step on the name (address/Unicode uniqueness). Effect not determined; it writes
      nothing visible in the sample entries.
5. In the samples the comments are in an Extension_Field continuation record (the 6 slots
   were full). One Dir_Entry with enough slots is equivalent for readers (section 2).

Rules on names and passwords:
- a name that exists or collates equal is refused;
- names of more than 126 bytes and comments of more than 126 bytes are refused (limits.md §1);
- a name with a comma is stored as `Last\0First` (not implemented by our writer, which refuses
  it);
- passwords of 64 bytes or more are refused.

`podb.Writer.add_user` does 1–4 in this order and then sets the password (§10). It skips step
4.5. On the sample it splits CCPODS ID_INDEX as in the §4 test vector. Adding 42 users to orig
(several leaf splits in every directory index, mailbox `U000000a.00` onwards) passes `verify`.
Its output has not been compared byte for byte with a user added by the original administration
program.

### 12.3 Delete a message from a mailbox; free space

A message is deleted per mailbox: one Message_Pointer goes. The stored message goes only when
the last mailbox lets go of it. A folder purge is one delete per pointer of the folder, in
FOLDER_MSGS order (index 27 query by Parent_ID).

Test vector [checked]: message 8 in the post office of a post-office-to-post-office test
(router-to-router.md) was deleted by the original software: pointer 0x1001 in `U0000009.00` (OURPO) went from flags 0 to 1 while
still in the Inbox, and Message_Index 0x100a has flags 0x301 and Mailbox_ID_Deleted 0x101a.

**Mailbox side** (owner Dir_Entry id, pointer record id):
1. Mailbox = the owner's Mailbox_Number (202). Lock the U file.
2. Read from the pointer: Parent_ID 4 (folder), Entry_Number 451, Message_Number 302,
   Message_Length 322, flags 199, Univ_Post_ID 305, Univ_Object_ID 452, Global_Msg_ID 455.
3. If the pointer has flag bit 0 (already deleted), unlock and return.
4. Bulletin boards (Dir_Type 4) with Message_Propagated (0x200000) get a special case: the
   folder's Entry_Count 442 += 1, and a Shadow record (tag 0x1EA) is made with fields 4, 451,
   455, 305, 452 and 491 Delete_Number = the new Entry_Count, plus Seen when Msg_Author_Local.
   Not implemented: our writer refuses bulletin boards.
5. **Delete the pointer** (§2):
   - flags |= 1;
   - File_Root.Deleted_Space += 6 × slots + 16;
   - its entries leave FOLDER_MSGS, UNIV_OBJECT and MAPI_THREAD; ID_INDEX keeps it.
6. **Folder counters** (size, seen = flags & 0x100):
   - On the folder: Number_Msgs −1, Size_Msgs −size, and when not seen Number_New −1,
     Size_New −size.
   - Number_Hier −1, Size_Hier −size, and when not seen Number_New_Hier −1, Size_New_Hier
     −size.
   - The folder is committed. Then the same Hier counters are applied to the parent while
     Parent_ID ≠ 0x2A.
   - Every value is written as computed; nothing is clamped.
   - **Entry_Count (442) is not changed**, so Entry_Numbers are not reused.
7. **Message_Copied (0x100000)**: a query on UNIV_OBJECT (index 28 of the mailbox) for (305,
   452). Its filter is a §4 Idx_Values program: `117, 115 450, 10E, 116 302, 115 n, 10E, 113` =
   "record tag == Message_Pointer and Message_Number == n".
   - If another such pointer exists (with a non-zero Message_Number), the mailbox keeps its
     reference.
   - If exactly one is left, that pointer loses 0x100000.
   - So all Message_Copied pointers of one message in one mailbox share one Mailbox_ID_Number.
8. Commit the U file.
9. If the reference is to be dropped (or the folder is a Shared_Folder): lock CCPOMI and run the
   CCPOMI side for (Message_Number, owner); for a Shared_Folder, update the bboard's
   Shared_Folder_Entry records (not implemented); commit CCPOMI. So the order is U file first,
   then CCPOMI, as two transactions.

**CCPOMI side** (Message_Number, holder) [checked]:
1. Lock CCPOMI. Find the Message_Index by Message_Number (MESSAGE_NUMBER_INDEX).
2. Walk its 327 fields. The first one whose value is the holder is rewritten **in place** as
   `328 Mailbox_ID_Deleted, holder` (a raw 6-byte slot write, no index change). Not found is an
   error.
   - No CCPOMI index keys on 327. MESSAGE_MEMBER is (4, 0x144) and is empty.
3. If another 327 is left, the record is committed (no index change) and that is all.
4. Otherwise:
   1. Read PO_File_Number 102, Message_Length 322 and Message_Offset 321 (325/326 too when
      statistics are kept).
   2. Delete the Message_Index: flags |= 1, Deleted_Space += 6 × slots + 16, out of
      MESSAGE_NUMBER and MESSAGE_OFFSET; ID_INDEX keeps it.
   3. Flush with the lock kept.
   4. Then free the space (below) for (file, length, offset).
   - With Message_Translated (0x800), the CCPOMI records that a 3-part query finds through
     (305, 452) are then deleted. Which index the query uses is not determined. Not
     implemented: our writer refuses such a message.
5. Commit CCPOMI. Statistics counters (fields 1293..1300) are not kept on disk.
- **CCPOMS is not touched**: the freed pages keep their data and the old Message_Number in
  the page header.
- A delete of a message that has no 327 left (for example after a failed delivery) skips
  step 2.

**Free space** (file, length, offset). The indexes used: MESSAGE_NUMBER 0x15, FREE_OFFSET 0x18
(PO_File_Number, Free_Offset, Free_Length), FREE_LENGTH 0x19.
1. **Successor**: query FREE_OFFSET with (file == file, Free_Offset == offset + length).
2. **Predecessor**:
   - with a successor, the entry just before it in FREE_OFFSET order (verified byte for byte
     against the original message manager's merges, §14);
   - without one, the last entry with (file == file, Free_Offset < offset).
   - It counts only if `Free_Offset + Free_Length == offset`.
3. merged = [pred.offset or offset, length + succ.len + pred.len).
4. Message_File 0x190 is read: Number_Free_Space 314, Size_Free_Space 315, Next_Msg_Offset 311,
   Size_Msgs 313, Number_Msgs 312. If merged.offset > Next_Msg_Offset, it is an error.
5. Then one of three cases:
   - **merged end == Next_Msg_Offset**: Next_Msg_Offset −= merged length, Size_Free_Space −=
     merged length, and both merged neighbours are deleted.
   - **a neighbour merged**: the predecessor (else the successor) gets Free_Length,
     Free_Offset = the merged span (which re-keys both FREE indexes). The other neighbour, if
     both merged, is deleted.
   - **none**: a new Free_Space (tag 340, 3 slots, fields in this order Free_Length 342,
     Free_Offset 341, PO_File_Number 102 = the constant 0x5000000), then committed.
     Number_Free_Space += 1.
6. Number_Free_Space −= the number of neighbours to delete.
7. Message_File gets: Number_Free_Space, Size_Free_Space + length, Next_Msg_Offset, Size_Msgs −
   length, Number_Msgs − 1.
8. Then the neighbours are deleted (34 bytes of Deleted_Space each): predecessor first, then
   successor.

Consequences (checked by `verify`, §11):
- Size_Msgs + Size_Free_Space = Next_Msg_Offset.
- The Free_Space records and the messages tile the store without overlap.
- No two free blocks are adjacent, and none ends at Next_Msg_Offset.
- Number_Free_Space and Size_Free_Space match the records.

The next delivery takes space as in §7: the first FREE_LENGTH entry that is long enough is
shrunk from the front or deleted.

**Index entry removal** [checked]: the entries after the removed one are moved down; the old
bytes of the last entry stay behind the new end (§4). A leaf left empty is abandoned (§4).

**Our writer** (`Writer.delete_message(user, number | pointer_id)`, `purge_folder(user,
folder)`; command line `delete` / `purge`) does mailbox-side steps 3, 5–9 and the CCPOMI side
and free space as above, one U transaction and then one CCPOMI transaction per pointer.
- It refuses bulletin boards (Dir_Type 4), Shared_Folder folders and Message_Translated
  messages.
- With several pointers to the same message in one mailbox, the pointer id must be given.
- It never sets Message_Copied itself; the rule is implemented for mailboxes where a client
  did.

**Not implemented or not determined**:
- the bboard Shadow record and Shared_Folder_Entry updates;
- the Message_Translated cleanup;
- compaction of CCPOMS and of the Deleted_Space;
- whether the predecessor query's `file ==` condition also bounds the walk (all Free_Space
  records are 0x5000000, so it makes no difference).

### 12.4 Mark a message read

Derived from the folder counter rule (§6); how the clients themselves mark a message read is
not determined. Our writer (`markread`), in the U file under its lock:
- a pointer that already has 0x100 is left alone;
- the Message_Pointer gets flag 0x100 Message_Seen;
- with size = the pointer's Message_Length (0x142), its folder gets Number_New 0x1BB −1,
  Size_New 0x1BC −size, Number_New_Hier 0x1BF −1, Size_New_Hier 0x1C0 −size;
- Number_New_Hier −1 and Size_New_Hier −size are repeated on each parent while Parent_ID is
  neither 0 nor 0x2A.

## 13. Not determined (summary)

- Collation weights with expansions/contractions and the second (fold) pass of the collation
  compare; locales other than "en" variant 0 (the "en" tables have none; a locale that has them
  would test it).
- Call_Password (0x195).
- The sources of the Message_Pointer flag values (receipt, priority, kind); folder routing by
  tag 0x1B.
- When a stored message is expected to carry tag 0x22.
- How the index part class is set from Data_Type (the mapping of §4 is inferred).
- Delete: the bboard Shadow record and Shared_Folder_Entry updates; the Message_Translated
  cleanup (index of its query); what a delete that skips the 327 retag cleans up; what
  Message_Index records with flags 0, holders and no pointers are (seen in an ADE test post
  office) and what removes them; when a pointer Message_Length is the message total instead of
  the unit length (ADE notices).
- Compaction rules (RECLAIM): it moves messages and deletes "unreadable" ones, leaving
  Size_Msgs + Size_Free_Space < Next_Msg_Offset.
- The address / Unicode name uniqueness step at add-user (12.2 step 4.5).
- What makes Drafts move under Folders (0x3C) in U4/U8.
- The further step after a password change of a post office mailbox.
- The role of CCPOMS.01..03 and how PO_File_Number low bits select them.
- TRANSACTION_INDEX use.
- Location letter C; how the letters L/R/P are derived for display.
- Files written by the original DOS programs other than those in §14 are not cross-checked
  against this description.
- How a writer coexists with live Windows/DOS programs (lock visibility): a deployment test.
- Our writer's files with the Windows programs (the DOS programs accept them, §14).
- The collation flag that adds +2 to the author name comparison (our writer uses the header
  collation flag, 0 in every sample).
- Tag 0x32: Seen and folder from the tag (our writer refuses such messages).

## 14. Verified compatible

Unit tests: `python3 -m unittest tests.test_podb -v`, 22 tests (6 for delete), cover the
checker, delivery (first-insert path, leaf and root splits, free space reuse), mark read, dry
run, locking, add user (ID_INDEX split, 42 users, passwords) and the author rule; all pass.
70 deliveries to one user split leaves of ID_INDEX, FOLDER_MSGS and UNIV_OBJECT; a stress run
(not in the suite) of 1500 deliveries gives depth-3 trees (root splits) in FOLDER_MSGS,
UNIV_OBJECT and CCPOMI MESSAGE_OFFSET, 1538 ID_INDEX entries in U4; `verify` passes.

Files written by `ccmail/podb.py` were used with the original DOS programs, writing only while
those were stopped, on a backed-up copy of the post office; `check` passed after every step.
Verified compatible with:
- **Lotus cc:Mail Router 6.10.00.4 (DOS)**: opens the lower-case `U000000a.00` /
  `U000000b.00` on a case-sensitive host; finds users we added (login, delivery of an upload
  into our U file); accepts the right password on a mailbox whose password only our writer set
  (typed upper case, stored lower case); refuses a wrong password on our user after the
  administration program changed it; sends our messages (with and without tag 0x22) to the client;
  continues our CCPOMI numbering, space, ids and indexes; stores a new message into a hole our
  delete left (taking and deleting our Free_Space record); does not send a message we deleted;
  marks our pointers Seen (0 → 0x100) when the client downloads them, and the Inbox
  Number_New drops to 0 (§12.1 step 3.4; U4 pointers 0x1006/0x1007 during user's call).
- **Lotus cc:Mail Remote 3.40B** (through the Router): receives and displays our messages. With
  the author rule (§12.1 step 3.4) an author does not receive its own copy; without it, it did.
- **ADMIN (DOS)**: lists the user we added in name order with Loc L and its comment; the message
  count matches Number_Msgs; changing the password of our user works and our reader decodes the
  new one (Prev_Mailbox_Password added).
- **Message manager 8.00.02.14 (MSGMGR)**: its deletes of two messages, and of two more next to
  free blocks (both neighbours merged), give byte-identical decrypted pages in CCPOMI.00 and the
  U file to the same deletes by our writer (two deletes: Deleted_Space +82 in CCPOMI, +76 per
  pointer; the second pair leaves one Free_Space [0, 0x7e0)).
- **ANALYZE 8.00.02.14**: full check (`/DI`) of a post office changed only by our writer
  (deliveries, deletes with every free-space case, a shared message kept): exit status 0, no
  finding. Messages stored without header dword +14 (§7) are reported "Message cannot be
  read"; with it they are not.
- **RECLAIM**: compaction of that post office: exit status 0, and `verify` passes afterwards.
- `verify` passes on post offices written only by the original programs (with the relaxations
  of §11).

Not tested:
1. Windows programs.
2. Concurrent access with the original programs on the same files (§8).
3. Other ADMIN functions over our files (rename, delete a user we added).
4. Longer messages and attachments stored by our writer (only one-line text messages were used
   with the original programs).
5. A wrong password refused on a mailbox whose password only our writer set.
6. Not implemented: bulletin-board delivery and delete (Shared_Folder_Entry, Shadow records),
   Message_Translated cleanup, Extension_Field continuations, comma names in add_user, locales
   with expansions, NFTCHECK/CCNFT.LG writes, tag 0x32 and tag 0x1B folder routing; CCPODOWN is
   honoured (refused).
