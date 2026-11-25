# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Address book administration on po.json: users and other post offices.

Every change also queues a directory update (spec/directory-updates.md) for the client users, so
their own copy of the directory follows: the changed entry only, as ADE sends changes.
Record forms the client applies (§3):
    add     Name + Locn L|P + Addr [+ Cmts]     not found -> added
    change  Name + Locn + Addr + Cmts           found -> comments/address set
    rename  Name old + Chng new + Locn + Addr   found -> renamed; already renamed -> still found
    delete  Name + Locn DL|DP                   not found -> "No changes made"
The client refuses a delete of its owner's own entry (error 4), so a deleted user is not sent one.
"""
import datetime
import os

from . import ade, directory, limits


class AdminError(Exception):
    pass


def _ade_rec(po, canon):
    """A user as an ADE record for the other post offices (ade.py): Locn L, Addr = us."""
    e = _entry(po, canon)
    return {"name": canon, "locn": "L", "letter": "L", "addr": po.name, "cmts": e.get("cmts", "")}


def _ade(po, records):
    """Queue the change as an ADE update to every partner post office configured for ADE."""
    return ade.queue_update(po, records)


def _check_name(po, name, kind, rename_of=None):
    name = name.strip()
    if not name:
        raise AdminError("empty name")
    if len(name) > limits.NAME_MAX:
        raise AdminError(f"name longer than {limits.NAME_MAX} characters")
    if "\0" in name or " at " in name.lower() or "@" in name:
        raise AdminError("a name cannot contain ' at ' or '@' (those are addresses)")
    if name.lower() == po.name.lower():
        raise AdminError("that is this post office's own name")
    learned = ade.lookup(po, name)
    other = po.user(name) or po.post_office(name) or (learned and learned["name"])
    if other and (rename_of is None or other.lower() != rename_of.lower()):
        # one directory: the client refuses a second entry with the same name (error 5)
        raise AdminError(f"{other} is already in the directory")
    return name


def _check_password(pw):
    if not pw or len(pw.encode("cp850", "replace")) > limits.PASSWORD_MAX:
        raise AdminError(f"password must be 1..{limits.PASSWORD_MAX} characters")
    if "\0" in pw:
        raise AdminError("password cannot contain NUL")


def _entry(po, canon):
    cfg = po._cfg["users"][canon]
    e = {"name": canon, "kind": "L", "addr": po.name}
    if isinstance(cfg, dict) and cfg.get("comments"):
        e["cmts"] = cfg["comments"]
    return e


def _queue(po, entries, skip=(), full_for=()):
    """Queue one update message per user: `entries` for everyone, the whole directory for the
    users in full_for (a new user). Returns [(user, id)]."""
    out = []
    if not entries and not full_for:
        return out
    for canon, _ in sorted(po.users.values()):
        if canon in skip:
            continue
        send = directory.directory_entries(po) if canon in full_for else entries
        if not send:
            continue
        msg = directory.update_message(po.name, canon, send, cp=po.user_codepage(canon))
        out.append((canon, po.deposit(canon, msg)))
    return out


# ----- users -----

def add_user(po, name, password, comments=None, codepage=None, notify=True):
    name = _check_name(po, name, "L")
    _check_password(password)
    if comments and len(comments) > limits.NAME_MAX:
        raise AdminError(f"comments longer than {limits.NAME_MAX} characters")

    def change(cfg):
        entry = {"password": password}
        if comments:
            entry["comments"] = comments
        if codepage:
            entry["codepage"] = codepage
        cfg["users"][name] = entry if len(entry) > 1 else password
    po.update(change)
    if notify:
        _ade(po, [_ade_rec(po, name)])
    return _queue(po, [_entry(po, name)], skip=(), full_for=(name,)) if notify else []


def set_user(po, name, comments=None, codepage=None, notify=True, email=None):
    """email: the user's own internet address (gateway From/envelope sender and inbound
    matching); "" removes it. Other keys of the entry (fetch, smtp, ...) are kept."""
    canon = po.user(name)
    if not canon:
        raise AdminError(f"unknown user {name}")
    if comments is not None and len(comments) > limits.NAME_MAX:
        raise AdminError(f"comments longer than {limits.NAME_MAX} characters")
    if email:
        from .gateway import is_internet
        email = email.strip()
        if not is_internet(email):
            raise AdminError(f"{email} is not an internet address (name@domain)")
        for ocanon, _ in po.users.values():
            e = po._cfg["users"][ocanon]
            if ocanon != canon and isinstance(e, dict) and str(e.get("email", "")).strip().lower() == email.lower():
                raise AdminError(f"{ocanon} already has the address {email}")

    def change(cfg):
        entry = cfg["users"][canon]
        if not isinstance(entry, dict):
            entry = {"password": entry}
        if comments is not None:
            if comments:
                entry["comments"] = comments
            else:
                entry.pop("comments", None)
        if codepage is not None:
            if codepage:
                entry["codepage"] = codepage
            else:
                entry.pop("codepage", None)
        if email is not None:
            if email:
                entry["email"] = email
            else:
                entry.pop("email", None)
        cfg["users"][canon] = entry if len(entry) > 1 else entry["password"]
    po.update(change)
    # the client sets Cmts only when the line is non-empty, so a cleared comment stays there
    if notify and comments is not None:
        _ade(po, [_ade_rec(po, canon)])          # for a peer post office Cmts: replaces, even with empty text
    return _queue(po, [_entry(po, canon)]) if notify and comments else []


def set_password(po, name, password):
    canon = po.user(name)
    if not canon:
        raise AdminError(f"unknown user {name}")
    _check_password(password)
    po._set_password(canon, password)


def _state_paths(po, canon):
    """Per-user state on disk: (description, path) for what exists."""
    out = []
    for label, path in (("waiting mail", os.path.join(po.root, "mail", canon)),
                        ("delivered mail", os.path.join(po.root, "delivered", canon)),
                        ("interactive-mode state (folders, drafts)", os.path.join(po.root, "vim", canon)),
                        ("fetch state", os.path.join(po.root, "fetch", canon + ".json"))):
        if os.path.exists(path):
            out.append((label, path))
    return out


def user_state(po, name):
    """What deleting this user removes, as readable lines (no passwords)."""
    canon = po.user(name)
    if not canon:
        raise AdminError(f"unknown user {name}")
    entry = po._cfg["users"][canon]
    entry = entry if isinstance(entry, dict) else {}
    lines = []
    n = len(po.pending(canon))
    if n:
        lines.append(f"{n} message(s) waiting for delivery")
    for label, path in _state_paths(po, canon):
        if label != "waiting mail":
            lines.append(f"{label}: {os.path.relpath(path, po.root)}")
    if entry.get("email"):
        lines.append(f"email address {entry['email']}")
    for key, what in (("fetch", "fetch account"), ("smtp", "outgoing SMTP account")):
        acc = entry.get(key)
        if isinstance(acc, dict):
            lines.append(f"{what} {acc.get('user', '')}@{acc.get('host', '')} "
                         f"({acc.get('protocol', acc.get('security', ''))}), settings removed")
    aliases = [k for k, v in ((po._cfg.get("gateway") or {}).get("aliases") or {}).items()
               if str(v).strip().lower() == canon.lower()]
    if aliases:
        lines.append("gateway aliases removed: " + ", ".join(sorted(aliases)))
    if po.failed_attempts(canon):
        lines.append(f"{po.failed_attempts(canon)} failed login attempt(s) recorded")
    return canon, lines


def delete_user(po, name, force=False, notify=True):
    """Remove the user from po.json (with its fetch/smtp settings and the aliases pointing to it)
    and move its files (waiting and delivered mail, interactive state, fetch state) into
    deleted/<user>-<time>/, so nothing is destroyed. force = also with mail waiting."""
    canon = po.user(name)
    if not canon:
        raise AdminError(f"unknown user {name}")
    waiting = po.pending(canon)
    if waiting and not force:
        raise AdminError(f"{canon} has {len(waiting)} message(s) waiting; use --force to delete anyway")

    def change(cfg):
        del cfg["users"][canon]
        cfg.get("failed_attempts", {}).pop(canon, None)
        aliases = (cfg.get("gateway") or {}).get("aliases")
        if isinstance(aliases, dict):
            for k in [k for k, v in aliases.items() if str(v).strip().lower() == canon.lower()]:
                del aliases[k]
    po.update(change)
    paths = _state_paths(po, canon)
    if paths:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        dst_root = os.path.join(po.root, "deleted", f"{canon}-{stamp}")
        os.makedirs(dst_root, exist_ok=True)
        for label, path in paths:
            if path.endswith(".json"):
                os.replace(path, os.path.join(dst_root, "fetch.json"))
                lock = path + ".lock"
                if os.path.exists(lock):
                    os.remove(lock)
            else:
                os.replace(path, os.path.join(dst_root, os.path.basename(os.path.dirname(path))))
    if notify:
        # the peer post office needs Addr on a delete: without it the record is "other" (Recv_Other)
        _ade(po, [{"name": canon, "locn": "L", "letter": "L", "delete": True, "addr": po.name}])
    return _queue(po, [{"name": canon, "kind": "L", "delete": True}]) if notify else []


def rename_user(po, old, new, notify=True):
    canon = po.user(old)
    if not canon:
        raise AdminError(f"unknown user {old}")
    new = _check_name(po, new, "L", rename_of=canon)

    def change(cfg):
        cfg["users"] = {(new if u == canon else u): v for u, v in cfg["users"].items()}
        fails = cfg.get("failed_attempts", {})
        if canon in fails:
            fails[new] = fails.pop(canon)
        aliases = (cfg.get("gateway") or {}).get("aliases") or {}
        for k, v in aliases.items():                    # gateway aliases follow the user
            if str(v).strip().lower() == canon.lower():
                aliases[k] = new
    po.update(change)
    for top in ("mail", "delivered"):
        src, dst = os.path.join(po.root, top, canon), os.path.join(po.root, top, new)
        if os.path.isdir(src) and not os.path.exists(dst):
            os.replace(src, dst)
    # the fetch state moves too, or the renamed user's whole account would be fetched again
    from .fetch import Fetcher
    fetcher = Fetcher(po, getattr(po, "gateway", None))
    src, dst = fetcher.state_path(canon), fetcher.state_path(new)
    if os.path.exists(src) and not os.path.exists(dst):
        os.replace(src, dst)
    rec = dict(_entry(po, new), name=canon, chng=new)
    if notify:
        _ade(po, [dict(_ade_rec(po, new), name=canon, chng=new)])   # the peer reads Chng: in an update
    return _queue(po, [rec]) if notify else []


def list_users(po):
    po.refresh()
    out = []
    for canon, _ in sorted(po.users.values()):
        cfg = po._cfg["users"][canon]
        cfg = cfg if isinstance(cfg, dict) else {}
        out.append((canon, cfg.get("comments", ""), cfg.get("codepage", ""), len(po.pending(canon)),
                    po.is_locked(canon)))
    return out


# ----- other post offices (spec/router-to-router.md) -----

def add_post_office(po, name, password, call_password=None, connect=None, mode=None, notify=True):
    name = _check_name(po, name, "P")
    if not password:
        raise AdminError("password (what that post office sends us) is required")

    def change(cfg):
        entry = {"password": password}
        if call_password:
            entry["call_password"] = call_password
        if connect:
            entry["connect"] = connect
        if mode:
            entry["mode"] = mode
        cfg.setdefault("post_offices", {})[name] = entry
    po.update(change)
    if notify:
        _ade(po, [{"name": name, "locn": "P", "letter": "P"}])    # sent only with Send_Other
    return _queue(po, [{"name": name, "kind": "P", "addr": po.name}]) if notify else []


def set_post_office(po, name, **fields):
    canon = po.post_office(name)
    if not canon:
        raise AdminError(f"unknown post office {name}")

    def change(cfg):
        entry = cfg["post_offices"][canon]
        for k, v in fields.items():
            if v is None:
                continue
            if v:
                entry[k] = v
            else:
                entry.pop(k, None)
    po.update(change)


def delete_post_office(po, name, force=False, notify=True):
    canon = po.post_office(name)
    if not canon:
        raise AdminError(f"unknown post office {name}")
    waiting = po.routed(canon)
    if waiting and not force:
        raise AdminError(f"{len(waiting)} message(s) wait for {canon}; use --force to delete anyway")

    def change(cfg):
        del cfg["post_offices"][canon]
    po.update(change)
    if notify:
        _ade(po, [{"name": canon, "locn": "P", "letter": "P", "delete": True}])
    return _queue(po, [{"name": canon, "kind": "P", "delete": True}]) if notify else []


def list_post_offices(po):
    po.refresh()
    return [(n, c.get("connect", ""), c.get("mode", ""), len(po.routed(n)))
            for n, c in sorted(po._cfg.get("post_offices", {}).items())]
