#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vault_bridge.py — JSON-line IPC server for the C# frontend.
==========================================================
Reuses the proven secure_vault.py core (no crypto reimplementation).
The C# process starts it and talks over stdin/stdout with newline-delimited
JSON objects.

Protocol (one line = one JSON object):
  request:   {"id": 1, "cmd": "unlock", "params": {...}}
  response:  {"id": 1, "type": "result", "ok": true, "data": {...}}
  error:     {"id": 1, "type": "error", "error": "message"}
  progress:  {"id": 1, "type": "progress", "done": 123, "total": 456}

Commands: ping, create, unlock, lock, status, list, groups,
  add_files, add_folder, extract_file, extract_selected, extract_all,
  delete, move_group, change_password, password_strength, shutdown.

Stdio only, 100% offline. Logs/debug go to stderr only.
"""
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secure_vault import (
    Vault,
    VaultError,
    password_strength as _pw_strength,
    PAD_GRANULARITY,
    _CRYPTO_BACKEND,
    _HAS_ARGON2,
)

vault: Vault | None = None
vault_dir: str = ""


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def progress_sender(req_id):
    def cb(done, total):
        try:
            send({"id": req_id, "type": "progress",
                  "done": int(done), "total": int(total)})
        except Exception:
            pass
    return cb


def require_unlocked() -> Vault:
    if vault is None or not vault.is_unlocked:
        raise VaultError("Vault is locked. Unlock it with the password.")
    return vault


def handle(req: dict):
    global vault, vault_dir
    req_id = req.get("id")
    cmd = req.get("cmd", "")
    params = req.get("params") or {}
    if not isinstance(params, dict):
        raise VaultError("Invalid parameters.")
    cb = progress_sender(req_id)

    if cmd == "ping":
        return {"backend": _CRYPTO_BACKEND, "has_argon2": bool(_HAS_ARGON2),
                "python": sys.version.split()[0]}

    if cmd == "password_strength":
        pw = params.get("password", "")
        if not isinstance(pw, str):
            raise VaultError("Invalid password.")
        label, score = _pw_strength(pw)
        return {"label": label, "score": int(score)}

    if cmd == "create":
        path = params.get("vault_path", "")
        password = params.get("password", "")
        if not isinstance(path, str) or not path.strip():
            raise VaultError("Invalid vault path.")
        if not isinstance(password, str) or not password:
            raise VaultError("Invalid password.")
        v = Vault.create(path, password)
        vault = v
        vault_dir = os.path.abspath(path)
        return {"vault_path": vault_dir, "files": len(v.list_files())}

    if cmd == "unlock":
        path = params.get("vault_path", "")
        password = params.get("password", "")
        if not isinstance(path, str) or not path.strip():
            raise VaultError("Invalid vault path.")
        if not isinstance(password, str) or not password:
            raise VaultError("Enter the password.")
        v = Vault(path)
        v.unlock(password)
        vault = v
        vault_dir = os.path.abspath(path)
        try:
            n = len(v.list_files())
        except Exception:
            n = 0
        return {"vault_path": vault_dir, "files": n}

    if cmd == "lock":
        try:
            if vault is not None:
                vault.lock()
        finally:
            vault = None
        return {"locked": True}

    if cmd == "status":
        unlocked = bool(vault is not None and vault.is_unlocked)
        n = 0
        if unlocked:
            try:
                n = len(vault.list_files())  # type: ignore
            except Exception:
                n = 0
        return {"unlocked": unlocked, "vault_path": vault_dir, "files": n,
                "backend": _CRYPTO_BACKEND, "has_argon2": bool(_HAS_ARGON2)}

    if cmd == "list":
        v = require_unlocked()
        gf = params.get("group_filter", "") or ""
        search = params.get("search", "") or ""
        if not isinstance(gf, str) or not isinstance(search, str):
            raise VaultError("Invalid filters.")
        if gf == "__EMPTY__":
            entries = v.list_files(search=search)
            entries = [e for e in entries if not (e.get("group") or "").strip()]
        else:
            entries = v.list_files(group_filter=gf, search=search)
        return {"files": entries}

    if cmd == "groups":
        v = require_unlocked()
        return {"groups": v.groups()}

    if cmd == "add_files":
        v = require_unlocked()
        paths = params.get("paths") or []
        group = params.get("group", "") or ""
        shred = bool(params.get("shred", False))
        if not isinstance(paths, list) or not paths:
            raise VaultError("No files to import.")
        if not isinstance(group, str):
            raise VaultError("Invalid group.")
        sizes = []
        for p in paths:
            if not isinstance(p, str):
                raise VaultError("Invalid path.")
            if os.path.islink(p):
                raise VaultError(f"Symlink skipped: {os.path.basename(p)}")
            try:
                sizes.append(os.path.getsize(p))
            except (OSError, ValueError) as e:
                raise VaultError(f"Unreadable file: {os.path.basename(p)}") from e
        total = sum(s + (PAD_GRANULARITY - (s % PAD_GRANULARITY)) for s in sizes)
        total = max(total, 1)
        out = []
        done = [0]
        for p, sz in zip(paths, sizes):
            base_done = done[0]

            def _cb(d, t, _b=base_done, _tot=total):
                try:
                    cb(min(_b + d, _tot), _tot)
                except Exception:
                    pass

            try:
                e = v.add_file(p, group=group, shred_original=shred, progress_cb=_cb)
            except VaultError as ve:
                raise VaultError(f"{ve} [{os.path.basename(p)}]") from ve
            out.append(e)
            pad = PAD_GRANULARITY - (int(e.get("size", sz)) % PAD_GRANULARITY)
            done[0] = base_done + int(e.get("size", sz)) + pad
            cb(min(done[0], total), total)
        return {"added": out, "count": len(out)}

    if cmd == "add_folder":
        v = require_unlocked()
        folder = params.get("folder", "")
        group = params.get("group", "") or ""
        shred = bool(params.get("shred", False))
        if not isinstance(folder, str) or not folder.strip():
            raise VaultError("Invalid folder.")
        added = v.add_folder(folder, group=group, shred_original=shred, progress_cb=cb)
        return {"added": added, "count": len(added)}

    if cmd == "extract_file":
        v = require_unlocked()
        fid = params.get("file_id", "")
        dest = params.get("dest_path", "")
        if not isinstance(fid, str) or not isinstance(dest, str):
            raise VaultError("Invalid parameters.")
        out = v.extract_file(fid, dest, progress_cb=cb)
        return {"path": out}

    if cmd == "extract_selected":
        v = require_unlocked()
        ids = params.get("ids") or []
        dest_dir = params.get("dest_dir", "")
        if not isinstance(ids, list) or not ids:
            raise VaultError("No selection.")
        if not isinstance(dest_dir, str) or not dest_dir.strip():
            raise VaultError("Invalid destination.")
        try:
            total = sum(int(v.get_entry(i)["size"]) for i in ids)
        except (VaultError, ValueError, TypeError) as e:
            raise VaultError("Invalid entry for extraction.") from e
        total = max(total, 1)
        out = []
        done = [0]
        for i in ids:
            e = v.get_entry(i)
            d = os.path.join(os.path.abspath(dest_dir),
                             Vault.sanitize_component(e["name"]))
            d = v._unique_dest(d)
            prev = [0]

            def _cb(x, t, _done=done, _prev=prev, _tot=total):
                _done[0] += (x - _prev[0])
                _prev[0] = x
                cb(min(_done[0], _tot), _tot)

            v.extract_file(i, d, progress_cb=_cb)
            out.append(d)
        return {"paths": out, "count": len(out)}

    if cmd == "extract_all":
        v = require_unlocked()
        dest_dir = params.get("dest_dir", "")
        gf = params.get("group_filter", "") or ""
        if not isinstance(dest_dir, str) or not dest_dir.strip():
            raise VaultError("Invalid destination.")
        if gf == "__EMPTY__":
            # ungrouped only: client-side fallback via extract_selected
            entries = v.list_files()
            ids = [e["id"] for e in entries if not (e.get("group") or "").strip()]
            if not ids:
                return {"paths": [], "count": 0}
            try:
                total = sum(int(v.get_entry(i)["size"]) for i in ids)
            except (VaultError, ValueError, TypeError) as e:
                raise VaultError("Invalid entry.") from e
            total = max(total, 1)
            out = []
            done = [0]
            for i in ids:
                e = v.get_entry(i)
                d = os.path.join(os.path.abspath(dest_dir),
                                 Vault.sanitize_component(e["name"]))
                d = v._unique_dest(d)
                prev = [0]

                def _cb2(x, t, _done=done, _prev=prev, _tot=total):
                    _done[0] += (x - _prev[0])
                    _prev[0] = x
                    cb(min(_done[0], _tot), _tot)

                v.extract_file(i, d, progress_cb=_cb2)
                out.append(d)
            return {"paths": out, "count": len(out)}
        outs = v.extract_all(dest_dir, group_filter=gf, progress_cb=cb)
        return {"paths": outs, "count": len(outs)}

    if cmd == "delete":
        v = require_unlocked()
        ids = params.get("ids") or []
        if not isinstance(ids, list) or not ids:
            raise VaultError("No selection.")
        n = len(ids)
        for k, i in enumerate(ids):
            v.delete_file(i)
            cb(k + 1, n)
        return {"deleted": n}

    if cmd == "move_group":
        v = require_unlocked()
        ids = params.get("ids") or []
        ng = params.get("new_group", "") or ""
        if not isinstance(ids, list) or not ids:
            raise VaultError("No selection.")
        if not isinstance(ng, str):
            raise VaultError("Invalid group.")
        for i in ids:
            v.move_to_group(i, ng)
        return {"moved": len(ids)}

    if cmd == "change_password":
        v = require_unlocked()
        old = params.get("old_password", "")
        new = params.get("new_password", "")
        if not isinstance(old, str) or not isinstance(new, str):
            raise VaultError("Invalid passwords.")
        v.change_password(old, new)
        return {"changed": True}

    if cmd == "shutdown":
        try:
            if vault is not None:
                vault.lock()
        finally:
            pass
        send({"id": req_id, "type": "result", "ok": True, "data": {"bye": True}})
        sys.stdout.flush()
        raise SystemExit(0)

    raise VaultError(f"Unknown command: {cmd!r}.")


def main() -> int:
    log("[bridge] started, pid:", os.getpid())
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except (ValueError, json.JSONDecodeError) as e:
            try:
                send({"id": None, "type": "error", "error": "Invalid JSON request."})
            except Exception:
                pass
            log("[bridge] json error:", e)
            continue
        req_id = req.get("id")
        try:
            data = handle(req)
            send({"id": req_id, "type": "result", "ok": True, "data": data})
        except VaultError as e:
            try:
                send({"id": req_id, "type": "error", "error": str(e) or "Vault error."})
            except Exception:
                pass
        except SystemExit:
            raise
        except Exception:
            traceback.print_exc(file=sys.stderr)
            try:
                send({"id": req_id, "type": "error",
                      "error": "Unexpected error (see log)."})
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
