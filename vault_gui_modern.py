#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vault — modern GUI (CustomTkinter).
=========================================
Modern frontend for the proven backend in `secure_vault.py`.

- No crypto reimplementation: imports Vault/VaultError and reuses everything
  (AES-256-GCM, Argon2id/scrypt, shredding, atomic manifest, selftest).
- Only the UI is new: dark, rounded, sidebar + cards, guided dialogs.

Run:  python vault_gui_modern.py
Needs: customtkinter + pycryptodomex (+ argon2-cffi recommended)
"""

import gc
import os
import queue
import threading
import time
import traceback

import customtkinter as ctk
from tkinter import filedialog, messagebox

from secure_vault import (
    Vault,
    VaultError,
    password_strength,
    format_size,
    PAD_GRANULARITY,
    FILE_ID_RE,
    _CRYPTO_BACKEND,
    _HAS_ARGON2,
)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

APP_TITLE = "Vault"
AUTOLOCK_SECONDS = 10 * 60

ACCENT = "#3b8ed0"
ACCENT_HOVER = "#2f7ab8"
CARD_BG = "#24262d"
CARD_SELECTED = "#2e4a62"
SIDEBAR_BG = "#1b1d21"
DANGER = "#c0392b"
MUTED = "#9aa0a8"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def short_date(iso: str) -> str:
    try:
        return (iso or "")[:16].replace("T", " ")
    except Exception:
        return iso or ""


def safe_msg(e: BaseException) -> str:
    if isinstance(e, VaultError):
        try:
            return str(e) or "Vault error."
        except Exception:
            return "Vault error."
    try:
        traceback.print_exc()
    except Exception:
        pass
    return "Unexpected error (see log). No sensitive data shown."


# ---------------------------------------------------------------------------
# Modal dialogs
# ---------------------------------------------------------------------------
def ask_group_dialog(parent, title="Group", initial="", groups=()) -> str | None:
    """Returns the chosen group, or None when cancelled."""
    dlg = ctk.CTkToplevel(parent)
    dlg.title(title)
    dlg.geometry("440x340")
    dlg.transient(parent)
    dlg.grab_set()
    result: dict = {"value": None}

    ctk.CTkLabel(dlg, text=title, font=ctk.CTkFont(size=17, weight="bold")).pack(pady=(18, 4))
    ctk.CTkLabel(dlg, text="Label to organize your files (e.g. Documents, Photos).",
                 text_color=MUTED, wraplength=380).pack(pady=(0, 10))

    entry = ctk.CTkEntry(dlg, placeholder_text="Group name (empty = no group)")
    entry.pack(fill="x", padx=24, pady=4)
    entry.insert(0, initial or "")
    entry.focus_set()

    if groups:
        ctk.CTkLabel(dlg, text="Existing groups (click to use):",
                     text_color=MUTED, font=ctk.CTkFont(size=12)).pack(pady=(10, 2))
        box = ctk.CTkScrollableFrame(dlg, height=90, fg_color="transparent")
        box.pack(fill="x", padx=24, pady=2)
        for g in groups[:20]:
            ctk.CTkButton(box, text=g, anchor="w", fg_color="transparent",
                          text_color=("gray10", "gray85"), hover_color=("gray70", "#333"),
                          command=lambda v=g: (entry.delete(0, "end"), entry.insert(0, v))
                          ).pack(fill="x", pady=1)

    btns = ctk.CTkFrame(dlg, fg_color="transparent")
    btns.pack(fill="x", padx=24, pady=14)
    ctk.CTkButton(btns, text="Cancel", fg_color="transparent", border_width=1,
                  command=lambda: (result.update(value=None), dlg.destroy())).pack(side="right", padx=(8, 0))
    ctk.CTkButton(btns, text="Confirm", fg_color=ACCENT, hover_color=ACCENT_HOVER,
                  command=lambda: (result.update(value=entry.get().strip()), dlg.destroy())).pack(side="right")
    dlg.bind("<Return>", lambda _e: (result.update(value=entry.get().strip()), dlg.destroy()))
    dlg.bind("<Escape>", lambda _e: (result.update(value=None), dlg.destroy()))
    parent.wait_window(dlg)
    return result["value"]


def ask_shred_dialog(parent) -> bool | None:
    """True=destroy originals, False=keep them, None=cancel."""
    dlg = ctk.CTkToplevel(parent)
    dlg.title("Original files")
    dlg.geometry("460x250")
    dlg.transient(parent)
    dlg.grab_set()
    result: dict = {"value": None}

    ctk.CTkLabel(dlg, text="What should happen to the originals?", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(18, 6))
    ctk.CTkLabel(dlg, text="The files were copied INTO the vault in encrypted form.\n"
                           "The plaintext originals stay on disk unless you destroy them with secure shredding.",
                 text_color=MUTED, justify="center", wraplength=400).pack(pady=(0, 14))
    row = ctk.CTkFrame(dlg, fg_color="transparent")
    row.pack(fill="x", padx=20, pady=4)
    ctk.CTkButton(row, text="No, keep them", fg_color="transparent", border_width=1,
                  command=lambda: (result.update(value=False), dlg.destroy())).pack(side="left", expand=True, padx=4)
    ctk.CTkButton(row, text="Yes, destroy them", fg_color=DANGER, hover_color="#a93226",
                  command=lambda: (result.update(value=True), dlg.destroy())).pack(side="left", expand=True, padx=4)
    ctk.CTkButton(dlg, text="Cancel import", fg_color="transparent", text_color=MUTED,
                  command=lambda: dlg.destroy()).pack(pady=6)
    dlg.bind("<Escape>", lambda _e: dlg.destroy())
    parent.wait_window(dlg)
    return result["value"]


def ask_password_change_dialog(parent) -> tuple[str, str] | None:
    dlg = ctk.CTkToplevel(parent)
    dlg.title("Change password")
    dlg.geometry("440x420")
    dlg.transient(parent)
    dlg.grab_set()
    result: dict = {"value": None}

    ctk.CTkLabel(dlg, text="Change password", font=ctk.CTkFont(size=17, weight="bold")).pack(pady=(18, 4))
    ctk.CTkLabel(dlg, text="Only the master key is re-wrapped: fast, files are not re-encrypted.",
                 text_color=MUTED, wraplength=380).pack(pady=(0, 10))

    e_old = ctk.CTkEntry(dlg, show="•", placeholder_text="Old password")
    e_old.pack(fill="x", padx=24, pady=4)
    e_new = ctk.CTkEntry(dlg, show="•", placeholder_text="New password (12+ characters recommended)")
    e_new.pack(fill="x", padx=24, pady=4)
    e_rep = ctk.CTkEntry(dlg, show="•", placeholder_text="Repeat new password")
    e_rep.pack(fill="x", padx=24, pady=4)
    lbl = ctk.CTkLabel(dlg, text="", text_color=MUTED)
    lbl.pack(pady=(6, 0))
    bar = ctk.CTkProgressBar(dlg, width=380)
    bar.pack(pady=6)
    bar.set(0)

    def on_type(*_):
        lab, score = password_strength(e_new.get())
        lbl.configure(text=f"Strength: {lab} ({score}/100)")
        bar.set(max(0, min(1, score / 100.0)))

    for w in (e_new,):
        try:
            w._entry.configure(show="•")
        except Exception:
            pass
    # trace semplice via key release
    e_new.bind("<KeyRelease>", on_type)
    e_old.focus_set()

    def ok():
        o, n, r = e_old.get(), e_new.get(), e_rep.get()
        if not o or not n:
            messagebox.showwarning("Warning", "Fill in the old and new passwords.", parent=dlg)
            return
        if n != r:
            messagebox.showerror("Error", "The two new passwords do not match.", parent=dlg)
            return
        _lab, score = password_strength(n)
        if score < 30 and not messagebox.askyesno("Weak password",
                                                  f"Strength: {_lab}. Proceed anyway?", parent=dlg):
            return
        result["value"] = (o, n)
        dlg.destroy()

    row = ctk.CTkFrame(dlg, fg_color="transparent")
    row.pack(fill="x", padx=24, pady=14)
    ctk.CTkButton(row, text="Cancel", fg_color="transparent", border_width=1,
                  command=dlg.destroy).pack(side="right", padx=(8, 0))
    ctk.CTkButton(row, text="Change", fg_color=ACCENT, hover_color=ACCENT_HOVER, command=ok).pack(side="right")
    dlg.bind("<Return>", lambda _e: ok())
    dlg.bind("<Escape>", lambda _e: dlg.destroy())
    parent.wait_window(dlg)
    return result["value"]


def confirm_delete_dialog(parent, n: int, preview: str) -> bool:
    dlg = ctk.CTkToplevel(parent)
    dlg.title("Delete permanently")
    dlg.geometry("460x300")
    dlg.transient(parent)
    dlg.grab_set()
    result = {"value": False}
    ctk.CTkLabel(dlg, text=f"Delete {n} files?", font=ctk.CTkFont(size=17, weight="bold")).pack(pady=(18, 6))
    ctk.CTkLabel(dlg, text="The encrypted blobs will be overwritten (shredded) and deleted.\nThis is IRREVERSIBLE.",
                 text_color=MUTED, justify="center", wraplength=400).pack(pady=(0, 8))
    ctk.CTkLabel(dlg, text=preview[:400], text_color=MUTED, wraplength=400,
                 font=ctk.CTkFont(size=12)).pack(pady=(0, 10))
    row = ctk.CTkFrame(dlg, fg_color="transparent")
    row.pack(fill="x", padx=24, pady=10)
    ctk.CTkButton(row, text="Cancel", fg_color="transparent", border_width=1,
                  command=dlg.destroy).pack(side="right", padx=(8, 0))
    ctk.CTkButton(row, text="Delete", fg_color=DANGER, hover_color="#a93226",
                  command=lambda: (result.update(value=True), dlg.destroy())).pack(side="right")
    dlg.bind("<Escape>", lambda _e: dlg.destroy())
    parent.wait_window(dlg)
    return bool(result["value"])


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
class ModernVaultApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title(APP_TITLE + " — Encrypted Database")
        self.root.geometry("1120x720")
        self.root.minsize(940, 600)

        self.vault: Vault | None = None
        self.vault_dir = ""
        self.entries: list[dict] = []
        self.all_groups: list[str] = []
        self.group_filter = ""          # "" = all
        self.search_text = ""
        self.sort_mode = "Name A→Z"
        self.selected: set[str] = set()
        self.last_group = ""
        self.row_widgets: dict[str, ctk.CTkFrame] = {}

        self._last_activity = time.time()
        self._jobs: queue.Queue = queue.Queue()
        self._progress_q: queue.Queue = queue.Queue()
        self._busy = 0
        self._busy_lock = threading.Lock()
        self._poll_scheduled = False

        self._build_login()
        self._build_main()
        self.show_login()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(1000, self._tick_autolock)

    # ================= login =================
    def _build_login(self):
        self.frame_login = ctk.CTkFrame(self.root, fg_color="transparent")
        center = ctk.CTkFrame(self.frame_login, fg_color="transparent")
        center.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center, text="Vault", font=ctk.CTkFont(size=30, weight="bold")).pack()
        ctk.CTkLabel(center, text="Encrypted database on your disk  •  AES-256-GCM  •  Memory-hard KDF",
                     text_color=MUTED).pack(pady=(2, 4))
        ctk.CTkLabel(center, text="Names, groups and contents are unreadable without the password.",
                     text_color=MUTED, font=ctk.CTkFont(size=12)).pack(pady=(0, 14))

        card = ctk.CTkFrame(center, width=560, corner_radius=16, fg_color=CARD_BG)
        card.pack(padx=10, pady=4)
        card.pack_propagate(False)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=26, pady=20)

        ctk.CTkLabel(inner, text="Vault folder", font=ctk.CTkFont(weight="bold")).pack(anchor="w")
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x", pady=(4, 10))
        self.var_vaultdir = ctk.StringVar()
        ctk.CTkEntry(row, textvariable=self.var_vaultdir,
                     placeholder_text="Pick or create an empty folder on disk…").pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(row, text="Browse…", width=110, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      command=self._browse_vaultdir).pack(side="left")

        ctk.CTkLabel(inner, text="Password", font=ctk.CTkFont(weight="bold")).pack(anchor="w")
        self.var_pw = ctk.StringVar()
        self.ent_pw = ctk.CTkEntry(inner, textvariable=self.var_pw, show="•",
                                   placeholder_text="Long passphrase (12+ characters)", height=40)
        self.ent_pw.pack(fill="x", pady=(4, 2))
        self.ent_pw.bind("<Return>", lambda _e: self.do_open())
        self.ent_pw.bind("<KeyRelease>", lambda _e: self._pw_meter())

        opt = ctk.CTkFrame(inner, fg_color="transparent")
        opt.pack(fill="x")
        self.var_show = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opt, text="Show password", variable=self.var_show,
                        command=lambda: self.ent_pw.configure(show="" if self.var_show.get() else "•")).pack(side="left")
        self.lbl_strength = ctk.CTkLabel(opt, text="", text_color=MUTED, font=ctk.CTkFont(size=12))
        self.lbl_strength.pack(side="right")
        self.bar_strength = ctk.CTkProgressBar(inner, height=8)
        self.bar_strength.pack(fill="x", pady=(4, 2))
        self.bar_strength.set(0)

        kdf = "Argon2id (128 MiB)" if _HAS_ARGON2 else "scrypt (N=131072)"
        ctk.CTkLabel(inner, text=f"KDF: {kdf}  •  {_CRYPTO_BACKEND}  •  100% offline",
                     text_color=MUTED, font=ctk.CTkFont(size=11)).pack(anchor="w", pady=(4, 0))

        btns = ctk.CTkFrame(inner, fg_color="transparent")
        btns.pack(fill="x", pady=(14, 2))
        ctk.CTkButton(btns, text="Open vault", height=42, font=ctk.CTkFont(size=15, weight="bold"),
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.do_open).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(btns, text="Create new", height=42, font=ctk.CTkFont(size=15),
                      fg_color="transparent", border_width=1, command=self.do_create).pack(side="left", expand=True, fill="x", padx=(6, 0))

        ctk.CTkLabel(center, text="Without the password your data is UNRECOVERABLE — there is no backdoor.",
                     text_color=MUTED, font=ctk.CTkFont(size=11)).pack(pady=(10, 0))

    def _browse_vaultdir(self):
        d = filedialog.askdirectory(title="Pick / create vault folder", parent=self.root)
        if d:
            self.var_vaultdir.set(d)
            self._touch()

    def _pw_meter(self):
        try:
            label, score = password_strength(self.var_pw.get())
        except Exception:
            label, score = ("", 0)
        self.lbl_strength.configure(text=f"{label} ({score}/100)" if self.var_pw.get() else "")
        self.bar_strength.set(max(0, min(1, score / 100.0)))
        self._touch()

    # ================= main =================
    def _build_main(self):
        self.frame_main = ctk.CTkFrame(self.root, fg_color="transparent")

        # ---- sidebar ----
        self.sidebar = ctk.CTkFrame(self.frame_main, width=250, corner_radius=0, fg_color=SIDEBAR_BG)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        ctk.CTkLabel(self.sidebar, text="Vault", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(18, 2), padx=16, anchor="w")
        self.lbl_vault_path = ctk.CTkLabel(self.sidebar, text="", text_color=MUTED,
                                           font=ctk.CTkFont(size=11), wraplength=210, justify="left")
        self.lbl_vault_path.pack(padx=16, anchor="w")
        self.lbl_lock = ctk.CTkLabel(self.sidebar, text="Unlocked", text_color="#2ecc71",
                                     font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_lock.pack(padx=16, pady=(2, 10), anchor="w")

        ctk.CTkLabel(self.sidebar, text="GROUPS", text_color=MUTED, font=ctk.CTkFont(size=12, weight="bold")).pack(padx=16, anchor="w", pady=(4, 4))
        self.groups_box = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", height=260)
        self.groups_box.pack(fill="both", expand=True, padx=8, pady=2)

        self.lbl_stats = ctk.CTkLabel(self.sidebar, text="", text_color=MUTED, font=ctk.CTkFont(size=12),
                                      justify="left", wraplength=210)
        self.lbl_stats.pack(padx=16, pady=8, anchor="w")
        self.lbl_autolock = ctk.CTkLabel(self.sidebar, text="", text_color=MUTED, font=ctk.CTkFont(size=11))
        self.lbl_autolock.pack(padx=16, anchor="w", pady=(0, 6))

        side_btns = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        side_btns.pack(fill="x", padx=12, pady=(0, 14))
        ctk.CTkButton(side_btns, text="Change password", fg_color="transparent", border_width=1,
                      command=self.ui_change_password).pack(fill="x", pady=3)
        ctk.CTkButton(side_btns, text="Lock vault", fg_color=DANGER, hover_color="#a93226",
                      command=lambda: self.do_lock()).pack(fill="x", pady=3)

        # ---- content ----
        content = ctk.CTkFrame(self.frame_main, fg_color="transparent")
        content.pack(side="left", fill="both", expand=True, padx=16, pady=12)

        # top bar: search + sort + add
        top = ctk.CTkFrame(content, fg_color="transparent")
        top.pack(fill="x", pady=(0, 8))
        self.var_search = ctk.StringVar()
        search = ctk.CTkEntry(top, textvariable=self.var_search, placeholder_text="Search files by name…", height=38)
        search.pack(side="left", fill="x", expand=True, padx=(0, 8))
        try:
            self.var_search.trace_add("write", lambda *_: self._on_search_changed())
        except Exception:
            pass
        self.cmb_sort = ctk.CTkComboBox(top, width=150, height=38, state="readonly",
                                        values=["Name A→Z", "Recent", "Largest", "Group"],
                                        command=lambda _v: self._on_sort_changed())
        self.cmb_sort.set("Name A→Z")
        self.cmb_sort.pack(side="left", padx=(0, 8))
        ctk.CTkButton(top, text="+ File", height=38, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      command=self.ui_add_files).pack(side="left", padx=2)
        ctk.CTkButton(top, text="+ Folder", height=38, fg_color="transparent", border_width=1,
                      command=self.ui_add_folder).pack(side="left", padx=2)

        # selection / actions bar
        self.action_bar = ctk.CTkFrame(content, fg_color=CARD_BG, corner_radius=12)
        self.action_bar.pack(fill="x", pady=(0, 8))
        self.lbl_sel = ctk.CTkLabel(self.action_bar, text="Nessuna selezione", text_color=MUTED)
        self.lbl_sel.pack(side="left", padx=14, pady=8)
        right = ctk.CTkFrame(self.action_bar, fg_color="transparent")
        right.pack(side="right", padx=8, pady=6)
        self.btn_extract = ctk.CTkButton(right, text="Extract", fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                         command=self.ui_extract_smart)
        self.btn_extract.pack(side="left", padx=3)
        ctk.CTkButton(right, text="Extract all", fg_color="transparent", border_width=1,
                      command=self.ui_extract_all).pack(side="left", padx=3)
        self.btn_delete = ctk.CTkButton(right, text="Delete", width=70, fg_color="transparent", border_width=1,
                                        command=self.ui_delete_selected)
        self.btn_delete.pack(side="left", padx=3)
        ctk.CTkButton(right, text="Group", fg_color="transparent", border_width=1,
                      command=self.ui_move_group).pack(side="left", padx=3)
        ctk.CTkButton(right, text="Select all", width=90, fg_color="transparent", border_width=0,
                      text_color=MUTED, command=self.select_all).pack(side="left", padx=3)

        # file list
        self.files_scroll = ctk.CTkScrollableFrame(content, fg_color="transparent")
        self.files_scroll.pack(fill="both", expand=True)
        self.lbl_empty = ctk.CTkLabel(self.files_scroll, text="", text_color=MUTED,
                                      font=ctk.CTkFont(size=14), justify="center")
        # status + progress
        bottom = ctk.CTkFrame(content, fg_color="transparent")
        bottom.pack(fill="x", pady=(8, 0))
        self.var_status = ctk.StringVar(value="Ready.")
        ctk.CTkLabel(bottom, textvariable=self.var_status, text_color=MUTED,
                     font=ctk.CTkFont(size=12), anchor="w").pack(side="left", fill="x", expand=True)
        self.progress = ctk.CTkProgressBar(bottom, width=220, height=10)
        self.progress.pack(side="right", padx=(10, 0))
        self.progress.set(0)

    # ================= viste =================
    def show_login(self):
        try:
            self.frame_main.pack_forget()
        except Exception:
            pass
        self.frame_login.pack(fill="both", expand=True)
        self.root.title(APP_TITLE + " — Encrypted Database")

    def show_main(self):
        try:
            self.frame_login.pack_forget()
        except Exception:
            pass
        self.frame_main.pack(fill="both", expand=True)
        self.root.title(f"{APP_TITLE} — {self.vault_dir}")
        try:
            short = self.vault_dir
            if len(short) > 38:
                short = "…" + short[-37:]
            self.lbl_vault_path.configure(text=short)
        except Exception:
            pass
        self.refresh_list()

    # ================= helpers UI =================
    def _touch(self):
        self._last_activity = time.time()

    def _is_busy(self) -> bool:
        try:
            with self._busy_lock:
                return self._busy > 0
        except Exception:
            return False

    def status(self, msg: str):
        try:
            self.var_status.set(msg)
        except Exception:
            pass

    def set_progress(self, done: int, total: int):
        try:
            pct = 0 if total <= 0 else max(0, min(1, done / float(total)))
            self.progress.set(pct)
        except Exception:
            pass

    def _tick_autolock(self):
        try:
            if self._is_busy():
                self._last_activity = time.time()
            elif self.vault is not None and self.vault.is_unlocked:
                rest = AUTOLOCK_SECONDS - (time.time() - self._last_activity)
                if rest <= 0:
                    self.do_lock(auto=True)
                    return
                try:
                    self.lbl_autolock.configure(text=f"Lock in {int(rest // 60)}:{int(rest % 60):02d}")
                except Exception:
                    pass
            else:
                try:
                    self.lbl_autolock.configure(text="")
                except Exception:
                    pass
        finally:
            try:
                self.root.after(1000, self._tick_autolock)
            except Exception:
                pass

    # ---- background jobs (worker never touches the UI) ----
    def run_bg(self, label: str, fn, done_cb=None):
        try:
            with self._busy_lock:
                self._busy += 1
        except Exception:
            pass
        self.status(label + "…")
        self.set_progress(0, 1)

        def progress_cb(d, t):
            try:
                self._progress_q.put((d, t))
            except Exception:
                pass

        def worker():
            try:
                res = fn(progress_cb)
                self._jobs.put(("ok", res, done_cb, label))
            except Exception as e:
                self._jobs.put(("err", e, done_cb, label))

        threading.Thread(target=worker, daemon=True).start()
        self._ensure_polling()

    def _ensure_polling(self):
        try:
            if not self._poll_scheduled:
                self._poll_scheduled = True
                self.root.after(80, self._poll_queues)
        except Exception:
            pass

    def _poll_queues(self):
        try:
            last = None
            while True:
                try:
                    last = self._progress_q.get_nowait()
                except queue.Empty:
                    break
            if last is not None:
                try:
                    d, t = last
                    self.set_progress(int(d), int(t))
                except Exception:
                    pass
            while True:
                try:
                    kind, payload, done_cb, label = self._jobs.get_nowait()
                except queue.Empty:
                    break
                try:
                    with self._busy_lock:
                        self._busy = max(0, self._busy - 1)
                except Exception:
                    pass
                if kind == "ok":
                    self.progress.set(0)
                    self.status(label + " done.")
                    self._touch()
                    if done_cb:
                        try:
                            done_cb(payload)
                        except Exception:
                            traceback.print_exc()
                else:
                    msg = safe_msg(payload)
                    try:
                        first = (msg.splitlines()[0] if msg.splitlines() else "Error")[:200]
                    except Exception:
                        first = "Error"
                    self.status("Error: " + first)
                    try:
                        messagebox.showerror("Error", msg, parent=self.root)
                    except Exception:
                        pass
        finally:
            try:
                busy = self._is_busy()
                pending = (not self._jobs.empty()) or (not self._progress_q.empty())
                if busy or pending:
                    self.root.after(80, self._poll_queues)
                else:
                    self._poll_scheduled = False
                    try:
                        self.progress.set(0)
                    except Exception:
                        pass
            except Exception:
                try:
                    self._poll_scheduled = False
                except Exception:
                    pass

    # ================= vault open/create/lock =================
    def _get_dir_and_pw(self) -> tuple[str, str]:
        d = (self.var_vaultdir.get() or "").strip().strip('"').strip("'")
        try:
            d = os.path.expanduser(d)
        except Exception:
            pass
        p = self.var_pw.get()
        if not d:
            raise VaultError("Select the vault folder.")
        if not p:
            raise VaultError("Enter the password.")
        return d, p

    def _clear_pw_widget(self):
        try:
            self.var_pw.set("")
        except Exception:
            pass
        try:
            self.ent_pw.delete(0, "end")
        except Exception:
            pass
        try:
            self.bar_strength.set(0)
            self.lbl_strength.configure(text="")
        except Exception:
            pass
        gc.collect()

    def do_create(self):
        try:
            d, p = self._get_dir_and_pw()
        except VaultError as e:
            return messagebox.showwarning("Warning", safe_msg(e), parent=self.root)
        try:
            _lab, score = password_strength(p)
        except Exception:
            _lab, score = ("-", 0)
        if score < 30:
            if not messagebox.askyesno("Weak password",
                                       f"The password is '{_lab}'. Create the vault anyway?\nA 12+ character passphrase is recommended.",
                                       parent=self.root):
                return
        try:
            self.vault = Vault.create(d, p)
            self.vault_dir = os.path.abspath(d)
        except VaultError as e:
            return messagebox.showerror("Error", safe_msg(e), parent=self.root)
        except Exception as e:
            return messagebox.showerror("Error", safe_msg(e), parent=self.root)
        finally:
            self._clear_pw_widget()
        self.selected.clear()
        self.group_filter = ""
        self.show_main()
        self.status("New vault created and unlocked.")
        self._touch()

    def do_open(self):
        try:
            d, p = self._get_dir_and_pw()
        except VaultError as e:
            return messagebox.showwarning("Warning", safe_msg(e), parent=self.root)
        try:
            v = Vault(d)
        except VaultError as e:
            self._clear_pw_widget()
            return messagebox.showerror("Cannot open", safe_msg(e), parent=self.root)
        try:
            v.unlock(p)
        except VaultError as e:
            return messagebox.showerror("Cannot open", safe_msg(e), parent=self.root)
        except Exception as e:
            return messagebox.showerror("Cannot open", safe_msg(e), parent=self.root)
        finally:
            self._clear_pw_widget()
        self.vault = v
        self.vault_dir = os.path.abspath(d)
        self.selected.clear()
        self.group_filter = ""
        self.show_main()
        try:
            n = len(self.vault.list_files())
        except Exception:
            n = 0
        self.status(f"Vault unlocked — {n} files.  (double-click to extract)")
        self._touch()

    def do_lock(self, auto=False):
        if self._is_busy() and not auto:
            messagebox.showwarning("Operation in progress",
                                   "An encryption/decryption operation is running.\nWait for it to finish before locking.",
                                   parent=self.root)
            return
        if auto and self._is_busy():
            return
        try:
            if self.vault is not None:
                try:
                    self.vault.lock()
                except Exception:
                    pass
        finally:
            self.vault = None
            self.entries = []
            self.selected.clear()
            self.show_login()
            try:
                self.status("Vault locked.")
            except Exception:
                pass
            if auto:
                try:
                    messagebox.showinfo("Auto-lock",
                                        "Vault locked after 10 min of inactivity.", parent=self.root)
                except Exception:
                    pass

    def on_close(self):
        if self._is_busy():
            try:
                ok = messagebox.askyesno("Operations in progress",
                                         "Operations are still running. Quit anyway?\n(temp files will be cleaned on next start)",
                                         parent=self.root)
                if not ok:
                    return
            except Exception:
                pass
        try:
            if self.vault is not None:
                try:
                    self.vault.lock()
                except Exception:
                    pass
        finally:
            try:
                self.root.destroy()
            except Exception:
                pass

    # ================= list / filters / selection =================
    def _on_search_changed(self):
        self.search_text = self.var_search.get()
        self._touch()
        self.refresh_list()

    def _on_sort_changed(self):
        try:
            self.sort_mode = self.cmb_sort.get()
        except Exception:
            pass
        self.refresh_list()

    def _apply_sort(self, entries: list[dict]) -> list[dict]:
        try:
            if self.sort_mode == "Recent":
                return sorted(entries, key=lambda e: str(e.get("created", "")), reverse=True)
            if self.sort_mode == "Largest":
                return sorted(entries, key=lambda e: int(e.get("size", 0)), reverse=True)
            if self.sort_mode == "Group":
                return sorted(entries, key=lambda e: ((e.get("group") or "").lower(), (e.get("name") or "").lower()))
            return sorted(entries, key=lambda e: (e.get("name") or "").lower())
        except Exception:
            return entries

    def refresh_list(self):
        try:
            if self.vault is None or not self.vault.is_unlocked:
                return
        except Exception:
            return
        try:
            gf = "" if self.group_filter in ("", "All") else self.group_filter
            entries = self.vault.list_files(group_filter=gf, search=self.search_text)
        except VaultError as e:
            return messagebox.showerror("Error", safe_msg(e), parent=self.root)
        except Exception as e:
            return messagebox.showerror("Error", safe_msg(e), parent=self.root)
        entries = self._apply_sort(entries)
        self.entries = entries
        # groups + stats (always on the whole vault)
        try:
            self.all_groups = self.vault.groups()
        except Exception:
            self.all_groups = []
        self._render_groups()
        self._render_files()
        self._update_stats()
        self._update_action_bar()

    def _render_groups(self):
        for w in self.groups_box.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass
        # per-group counts (whole view, ignoring the current filter)
        counts: dict[str, int] = {}
        try:
            assert self.vault is not None
            all_e = self.vault.list_files()
            for e in all_e:
                g = (e.get("group") or "").strip()
                if g:
                    counts[g] = counts.get(g, 0) + 1
            total = len(all_e)
        except Exception:
            total = len(self.entries)

        def mk_btn(label, value, count=None):
            active = (self.group_filter == value) or (value == "" and self.group_filter in ("", "All"))
            txt = label if count is None else f"{label}  ·  {count}"
            b = ctk.CTkButton(self.groups_box, text=txt, anchor="w", height=32,
                              fg_color=(ACCENT if active else "transparent"),
                              text_color=("white" if active else ("gray10", "gray85")),
                              hover_color=(ACCENT_HOVER if active else ("gray70", "#333")),
                              command=lambda v=value: self._set_group(v))
            b.pack(fill="x", pady=1)

        mk_btn("All files", "", total)
        mk_btn("No group", "__EMPTY__", None)
        for g in self.all_groups:
            mk_btn(g, g, counts.get(g, 0))

    def _set_group(self, value: str):
        if value == "__EMPTY__":
            # special filter: show ungrouped files (client-side)
            self.group_filter = "__EMPTY__"
        else:
            self.group_filter = value
        self.selected.clear()
        self._touch()
        if value == "__EMPTY__":
            self.refresh_list_empty_only()
        else:
            self.refresh_list()

    def refresh_list_empty_only(self):
        try:
            if self.vault is None or not self.vault.is_unlocked:
                return
            entries = self.vault.list_files(search=self.search_text)
            entries = [e for e in entries if not (e.get("group") or "").strip()]
            self.entries = self._apply_sort(entries)
            try:
                self.all_groups = self.vault.groups()
            except Exception:
                pass
            self._render_groups()
            self._render_files()
            self._update_stats()
            self._update_action_bar()
        except Exception as e:
            messagebox.showerror("Error", safe_msg(e), parent=self.root)

    def _render_files(self):
        for w in self.files_scroll.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass
        self.row_widgets.clear()
        if not self.entries:
            hint = "Vault is empty.\nPress + File or + Folder to encrypt your first files."
            if self.search_text or self.group_filter:
                hint = "No files found.\nTry changing the search or group."
            lbl = ctk.CTkLabel(self.files_scroll, text=hint, text_color=MUTED,
                               font=ctk.CTkFont(size=15), justify="center")
            lbl.pack(pady=60)
            return
        for e in self.entries:
            fid = str(e.get("id", ""))
            if not fid:
                continue
            sel = fid in self.selected
            row = ctk.CTkFrame(self.files_scroll, corner_radius=10,
                               fg_color=(CARD_SELECTED if sel else CARD_BG))
            row.pack(fill="x", pady=3, padx=2)
            left = ctk.CTkFrame(row, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=12, pady=8)
            txt = ctk.CTkFrame(left, fg_color="transparent")
            txt.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(txt, text=e.get("name", "-"), font=ctk.CTkFont(size=14, weight="bold"),
                         anchor="w").pack(anchor="w")
            grp = (e.get("group") or "").strip() or "No group"
            ctk.CTkLabel(txt, text=grp, text_color=MUTED,
                         font=ctk.CTkFont(size=12), anchor="w").pack(anchor="w")
            right = ctk.CTkFrame(row, fg_color="transparent")
            right.pack(side="right", padx=12)
            ctk.CTkLabel(right, text=format_size(e.get("size", 0)),
                         font=ctk.CTkFont(size=13, weight="bold"), anchor="e").pack(anchor="e")
            ctk.CTkLabel(right, text=short_date(str(e.get("created", ""))),
                         text_color=MUTED, font=ctk.CTkFont(size=11), anchor="e").pack(anchor="e")
            self.row_widgets[fid] = row
            # row + child clicks all drive selection
            row.bind("<Button-1>", lambda ev, f=fid: self.on_row_click(f, ev))
            row.bind("<Double-Button-1>", lambda ev, f=fid: self.on_row_double(f))
            for child in list(left.winfo_children()) + list(txt.winfo_children()) + list(right.winfo_children()):
                try:
                    child.bind("<Button-1>", lambda ev, f=fid: self.on_row_click(f, ev))
                    child.bind("<Double-Button-1>", lambda ev, f=fid: self.on_row_double(f))
                except Exception:
                    pass

    def _update_stats(self):
        try:
            total_size = sum(int(e.get("size", 0)) for e in self.entries)
        except Exception:
            total_size = 0
        try:
            n_all = len(self.vault.list_files()) if self.vault else 0
        except Exception:
            n_all = len(self.entries)
        try:
            self.lbl_stats.configure(text=f"{n_all} files in vault\n{format_size(total_size)} shown ({len(self.entries)})")
        except Exception:
            pass

    def _update_action_bar(self):
        n = len(self.selected)
        try:
            if n == 0:
                self.lbl_sel.configure(text=f"{len(self.entries)} files • double-click to extract • Ctrl+click for multi-select")
            elif n == 1:
                self.lbl_sel.configure(text="1 file selected")
            else:
                self.lbl_sel.configure(text=f"{n} files selected")
        except Exception:
            pass

    def on_row_click(self, fid: str, ev=None):
        self._touch()
        try:
            ctrl = ev is not None and (getattr(ev, "state", 0) & 0x0004)
        except Exception:
            ctrl = False
        if ctrl:
            if fid in self.selected:
                self.selected.discard(fid)
            else:
                self.selected.add(fid)
        else:
            if self.selected == {fid}:
                self.selected.clear()
            else:
                self.selected = {fid}
        # recolor without rebuilding everything (fast)
        for k, row in self.row_widgets.items():
            try:
                row.configure(fg_color=(CARD_SELECTED if k in self.selected else CARD_BG))
            except Exception:
                pass
        self._update_action_bar()

    def on_row_double(self, fid: str):
        self.selected = {fid}
        for k, row in self.row_widgets.items():
            try:
                row.configure(fg_color=(CARD_SELECTED if k in self.selected else CARD_BG))
            except Exception:
                pass
        self._update_action_bar()
        self.ui_extract_smart()

    def select_all(self):
        self.selected = {str(e["id"]) for e in self.entries if e.get("id")}
        for k, row in self.row_widgets.items():
            try:
                row.configure(fg_color=(CARD_SELECTED if k in self.selected else CARD_BG))
            except Exception:
                pass
        self._update_action_bar()
        self._touch()

    def _valid_selected_ids(self) -> list[str]:
        return [i for i in self.selected if isinstance(i, str) and FILE_ID_RE.match(i)]

    # ================= import =================
    def ui_add_files(self):
        if self.vault is None:
            return
        try:
            paths = filedialog.askopenfilenames(title="Select files to encrypt into the vault", parent=self.root)
        except Exception as e:
            return messagebox.showerror("Error", safe_msg(e), parent=self.root)
        if not paths:
            return
        group = ask_group_dialog(self.root, title="Group for these files",
                                 initial=(self.last_group or ("" if self.group_filter in ("", "All", "__EMPTY__") else self.group_filter)),
                                 groups=self.all_groups)
        if group is None:
            return
        shred = ask_shred_dialog(self.root)
        if shred is None:
            return
        self.last_group = group or ""
        paths = list(paths)

        def job(progress_cb):
            sizes = []
            for p in paths:
                try:
                    if os.path.islink(p):
                        raise VaultError(f"Symlink skipped: {os.path.basename(p)}")
                    sizes.append(os.path.getsize(p))
                except VaultError:
                    raise
                except (OSError, ValueError) as e:
                    raise VaultError(f"Unreadable file: {os.path.basename(p)}") from e
            total = sum(s + (PAD_GRANULARITY - (s % PAD_GRANULARITY)) for s in sizes)
            total = max(total, 1)
            assert self.vault is not None
            out = []
            done = [0]
            for p, sz in zip(paths, sizes):
                base_done = done[0]

                def cb(d, t, _b=base_done, _tot=total):
                    try:
                        progress_cb(min(_b + d, _tot), _tot)
                    except Exception:
                        pass

                try:
                    e = self.vault.add_file(p, group=group or "", shred_original=bool(shred), progress_cb=cb)
                except VaultError as ve:
                    raise VaultError(f"{ve} [{os.path.basename(p)}]") from ve
                out.append(e)
                pad = PAD_GRANULARITY - (int(e.get("size", sz)) % PAD_GRANULARITY)
                done[0] = base_done + int(e.get("size", sz)) + pad
                try:
                    progress_cb(min(done[0], total), total)
                except Exception:
                    pass
            return out

        self.run_bg(f"Encrypting {len(paths)} files", job,
                    done_cb=lambda _r: (self.refresh_list(),
                                        self.status(f"Imported {len(_r)} files into group '{group or '-'}'.")))

    def ui_add_folder(self):
        if self.vault is None:
            return
        folder = filedialog.askdirectory(title="Select folder to encrypt (file group)", parent=self.root)
        if not folder:
            return
        try:
            initial = self.last_group or os.path.basename(os.path.abspath(folder))
        except Exception:
            initial = ""
        group = ask_group_dialog(self.root, title="Group for this folder",
                                 initial=initial or "", groups=self.all_groups)
        if group is None:
            return
        shred = ask_shred_dialog(self.root)
        if shred is None:
            return
        self.last_group = group or ""
        assert self.vault is not None
        v = self.vault

        def job(progress_cb):
            return v.add_folder(folder, group=group or "", shred_original=bool(shred), progress_cb=progress_cb)

        def _done(r):
            try:
                self.refresh_list()
                self.status(f"Imported {len(r)} files from the folder.")
            except Exception:
                pass
        self.run_bg("Encrypting folder", job, done_cb=_done)

    # ================= export / delete / groups / password =================
    def ui_extract_smart(self):
        """One smart button: 1 file -> Save As, N files -> folder."""
        if self.vault is None:
            return
        ids = self._valid_selected_ids()
        if not ids:
            return messagebox.showinfo("No selection", "Select at least one file from the list.", parent=self.root)
        if len(ids) == 1:
            assert self.vault is not None
            try:
                entry = self.vault.get_entry(ids[0])
            except VaultError as e:
                return messagebox.showerror("Error", safe_msg(e), parent=self.root)
            try:
                dest = filedialog.asksaveasfilename(title="Extract and decrypt as…",
                                                    initialfile=Vault.sanitize_component(entry["name"]),
                                                    parent=self.root)
            except Exception as e:
                return messagebox.showerror("Error", safe_msg(e), parent=self.root)
            if not dest:
                return
            v = self.vault
            fid = ids[0]

            def job(progress_cb):
                return v.extract_file(fid, dest, progress_cb=progress_cb)

            def _done(p):
                try:
                    messagebox.showinfo("Extracted", f"Decrypted and verified file (SHA-256):\n{p}", parent=self.root)
                except Exception:
                    pass
            self.run_bg("Decryption", job, done_cb=_done)
        else:
            destdir = filedialog.askdirectory(title=f"Destination folder ({len(ids)} files)", parent=self.root)
            if not destdir:
                return
            v = self.vault
            ids_copy = list(ids)

            def job(progress_cb):
                try:
                    total = sum(int(v.get_entry(i)["size"]) for i in ids_copy)
                except (VaultError, ValueError, TypeError) as e:
                    raise VaultError("Invalid entry for extraction.") from e
                total = max(total, 1)
                out = []
                done = [0]
                for i in ids_copy:
                    from secure_vault import validate_file_id as _v
                    _v(i)
                    e = v.get_entry(i)
                    d = os.path.join(destdir, Vault.sanitize_component(e["name"]))
                    d = v._unique_dest(d)
                    prev = [0]

                    def cb(x, t, _done=done, _prev=prev, _tot=total):
                        _done[0] += (x - _prev[0])
                        _prev[0] = x
                        try:
                            progress_cb(min(_done[0], _tot), _tot)
                        except Exception:
                            pass
                    v.extract_file(i, d, progress_cb=cb)
                    out.append(d)
                return out

            def _done_multi(r):
                try:
                    messagebox.showinfo("Extracted", f"{len(r)} files decrypted and verified in:\n{destdir}", parent=self.root)
                except Exception:
                    pass
            self.run_bg(f"Decrypting {len(ids)} files", job, done_cb=_done_multi)

    def ui_extract_all(self):
        if self.vault is None:
            return
        destdir = filedialog.askdirectory(title="Destination folder (entire vault)", parent=self.root)
        if not destdir:
            return
        gf = "" if self.group_filter in ("", "All", "__EMPTY__") else self.group_filter
        v = self.vault

        def job(progress_cb):
            return v.extract_all(destdir, group_filter=gf, progress_cb=progress_cb)

        def _done(r):
            try:
                messagebox.showinfo("Extracted", f"{len(r)} files decrypted and verified (SHA-256).", parent=self.root)
            except Exception:
                pass
        self.run_bg("Full extraction", job, done_cb=_done)

    def ui_delete_selected(self):
        if self.vault is None:
            return
        ids = self._valid_selected_ids()
        if not ids:
            return messagebox.showinfo("No selection", "Select at least one file.", parent=self.root)
        names = []
        for i in ids[:8]:
            try:
                assert self.vault is not None
                names.append("- " + str(self.vault.get_entry(i).get("name", i)))
            except Exception:
                names.append("- " + i)
        extra = f"\n…and {len(ids) - 8} more files." if len(ids) > 8 else ""
        if not confirm_delete_dialog(self.root, len(ids), "\n".join(names) + extra):
            return
        v = self.vault
        ids_copy = list(ids)

        def job(progress_cb):
            from secure_vault import validate_file_id as _v
            n = len(ids_copy)
            for k, i in enumerate(ids_copy):
                _v(i)
                v.delete_file(i)
                try:
                    progress_cb(k + 1, n)
                except Exception:
                    pass
            return n

        def _done(_n):
            self.selected.clear()
            self.refresh_list()
        self.run_bg("Secure deletion (shredding)", job, done_cb=_done)

    def ui_move_group(self):
        if self.vault is None:
            return
        ids = self._valid_selected_ids()
        if not ids:
            return messagebox.showinfo("No selection", "Select at least one file.", parent=self.root)
        ng = ask_group_dialog(self.root, title=f"Move {len(ids)} files to group",
                              initial="", groups=self.all_groups)
        if ng is None:
            return
        try:
            assert self.vault is not None
            for i in ids:
                self.vault.move_to_group(i, ng)
            self.refresh_list()
            self.status(f"{len(ids)} files moved to '{(ng or 'No group')[:64]}'.")
        except VaultError as e:
            messagebox.showerror("Error", safe_msg(e), parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", safe_msg(e), parent=self.root)

    def ui_change_password(self):
        if self.vault is None:
            return
        if self._is_busy():
            return messagebox.showwarning("Operation in progress",
                                          "Wait for completion before changing the password.",
                                          parent=self.root)
        res = ask_password_change_dialog(self.root)
        if not res:
            return
        old, new = res
        try:
            assert self.vault is not None
            self.vault.change_password(old, new)
            self._touch()
            self.status("Password changed (master key re-wrapped).")
            messagebox.showinfo("OK", "Password changed. Your data was NOT re-encrypted\n(only the master key was re-wrapped).",
                                parent=self.root)
        except VaultError as e:
            messagebox.showerror("Error", safe_msg(e), parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", safe_msg(e), parent=self.root)
        finally:
            gc.collect()

    def run(self):
        self.root.mainloop()


def main():
    app = ModernVaultApp()
    app.run()


if __name__ == "__main__":
    main()
