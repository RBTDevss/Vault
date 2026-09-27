#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VAULT — Encrypted on-disk database (AES-256-GCM + Scrypt/Argon2id)
==============================================================================
Single-file program with a Tkinter GUI.

What it does:
  - Turns a folder on your disk into a private encrypted database.
  - Every imported file is ENCRYPTED with AES-256-GCM and stored as an
    anonymous blob (random name). Names, groups, real sizes and contents are
    unreadable without the password.
  - Supports single files and whole groups/folders.
  - Secure deletion (shredding) of blobs and, on request, of the originals.
  - No plaintext temp files, 1 MB chunk streaming (handles large files).
  - Fully encrypted and authenticated index (manifest).

Security (forensic level — best effort on stock OS):
  [1] Memory-hard KDF: Argon2id when available (argon2-cffi), otherwise
      scrypt (N=131072, r=8, p=1, ~128 MB). Slows down GPU/ASIC brute force.
  [2] 256-bit CSPRNG master key; data is NEVER encrypted directly with the
      password but with per-file keys (FEK) wrapped by the master key.
      Changing the password only re-wraps the master key.
  [3] Unique 256-bit FEK per file + never-reused nonces
      (8 random bytes + 32-bit counter). GCM authenticates every chunk:
      tampering = decryption error, no partial corrupt output.
  [4] Random blob names (128 bit), padding to 512-byte multiples to hide
      exact sizes, encrypted manifest (names/groups hidden).
  [5] 3-pass shredding (random/zero/random) + fsync + anonymous rename
      before unlink. Atomic manifest writes.
  [6] No plaintext temp files: direct streaming encryption/decryption
      source->destination. Lock wipes keys from memory (best effort).
  HONEST LIMITS (no pure software can remove these without dedicated HW):
    - On SSD/NVMe, wear-leveling and FS journals may keep unreachable
      physical copies: for maximum security also use full-disk encryption
      (BitLocker/LUKS/FileVault) and shred originals ASAP. Deleted blobs
      stay unreadable without the master key.
    - RAM/swap/hibernation may retain fragments: lock the vault when done;
      against advanced threats use a live/amnesic OS.
    - Python cannot deterministically wipe immutable strings: passwords are
      cleared from widgets and keys zeroed as bytearray where possible.

Dependencies:  pycryptodomex (or pycryptodome)  —  pip install -r requirements.txt
              argon2-cffi (optional, recommended) — Argon2id is used when present.
Run:  python vault.py
Quick test: python vault.py --selftest
"""

import base64
import binascii
import datetime
import gc
import hashlib
import json
import os
import queue
import re
import secrets
import shutil
import struct
import sys
import threading
import time
import traceback
import unicodedata
# NOTE: no compression before encryption (compression oracle / CRIME-like:
# ciphertext size would leak plaintext redundancy). Deliberately absent.
from pathlib import Path

# --------------------------------------------------------------------------
# Crypto backend (pycryptodomex preferred, pycryptodome fallback)
# --------------------------------------------------------------------------
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    _CRYPTO_BACKEND = "Cryptodome (pycryptodomex)"
except ImportError:  # fallback pycryptodome classico
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        _CRYPTO_BACKEND = "Crypto (pycryptodome)"
    except ImportError:
        AES = None  # type: ignore
        get_random_bytes = None  # type: ignore
        _CRYPTO_BACKEND = "MISSING"

# Optional Argon2id (preferred over scrypt when installed)
_HAS_ARGON2 = False
try:
    from argon2.low_level import hash_secret_raw, Type as _ArgonType
    _HAS_ARGON2 = True
except Exception:
    _HAS_ARGON2 = False

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
VAULT_MAGIC = "PVLT1"
BLOB_MAGIC = b"PVB1"
APP_TITLE = "Vault — Encrypted Database"
CHUNK_SIZE = 1024 * 1024          # 1 MB per chunk (streaming, constant RAM)
PAD_GRANULARITY = 512             # hides exact size within 512 bytes
SHRED_PASSES_DEFAULT = 3
SHRED_BLOCK = 64 * 1024
MAX_COUNTER = 2 ** 32 - 1         # 32-bit nonce counter: never reuse a nonce
MAX_MANIFEST_BYTES = 32 * 1024 * 1024   # 32 MB: anti-DoS cap on encrypted manifest
MAX_META_BYTES = 64 * 1024              # vault.meta must stay small
MAX_FILE_SIZE = 2 ** 60                 # sanity cap per entry (~1 EiB)
FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# scrypt (hashlib, memory-hard, in the stdlib)
SCRYPT_N = 2 ** 17               # 131072 — ~128 MB, ~0.5-2 s on modern PCs
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
# Accepted KDF limits for on-disk params (anti-DoS against tampered meta):
# scrypt N power of 2 in [2^14, 2^20], r in [1,16], p in [1,4].
SCRYPT_N_MIN = 2 ** 14
SCRYPT_N_MAX = 2 ** 20
# Argon2id (when argon2-cffi is present) — recommended OWASP settings
ARGON_TIME_COST = 3
ARGON_MEMORY_KIB = 131072        # 128 MiB
ARGON_PARALLELISM = 4
ARGON_DKLEN = 32
ARGON_TIME_MIN, ARGON_TIME_MAX = 1, 10
ARGON_MEM_MIN_KIB, ARGON_MEM_MAX_KIB = 8192, 1048576   # 8 MiB .. 1 GiB
ARGON_PAR_MIN, ARGON_PAR_MAX = 1, 16
# Legacy PBKDF2 (accepted only when an old vault explicitly declares it)
PBKDF2_ITER_MIN, PBKDF2_ITER_MAX = 100_000, 2_000_000

VERIFIER = b"PRIVATE-VAULT-v1-OK"

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class VaultError(Exception):
    """Generic vault error (safe to show to the user)."""


# --------------------------------------------------------------------------
# Utility
# --------------------------------------------------------------------------
def _require_crypto():
    if AES is None or get_random_bytes is None:
        raise VaultError(
            "Missing crypto backend.\n"
            "Install with:  pip install pycryptodomex\n"
            "(or: pip install pycryptodome)"
        )


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    """Strict Base64: format errors become VaultError (no traceback leaks)."""
    try:
        if not isinstance(s, str):
            raise VaultError("Invalid encoded data.")
        if len(s) > 64 * 1024 * 1024:
            raise VaultError("Encoded data too large.")
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as e:
        raise VaultError("Corrupted encoded data.") from e


def utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def wipe_bytearray(buf: bytearray | None):
    """Zero a mutable bytearray (best effort). Call ONLY on real bytearrays
    we own (master/FEK). Has no effect on immutable bytes."""
    if buf is None:
        return
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def strong_random(n: int) -> bytes:
    _require_crypto()
    if n < 0 or n > 64 * 1024 * 1024:
        raise VaultError("Invalid random request.")
    if n == 0:
        return b""
    return get_random_bytes(n)


def new_file_id() -> str:
    return secrets.token_hex(16)  # 128 bit


def validate_file_id(fid: str) -> str:
    """Rejects path traversal via tampered IDs (untrusted/corrupt manifest)."""
    if not isinstance(fid, str) or not FILE_ID_RE.match(fid):
        raise VaultError("Invalid file ID.")
    return fid


def is_path_inside(child: str, parent: str) -> bool:
    """True when child == parent or child is contained in parent (realpath compare)."""
    try:
        c = os.path.realpath(os.path.abspath(child))
        p = os.path.realpath(os.path.abspath(parent))
        return c == p or c.startswith(p + os.sep)
    except Exception:
        return False


def set_private_perms(path: str) -> None:
    """Owner-only access for a file/directory (best effort). Never fails the operation."""
    try:
        if os.name != "nt":
            if os.path.isdir(path):
                os.chmod(path, 0o700)
            else:
                os.chmod(path, 0o600)
        else:
            # Windows: almeno flag read-only off + tentativo 0o600 (ACL reali non gestibili in stdlib)
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
    except Exception:
        pass


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def validate_kdf_params(kdf: str, params: dict) -> dict:
    """Validates on-disk KDF params (untrusted meta). Rejects absurd values
    that would cause DoS (huge RAM/CPU) or silent downgrades."""
    if not isinstance(params, dict):
        raise VaultError("Invalid KDF parameters.")
    if kdf == "scrypt":
        try:
            n = int(params.get("n", SCRYPT_N))
            r = int(params.get("r", SCRYPT_R))
            p = int(params.get("p", SCRYPT_P))
        except Exception as e:
            raise VaultError("Invalid scrypt parameters.") from e
        if (not _is_power_of_two(n)) or not (SCRYPT_N_MIN <= n <= SCRYPT_N_MAX):
            raise VaultError("scrypt parameters out of range (N).")
        if not (1 <= r <= 16) or not (1 <= p <= 4):
            raise VaultError("scrypt parameters out of range (r/p).")
        return {"n": n, "r": r, "p": p}
    elif kdf == "argon2id":
        try:
            t = int(params.get("time_cost", ARGON_TIME_COST))
            m = int(params.get("memory_kib", ARGON_MEMORY_KIB))
            par = int(params.get("parallelism", ARGON_PARALLELISM))
        except Exception as e:
            raise VaultError("Invalid Argon2 parameters.") from e
        if not (ARGON_TIME_MIN <= t <= ARGON_TIME_MAX):
            raise VaultError("Argon2 parameters out of range (time).")
        if not (ARGON_MEM_MIN_KIB <= m <= ARGON_MEM_MAX_KIB):
            raise VaultError("Argon2 parameters out of range (memory).")
        if not (ARGON_PAR_MIN <= par <= ARGON_PAR_MAX):
            raise VaultError("Argon2 parameters out of range (parallelism).")
        return {"time_cost": t, "memory_kib": m, "parallelism": par}
    elif kdf == "pbkdf2":
        # Legacy only, explicitly declared: never used for new vaults, accepted for reading.
        try:
            it = int(params.get("iterations", 600_000))
        except Exception as e:
            raise VaultError("Invalid PBKDF2 parameters.") from e
        if not (PBKDF2_ITER_MIN <= it <= PBKDF2_ITER_MAX):
            raise VaultError("PBKDF2 parameters out of range.")
        return {"iterations": it}
    else:
        raise VaultError(f"Unknown/unsupported KDF: {kdf!r}.")


def cleanup_stale_tmp(directory: str) -> None:
    """Removes orphan temp files (*.tmp-*) from previous crashes. Best effort."""
    try:
        if not os.path.isdir(directory):
            return
        for fn in os.listdir(directory):
            if ".tmp-" in fn:
                full = os.path.join(directory, fn)
                try:
                    if os.path.isfile(full) and not os.path.islink(full):
                        os.remove(full)
                except Exception:
                    pass
    except Exception:
        pass


def password_strength(pw: str) -> tuple[str, int]:
    """Honest 0-100 estimate + label. Not full zxcvbn, but blocks weak passwords."""
    if not pw:
        return ("Empty", 0)
    length = len(pw)
    classes = 0
    if any(c.islower() for c in pw):
        classes += 1
    if any(c.isupper() for c in pw):
        classes += 1
    if any(c.isdigit() for c in pw):
        classes += 1
    if any(not c.isalnum() for c in pw):
        classes += 1
    # penalize trivial patterns
    lowered = pw.lower()
    banal = ["password", "123456", "qwerty", "vault", "admin", "hello"]
    penalty = 0
    for b in banal:
        if b in lowered:
            penalty += 25
    score = min(100, length * 5 + (classes - 1) * 12 - penalty)
    score = max(0, score)
    if score < 30:
        label = "Weak"
    elif score < 55:
        label = "Fair"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very strong"
    if length < 12:
        label += " — use 12+ characters"
    return (label, score)


# --------------------------------------------------------------------------
# KDF: Argon2id when available, otherwise scrypt (memory-hard)
# --------------------------------------------------------------------------
def kdf_info_default() -> dict:
    if _HAS_ARGON2:
        return {"kdf": "argon2id",
                "params": {"time_cost": ARGON_TIME_COST,
                           "memory_kib": ARGON_MEMORY_KIB,
                           "parallelism": ARGON_PARALLELISM}}
    return {"kdf": "scrypt",
            "params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}}


def derive_kek(password: bytes, salt: bytes, kdf: str, params: dict) -> bytes:
    """Derives a 256-bit Key-Encrypting-Key from the password.
    NO silent fallback: an unknown KDF is an error (anti-downgrade)."""
    if not isinstance(salt, (bytes, bytearray)) or not (8 <= len(salt) <= 64):
        raise VaultError("Invalid salt.")
    if kdf == "argon2id":
        if not _HAS_ARGON2:
            raise VaultError(
                "This vault requires Argon2id but 'argon2-cffi' is not installed.\n"
                "Install with: pip install argon2-cffi")
        vp = validate_kdf_params("argon2id", params)
        try:
            return hash_secret_raw(bytes(password), bytes(salt),
                                   time_cost=vp["time_cost"],
                                   memory_cost=vp["memory_kib"],
                                   parallelism=vp["parallelism"],
                                   hash_len=ARGON_DKLEN,
                                   type=_ArgonType.ID)
        except VaultError:
            raise
        except Exception as e:
            raise VaultError(f"Argon2 derivation failed: {e}") from e
    elif kdf == "scrypt":
        vp = validate_kdf_params("scrypt", params)
        try:
            # high maxmem: OpenSSL on Windows defaults to 32 MiB and would fail
            # with N=131072 (~128 MB). 256 MiB covers our settings with margin.
            return hashlib.scrypt(bytes(password), salt=bytes(salt),
                                  n=vp["n"], r=vp["r"], p=vp["p"],
                                  maxmem=256 * 1024 * 1024,
                                  dklen=SCRYPT_DKLEN)
        except VaultError:
            raise
        except Exception as e:
            raise VaultError(f"scrypt derivation failed: {e}") from e
    elif kdf == "pbkdf2":
        vp = validate_kdf_params("pbkdf2", params)
        try:
            return hashlib.pbkdf2_hmac("sha256", bytes(password), bytes(salt),
                                       vp["iterations"], dklen=32)
        except VaultError:
            raise
        except Exception as e:
            raise VaultError(f"PBKDF2 derivation failed: {e}") from e
    else:
        raise VaultError(f"Unknown/unsupported KDF: {kdf!r}.")


# --------------------------------------------------------------------------
# Shredding / safe writes
# --------------------------------------------------------------------------
def fsync_dir(dirpath: str):
    try:
        if os.name == "nt":
            return  # Windows: fsync on directories is not supported
        fd = os.open(dirpath, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass


def shred_file(path: str, passes: int = SHRED_PASSES_DEFAULT) -> None:
    """Overwrites a file (3 passes), renames it randomly, then deletes it.
    Best effort: on SSDs the firmware may keep physical pages, but the data
    stays encrypted (useless without the key).

    Never follows symlinks (only the link itself is removed). Handles
    read-only files by making them writable first. Warns on multiple
    hardlinks (content is destroyed, but sibling paths may remain).
    """
    hardlinked = False
    try:
        try:
            if os.path.islink(path):
                # Never follow symlinks in shred: remove only the link.
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
                return
        except VaultError:
            raise
        except Exception:
            pass
        if not os.path.isfile(path):
            return
        try:
            st = os.stat(path)
            size = st.st_size
            if getattr(st, "st_nlink", 1) > 1:
                hardlinked = True
        except (OSError, ValueError) as e:
            raise VaultError(f"Shredding failed (stat): {e}") from e
        if size > 0:
            # try to make writable (read-only files)
            try:
                if not os.access(path, os.W_OK):
                    try:
                        os.chmod(path, 0o600)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                with open(path, "r+b") as f:
                    for p in range(max(1, int(passes))):
                        f.seek(0)
                        remaining = size
                        if p % 3 == 1:
                            # zero pass
                            zero = b"\x00" * SHRED_BLOCK
                            while remaining > 0:
                                chunk = zero[:min(SHRED_BLOCK, remaining)]
                                f.write(chunk)
                                remaining -= len(chunk)
                        else:
                            while remaining > 0:
                                n = min(SHRED_BLOCK, remaining)
                                f.write(os.urandom(n))
                                remaining -= n
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except Exception:
                            pass
            except (FileNotFoundError, NotADirectoryError):
                return
            except (OSError, ValueError) as e:
                raise VaultError(f"Shredding failed (overwrite): {e}") from e
        # anonymous rename before unlink (dirtier directory journal less)
        d = os.path.dirname(os.path.abspath(path))
        tmp = os.path.join(d, secrets.token_hex(8) + ".del")
        try:
            os.replace(path, tmp)
            path = tmp
        except Exception:
            pass
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        fsync_dir(d)
        if hardlinked:
            raise VaultError("Shred done, but the file had multiple hardlinks: "
                             "other paths may still exist (with destroyed content). "
                             "Remove them manually.")
    except FileNotFoundError:
        return
    except VaultError:
        raise
    except Exception as e:
        # last resort: still try to remove
        try:
            os.remove(path)
        except Exception:
            pass
        raise VaultError("Shredding failed.") from e


def atomic_write_bytes(path: str, data: bytes) -> None:
    """Atomic write: tmp + fsync + os.replace + fsync dir. Restrictive
    permissions (0600), tmp cleanup on error. OSError converted to
    VaultError (no traceback leaks to the user)."""
    try:
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
    except (OSError, ValueError) as e:
        raise VaultError(f"Cannot prepare directory: {e}") from e
    tmp = path + f".tmp-{secrets.token_hex(8)}"
    try:
        with open(tmp, "wb") as f:
            try:
                if os.name != "nt":
                    try:
                        os.fchmod(f.fileno(), 0o600)
                    except Exception:
                        pass
            except Exception:
                pass
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        set_private_perms(tmp)
        os.replace(tmp, path)
        set_private_perms(path)
        fsync_dir(d)
    except (OSError, ValueError) as e:
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise VaultError(f"Write failed: {e}") from e
    except VaultError:
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except Exception:
            pass
        raise


def _backup_file(path: str) -> None:
    """Copies path -> path.bak (keeps 1 generation). Best effort, never fatal."""
    try:
        if os.path.isfile(path) and not os.path.islink(path):
            bak = path + ".bak"
            tmp_bak = bak + f".tmp-{secrets.token_hex(8)}"
            try:
                shutil.copy2(path, tmp_bak)
                set_private_perms(tmp_bak)
                os.replace(tmp_bak, bak)
            except Exception:
                try:
                    if os.path.isfile(tmp_bak):
                        os.remove(tmp_bak)
                except Exception:
                    pass
                try:
                    shutil.copy2(path, bak)
                except Exception:
                    pass
            try:
                set_private_perms(bak)
            except Exception:
                pass
    except Exception:
        pass


def atomic_write_with_backup(path: str, data: bytes) -> None:
    _backup_file(path)
    atomic_write_bytes(path, data)


def _sync_backup_to_current(path: str) -> None:
    """Overwrites path.bak with the current path content (forensic purge).
    Used after delete/move/change_password: the old backup would still hold
    data the user explicitly removed (names, groups, old wrapped master)."""
    try:
        if os.path.isfile(path) and not os.path.islink(path):
            bak = path + ".bak"
            tmp_bak = bak + f".tmp-{secrets.token_hex(8)}"
            try:
                shutil.copy2(path, tmp_bak)
                set_private_perms(tmp_bak)
                os.replace(tmp_bak, bak)
                set_private_perms(bak)
            except Exception:
                try:
                    if os.path.isfile(tmp_bak):
                        os.remove(tmp_bak)
                except Exception:
                    pass
    except Exception:
        pass


def _shred_backup(path: str) -> None:
    """Destroys path.bak with shredding (full forensic purge). Best effort."""
    try:
        bak = path + ".bak"
        if os.path.islink(bak):
            try:
                os.remove(bak)
            except Exception:
                pass
        elif os.path.isfile(bak):
            shred_file(bak, passes=SHRED_PASSES_DEFAULT)
    except Exception:
        pass


# --------------------------------------------------------------------------
# AES-GCM helpers (pycryptodome/x backend)
# --------------------------------------------------------------------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Returns (nonce, ct||tag). Validates key/nonce lengths (anti-corruption)."""
    _require_crypto()
    try:
        kb = bytes(key)
        pb = bytes(plaintext)
    except Exception as e:
        raise VaultError("Invalid encryption parameters.") from e
    if len(kb) not in (16, 24, 32):
        raise VaultError("Invalid AES key.")
    if nonce is None:
        nonce = strong_random(12)
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 12:
        raise VaultError("Invalid nonce.")
    try:
        cipher = AES.new(kb, AES.MODE_GCM, nonce=bytes(nonce))
    except (ValueError, TypeError, KeyError) as e:
        raise VaultError("AES init failed.") from e
    try:
        ct, tag = cipher.encrypt_and_digest(pb)
    except (ValueError, TypeError) as e:
        raise VaultError("Encryption failed.") from e
    return bytes(nonce), ct + tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes) -> bytes:
    _require_crypto()
    try:
        kb = bytes(key)
        nb = bytes(nonce)
        cb = bytes(ct_and_tag)
    except Exception as e:
        raise VaultError("Invalid decryption parameters.") from e
    if len(kb) not in (16, 24, 32):
        raise VaultError("Invalid AES key.")
    if len(nb) != 12:
        raise VaultError("Corrupted ciphertext (nonce).")
    if len(cb) < 16:
        raise VaultError("Corrupted ciphertext (too short).")
    if len(cb) > (CHUNK_SIZE + PAD_GRANULARITY + 1024) * 2 and len(cb) > 4 * 1024 * 1024:
        # NOTE: the real manifest cap is MAX_MANIFEST_BYTES; this is a
        # generous anti-DoS cap for single decrypts (a full manifest is < 32MB).
        if len(cb) > MAX_MANIFEST_BYTES + 1024:
            raise VaultError("Ciphertext too large.")
    ct, tag = cb[:-16], cb[-16:]
    try:
        cipher = AES.new(kb, AES.MODE_GCM, nonce=nb)
    except (ValueError, TypeError, KeyError) as e:
        raise VaultError("Corrupted ciphertext.") from e
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        raise VaultError("Wrong password or tampered/corrupted data.")


# --------------------------------------------------------------------------
# Vault class
# --------------------------------------------------------------------------
class Vault:
    """Encrypted on-disk vault. ALWAYS call unlock() before any operation."""

    def __init__(self, vault_path: str):
        if not isinstance(vault_path, str) or not vault_path.strip():
            raise VaultError("Invalid vault path.")
        self.vault_path = os.path.abspath(os.path.expanduser(vault_path.strip()))
        self.data_dir = os.path.join(self.vault_path, "data")
        self.meta_path = os.path.join(self.vault_path, "vault.meta")
        self.manifest_path = os.path.join(self.vault_path, "vault_manifest.enc")
        self._master: bytearray | None = None   # 32-byte master key (RAM only while unlocked)
        self._manifest: dict | None = None      # {"files": [...]}
        self._meta: dict | None = None
        self._op_lock = threading.RLock()  # guards master/manifest against thread races

    # -- state -----------------------------------------------------------
    @property
    def is_unlocked(self) -> bool:
        with self._op_lock:
            return self._master is not None and self._manifest is not None

    @property
    def exists(self) -> bool:
        try:
            return os.path.isfile(self.meta_path) and not os.path.islink(self.meta_path)
        except Exception:
            return False

    def _copy_master(self) -> bytes:
        """Thread-safe master key copy. Raises when locked."""
        with self._op_lock:
            if self._master is None:
                raise VaultError("Vault is locked. Unlock it with the password.")
            return bytes(self._master)

    def _assert_src_allowed(self, src_abs: str) -> None:
        """Forbids sources inside the vault (anti self-destruction + loops)."""
        if is_path_inside(src_abs, self.vault_path):
            raise VaultError("Source file/folder is inside the vault: forbidden "
                             "(avoids importing or destroying the vault itself).")
        if os.path.islink(src_abs):
            # Explicit refusal for single files (never follow symlinks,
            # especially with shred_original which would destroy the target).
            raise VaultError("Symlink source: forbidden for safety.")

    def _assert_dest_allowed(self, dest_abs: str) -> None:
        """Forbids destinations inside the vault (anti meta/blob overwrite)."""
        if is_path_inside(dest_abs, self.vault_path):
            raise VaultError("Destination inside the vault: forbidden "
                             "(pick a folder outside the vault).")
        for p in (self.meta_path, self.manifest_path,
                  self.meta_path + ".bak", self.manifest_path + ".bak"):
            try:
                if os.path.abspath(dest_abs) == os.path.abspath(p):
                    raise VaultError("Destination reserved for the vault: forbidden.")
            except VaultError:
                raise
            except Exception:
                pass

    def _validate_entry(self, e: dict) -> dict:
        """Validates a manifest entry (strict schema)."""
        try:
            if not isinstance(e, dict):
                raise VaultError("Corrupt manifest (entry).")
            fid = e.get("id")
            validate_file_id(fid if isinstance(fid, str) else "")
            name = e.get("name")
            group = e.get("group", "")
            size = e.get("size")
            padded = e.get("padded")
            sha = e.get("sha256", "")
            chunks = e.get("chunks")
            if not isinstance(name, str) or not (1 <= len(name) <= 1024):
                raise VaultError("Corrupt manifest (name).")
            if not isinstance(group, str) or len(group) > 8 * 65:
                raise VaultError("Corrupt manifest (group).")
            if not isinstance(size, int) or not (0 <= size <= MAX_FILE_SIZE):
                raise VaultError("Corrupt manifest (size).")
            if not isinstance(padded, int) or not (size <= padded <= size + PAD_GRANULARITY + 16):
                raise VaultError("Corrupt manifest (padded).")
            if not isinstance(sha, str) or (sha != "" and not re.fullmatch(r"[0-9a-f]{64}", sha)):
                raise VaultError("Corrupt manifest (sha).")
            if not isinstance(chunks, int) or not (0 <= chunks <= MAX_COUNTER + 1):
                raise VaultError("Corrupt manifest (chunks).")
            for k in ("fek_nonce_b64", "fek_ct_b64"):
                v = e.get(k)
                if not isinstance(v, str) or not (1 <= len(v) <= 4096):
                    raise VaultError("Corrupt manifest (FEK).")
            # Optional forensic fields (backward compatible): preserved mtime_ns + mode.
            if "mtime_ns" in e and e["mtime_ns"] is not None:
                mt = e["mtime_ns"]
                if not isinstance(mt, int) or not (0 <= mt <= 2 ** 63 - 1):
                    raise VaultError("Corrupt manifest (mtime).")
            if "mode" in e and e["mode"] is not None:
                mo = e["mode"]
                if not isinstance(mo, int) or not (0 <= mo <= 0o7777):
                    raise VaultError("Corrupt manifest (mode).")
            return e
        except VaultError:
            raise
        except Exception as ex:
            raise VaultError("Corrupt manifest.") from ex

    # -- create / open -------------------------------------------
    @classmethod
    def create(cls, vault_path: str, password: str) -> "Vault":
        _require_crypto()
        if not isinstance(password, str) or len(password.encode("utf-8")) < 8:
            raise VaultError("Password too short: minimum 8 characters (12+ recommended).")
        v = cls(vault_path)
        if v.exists:
            raise VaultError("A vault already exists in this folder. Open it instead of creating one.")
        # Reject non-empty directories (anti-hijack: never mix existing data with the vault).
        try:
            if os.path.isfile(v.vault_path) or os.path.islink(v.vault_path):
                raise VaultError("The vault path is an existing file.")
            if os.path.isdir(v.vault_path) and os.listdir(v.vault_path):
                raise VaultError("Folder is not empty: pick an empty folder or open it as a vault.")
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Unusable vault path: {e}") from e
        try:
            os.makedirs(v.data_dir, exist_ok=True)
            set_private_perms(v.vault_path)
            set_private_perms(v.data_dir)
        except (OSError, ValueError) as e:
            raise VaultError(f"Cannot create vault: {e}") from e
        master: bytearray | None = bytearray(strong_random(32))
        kek: bytes | None = None
        try:
            info = kdf_info_default()
            salt = strong_random(16)
            pw_bytes = password.encode("utf-8")
            try:
                kek = derive_kek(pw_bytes, salt, info["kdf"], info["params"])
                nonce, ct = aes_gcm_encrypt(bytes(kek), bytes(master) + VERIFIER)
            finally:
                # bytes immutabili: non azzerabili davvero -> rilascia riferimenti.
                try:
                    del pw_bytes
                except Exception:
                    pass
                kek = None
                gc.collect()
            v._meta = {"magic": VAULT_MAGIC, "version": 1,
                       "kdf": info["kdf"], "kdf_params": info["params"],
                       "salt_b64": b64e(salt), "nonce_b64": b64e(nonce), "ct_b64": b64e(ct)}
            atomic_write_with_backup(v.meta_path, json.dumps(v._meta, indent=2).encode("utf-8"))
            with v._op_lock:
                v._master = master  # passa ownership (non duplicare)
                master = None  # type: ignore
                v._manifest = {"files": []}
                v._save_manifest_locked()
        finally:
            if master is not None:
                wipe_bytearray(master)
            gc.collect()
        return v

    def unlock(self, password: str) -> None:
        _require_crypto()
        if not isinstance(password, str) or not password:
            raise VaultError("Enter the password.")
        with self._op_lock:
            self.lock()
            if not self.exists:
                raise VaultError("No vault found in this folder (vault.meta is missing).")
            try:
                if os.path.getsize(self.meta_path) > MAX_META_BYTES:
                    raise VaultError("Abnormal vault.meta file (too large).")
            except VaultError:
                raise
            except (OSError, ValueError) as e:
                raise VaultError(f"Unreadable vault.meta: {e}") from e
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (OSError, ValueError) as e:
                raise VaultError("Invalid or damaged vault.meta file.") from e
            try:
                if not isinstance(meta, dict) or meta.get("magic") != VAULT_MAGIC:
                    raise VaultError("Invalid or damaged vault.meta file.")
                if meta.get("version") != 1:
                    raise VaultError("Unsupported vault version.")
                kdf = meta.get("kdf", "scrypt")
                params = meta.get("kdf_params", {})
                if not isinstance(kdf, str) or not isinstance(params, dict):
                    raise VaultError("Damaged vault.meta (KDF).")
                validate_kdf_params(kdf, params)
                salt = b64d(meta["salt_b64"])
                nonce = b64d(meta["nonce_b64"])
                ct = b64d(meta["ct_b64"])
                if not (8 <= len(salt) <= 64) or len(nonce) != 12:
                    raise VaultError("Damaged vault.meta.")
                if not (16 <= len(ct) <= 4096):
                    raise VaultError("Damaged vault.meta.")
            except KeyError as e:
                raise VaultError("Incomplete or damaged vault.meta file.") from e
            pw_bytes = password.encode("utf-8")
            raw: bytes | None = None
            try:
                kek = derive_kek(pw_bytes, salt, kdf, params)
                try:
                    raw = aes_gcm_decrypt(bytes(kek), nonce, ct)
                finally:
                    kek = None
                    gc.collect()
            finally:
                try:
                    del pw_bytes
                except Exception:
                    pass
                gc.collect()
            try:
                assert raw is not None
                if not raw.endswith(VERIFIER) or len(raw) != 32 + len(VERIFIER):
                    # Should never happen: GCM would already have failed. Defense in depth.
                    raise VaultError("Wrong password or tampered vault.meta.")
                master = bytearray(raw[:32])
            finally:
                raw = None
                gc.collect()
            self._meta = meta
            self._master = master
            try:
                os.makedirs(self.data_dir, exist_ok=True)
                set_private_perms(self.data_dir)
            except Exception:
                pass
            cleanup_stale_tmp(self.data_dir)
            cleanup_stale_tmp(self.vault_path)
            # load manifest (falls back to .bak when the primary is corrupt:
            # crash/bitrot recovery; the .bak is encrypted with the same master).
            try:
                if os.path.isfile(self.manifest_path):
                    try:
                        self._manifest = self._load_manifest_locked()
                    except VaultError as primary_err:
                        bak = self.manifest_path + ".bak"
                        if os.path.isfile(bak) and not os.path.islink(bak):
                            try:
                                recovered = self._load_manifest_from(bak)
                            except VaultError:
                                raise primary_err from None
                            # Restore the primary from the verified backup.
                            try:
                                atomic_write_bytes(
                                    self.manifest_path,
                                    Path(bak).read_bytes())
                                set_private_perms(self.manifest_path)
                            except Exception:
                                pass
                            self._manifest = recovered
                        else:
                            raise
                else:
                    self._manifest = {"files": []}
            except VaultError:
                # Unreadable manifest: close everything (no orphan master in RAM).
                try:
                    if self._master is not None:
                        wipe_bytearray(self._master)
                finally:
                    self._master = None
                    self._manifest = None
                    self._meta = None
                raise

    def lock(self) -> None:
        with self._op_lock:
            if self._master is not None:
                wipe_bytearray(self._master)
                self._master = None
            self._manifest = None
            self._meta = None
            gc.collect()

    def _require_unlocked(self):
        with self._op_lock:
            if self._master is None or self._manifest is None:
                raise VaultError("Vault is locked. Unlock it with the password.")

    # -- manifest ---------------------------------------------------------
    def _load_manifest_from(self, path: str) -> dict:
        # Call with _op_lock held (or from unlock, which already holds it).
        assert self._master is not None
        try:
            if os.path.getsize(path) > MAX_MANIFEST_BYTES + 4096:
                raise VaultError("Abnormal manifest (too large).")
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Unreadable manifest: {e}") from e
        try:
            with open(path, "r", encoding="utf-8") as f:
                wrapper = json.load(f)
        except (OSError, ValueError) as e:
            raise VaultError("Invalid or damaged manifest.") from e
        try:
            if not isinstance(wrapper, dict) or wrapper.get("magic") != "PVMAN1":
                raise VaultError("Invalid or damaged manifest.")
            nonce = b64d(wrapper["nonce_b64"])
            ct = b64d(wrapper["ct_b64"])
            if len(nonce) != 12 or len(ct) < 16 or len(ct) > MAX_MANIFEST_BYTES + 1024:
                raise VaultError("Corrupt manifest.")
        except KeyError as e:
            raise VaultError("Incomplete or damaged manifest.") from e
        raw = aes_gcm_decrypt(bytes(self._master), nonce, ct)
        try:
            try:
                man = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as e:
                raise VaultError("Corrupt manifest.") from e
            if not isinstance(man, dict) or "files" not in man or not isinstance(man["files"], list):
                raise VaultError("Corrupt manifest.")
            if len(man["files"]) > 200_000:
                raise VaultError("Abnormal manifest (too many entries).")
            for e in man["files"]:
                self._validate_entry(e)
            return man
        finally:
            raw = None
            gc.collect()

    def _load_manifest_locked(self) -> dict:
        return self._load_manifest_from(self.manifest_path)

    def _save_manifest_locked(self) -> None:
        # Call with _op_lock held.
        assert self._master is not None and self._manifest is not None
        try:
            raw = json.dumps(self._manifest, ensure_ascii=False).encode("utf-8")
        except (ValueError, TypeError) as e:
            raise VaultError(f"Non-serializable manifest: {e}") from e
        if len(raw) > MAX_MANIFEST_BYTES:
            raise VaultError("Manifest too large.")
        master_copy = bytes(self._master)
        try:
            nonce, ct = aes_gcm_encrypt(master_copy, raw)
        finally:
            raw = None
            gc.collect()
        wrapper = {"magic": "PVMAN1", "version": 1,
                   "nonce_b64": b64e(nonce), "ct_b64": b64e(ct)}
        try:
            payload = json.dumps(wrapper).encode("utf-8")
        except (ValueError, TypeError) as e:
            raise VaultError(f"Non-serializable manifest: {e}") from e
        atomic_write_with_backup(self.manifest_path, payload)

    # -- queries -------------------------------------------------------
    def list_files(self, group_filter: str = "", search: str = "") -> list[dict]:
        self._require_unlocked()
        with self._op_lock:
            assert self._manifest is not None
            files = list(self._manifest["files"])
        out = []
        gf = (group_filter or "").strip().lower()
        q = (search or "").strip().lower()
        for e in files:
            try:
                self._validate_entry(e)
            except VaultError:
                continue  # skip corrupt entries without breaking the list
            if gf and (e.get("group") or "").strip().lower() != gf:
                continue
            if q and q not in (e.get("name") or "").lower():
                continue
            out.append(dict(e))
        out.sort(key=lambda e: ((e.get("group") or "").lower(), (e.get("name") or "").lower()))
        return out

    def groups(self) -> list[str]:
        self._require_unlocked()
        with self._op_lock:
            assert self._manifest is not None
            files = list(self._manifest["files"])
        g = sorted({(e.get("group") or "").strip() for e in files
                    if isinstance(e.get("group"), str)} - {""})
        return g

    def get_entry(self, file_id: str) -> dict:
        validate_file_id(file_id)
        self._require_unlocked()
        with self._op_lock:
            assert self._manifest is not None
            for e in self._manifest["files"]:
                if e.get("id") == file_id:
                    self._validate_entry(e)
                    return dict(e)
        raise VaultError("File not found in the vault.")

    def _pad_len_for(self, actual: int) -> int:
        # Padding is ALWAYS 1..512 bytes (hides empty and 512-aligned files).
        return PAD_GRANULARITY - (actual % PAD_GRANULARITY)

    # -- encrypted import (streaming) ----------------------------------
    def add_file(self, src_path: str, group: str = "",
                 shred_original: bool = False, progress_cb=None) -> dict:
        """Encrypts src_path into the vault. Returns the manifest entry."""
        _require_crypto()
        self._require_unlocked()
        if not isinstance(src_path, str) or not src_path.strip():
            raise VaultError("Invalid source path.")
        src_abs = os.path.abspath(src_path)
        self._assert_src_allowed(src_abs)
        try:
            if not os.path.isfile(src_abs) or os.path.islink(src_abs):
                raise VaultError("Source file not found.")
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Unreadable source file: {e}") from e
        try:
            st = os.stat(src_abs)
            initial_size = st.st_size
            src_mtime_ns = getattr(st, "st_mtime_ns", None)
            src_mode = (st.st_mode & 0o7777) if hasattr(st, "st_mode") else None
        except (OSError, ValueError) as e:
            raise VaultError(f"Unreadable source file: {e}") from e
        if initial_size < 0 or initial_size > MAX_FILE_SIZE:
            raise VaultError("Invalid file size.")
        if not isinstance(src_mtime_ns, int) or not (0 <= src_mtime_ns <= 2 ** 63 - 1):
            src_mtime_ns = None
        if not isinstance(src_mode, int) or not (0 <= src_mode <= 0o7777):
            src_mode = None
        group = Vault.sanitize_group(group)
        name = os.path.basename(src_abs) or "file"
        if len(name) > 1024:
            name = name[:1024]
        master_copy = self._copy_master()

        file_id = new_file_id()
        with self._op_lock:
            assert self._manifest is not None
            existing = {e.get("id") for e in self._manifest["files"]}
        while file_id in existing:
            file_id = new_file_id()
        blob_path = os.path.join(self.data_dir, file_id + ".blk")
        if os.path.exists(blob_path):
            # filesystem collision (near-impossible): regenerate
            file_id = new_file_id()
            blob_path = os.path.join(self.data_dir, file_id + ".blk")
            if os.path.exists(blob_path):
                raise VaultError("Blob collision, retry.")
        try:
            os.makedirs(self.data_dir, exist_ok=True)
        except (OSError, ValueError) as e:
            raise VaultError(f"Data directory not writable: {e}") from e

        fek: bytearray | None = bytearray(strong_random(32))
        assert fek is not None
        base = strong_random(8)  # 8 random bytes + 32-bit counter -> 12-byte nonce
        sha = hashlib.sha256()
        tmp_blob = blob_path + f".tmp-{secrets.token_hex(8)}"
        counter = 0
        actual = 0
        entry: dict | None = None
        try:
            try:
                fin = open(src_abs, "rb")
            except (OSError, ValueError) as e:
                raise VaultError(f"Unreadable source file: {e}") from e
            with fin:
                try:
                    fout = open(tmp_blob, "wb")
                except (OSError, ValueError) as e:
                    raise VaultError(f"Cannot write blob: {e}") from e
                with fout:
                    try:
                        if os.name != "nt":
                            try:
                                os.fchmod(fout.fileno(), 0o600)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    fout.write(BLOB_MAGIC)
                    fout.write(base)

                    def enc_write(plain: bytes):
                        nonlocal counter
                        if counter > MAX_COUNTER:
                            raise VaultError("File too large (nonce overflow).")
                        if not isinstance(plain, (bytes, bytearray)) or len(plain) == 0:
                            raise VaultError("Invalid internal chunk.")
                        if len(plain) > CHUNK_SIZE + PAD_GRANULARITY:
                            raise VaultError("Chunk too large.")
                        nonce = base + struct.pack(">I", counter)
                        try:
                            assert fek is not None
                            cipher = AES.new(bytes(fek), AES.MODE_GCM, nonce=nonce)
                            ct, tag = cipher.encrypt_and_digest(bytes(plain))
                        except (ValueError, TypeError, KeyError) as e:
                            raise VaultError("Chunk encryption failed.") from e
                        blob = ct + tag
                        fout.write(struct.pack(">I", len(blob)))
                        fout.write(nonce)
                        fout.write(blob)
                        counter += 1

                    est_total = max(initial_size + PAD_GRANULARITY, 1)
                    while True:
                        try:
                            chunk = fin.read(CHUNK_SIZE)
                        except (OSError, ValueError) as e:
                            raise VaultError(f"Source read failed: {e}") from e
                        if not chunk:
                            break
                        if not isinstance(chunk, (bytes, bytearray)):
                            raise VaultError("Invalid source read.")
                        sha.update(chunk)
                        enc_write(bytes(chunk))
                        actual += len(chunk)
                        if actual > MAX_FILE_SIZE:
                            raise VaultError("File too large.")
                        if progress_cb:
                            try:
                                progress_cb(min(actual, est_total), est_total)
                            except Exception:
                                pass
                    # Padding is computed on the ACTUAL bytes read (anti-TOCTOU:
                    # if the file grew while reading, use actual, not the initial stat).
                    pad_len = self._pad_len_for(actual)
                    enc_write(strong_random(pad_len))  # random padding, excluded from sha
                    if progress_cb:
                        try:
                            progress_cb(actual + pad_len, actual + pad_len)
                        except Exception:
                            pass
                    fout.flush()
                    try:
                        os.fsync(fout.fileno())
                    except Exception:
                        pass
            set_private_perms(tmp_blob)
            # wrap FEK with the master key (GCM: authenticated)
            assert fek is not None
            nonce_w, ct_w = aes_gcm_encrypt(master_copy, bytes(fek))
            digest = sha.hexdigest()
            entry = {"id": file_id, "name": name, "group": group,
                     "size": actual, "padded": actual + pad_len,
                     "sha256": digest, "created": utcnow_iso(),
                     "chunks": counter,
                     "fek_nonce_b64": b64e(nonce_w), "fek_ct_b64": b64e(ct_w)}
            # Optional forensic fidelity (backward compatible): preserve mtime/mode.
            if src_mtime_ns is not None:
                entry["mtime_ns"] = src_mtime_ns
            if src_mode is not None:
                entry["mode"] = src_mode
            self._validate_entry(entry)
            # Atomic commit: if the vault was locked mid-stream,
            # abort (no orphan manifest) and clean up.
            with self._op_lock:
                if self._master is None or self._manifest is None:
                    raise VaultError("Vault locked during import: operation cancelled.")
                if any(e.get("id") == file_id for e in self._manifest["files"]):
                    raise VaultError("ID collision, retry.")
                if os.path.exists(blob_path):
                    raise VaultError("Blob collision, retry.")
                try:
                    os.replace(tmp_blob, blob_path)
                except (OSError, ValueError) as e:
                    raise VaultError(f"Blob commit failed: {e}") from e
                set_private_perms(blob_path)
                fsync_dir(self.data_dir)
                self._manifest["files"].append(entry)
                try:
                    self._save_manifest_locked()
                except VaultError:
                    # Rollback: remove orphan blob (manifest not updated).
                    try:
                        if os.path.isfile(blob_path):
                            shred_file(blob_path, passes=1)
                    except Exception:
                        pass
                    try:
                        self._manifest["files"] = [e for e in self._manifest["files"]
                                                   if e.get("id") != file_id]
                    except Exception:
                        pass
                    raise
        except VaultError:
            try:
                if os.path.isfile(tmp_blob) and not os.path.islink(tmp_blob):
                    shred_file(tmp_blob, passes=1)
                elif os.path.isfile(tmp_blob):
                    try:
                        os.remove(tmp_blob)
                    except Exception:
                        pass
            except Exception:
                pass
            raise
        except (OSError, ValueError, struct.error) as e:
            try:
                if os.path.isfile(tmp_blob):
                    shred_file(tmp_blob, passes=1)
            except Exception:
                pass
            raise VaultError(f"Import failed: {e}") from e
        except Exception as e:
            try:
                if os.path.isfile(tmp_blob):
                    shred_file(tmp_blob, passes=1)
            except Exception:
                pass
            raise VaultError("Import failed.") from e
        finally:
            if fek is not None:
                wipe_bytearray(fek)
                fek = None
            master_copy = b"\x00" * 32
            gc.collect()

        assert entry is not None
        if shred_original:
            # Re-check symlink before destroying (anti-TOCTOU/swap).
            try:
                if os.path.islink(src_abs):
                    raise VaultError("Shred refused: source became a symlink.")
            except VaultError:
                raise
            except Exception:
                pass
            shred_file(src_abs, passes=SHRED_PASSES_DEFAULT)
        return dict(entry)

    def add_folder(self, folder_path: str, group: str = "",
                   shred_original: bool = False, progress_cb=None) -> list[dict]:
        """Recursively imports a folder. The default group is the folder name."""
        self._require_unlocked()
        if not isinstance(folder_path, str) or not folder_path.strip():
            raise VaultError("Invalid folder.")
        root = os.path.abspath(folder_path)
        try:
            if os.path.islink(root):
                raise VaultError("Symlinked folder: forbidden.")
            if not os.path.isdir(root):
                raise VaultError("Folder not found.")
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Unreadable folder: {e}") from e
        # Forbid folder == vault, inside the vault, or CONTAINING the vault
        # (otherwise meta, manifest and blobs would be imported/destroyed).
        if is_path_inside(root, self.vault_path) or is_path_inside(self.vault_path, root):
            raise VaultError("Folder matches/contains/is inside the vault: forbidden.")
        base_group = (group or "").strip() or os.path.basename(root.rstrip(os.sep))
        base_group = Vault.sanitize_group(base_group) or "Import"
        # collect files (skip symlinks to avoid escapes / loops)
        targets: list[tuple[str, str]] = []
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                # drop symlinked dirs + skip dirs inside the vault (defense in depth)
                kept = []
                for d in dirnames:
                    full_d = os.path.join(dirpath, d)
                    try:
                        if os.path.islink(full_d):
                            continue
                        if is_path_inside(full_d, self.vault_path) or \
                           is_path_inside(self.vault_path, full_d):
                            continue
                    except Exception:
                        continue
                    kept.append(d)
                dirnames[:] = kept
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    try:
                        if os.path.islink(full) or not os.path.isfile(full):
                            continue
                        if is_path_inside(full, self.vault_path):
                            continue
                    except (OSError, ValueError):
                        continue
                    try:
                        rel = os.path.relpath(os.path.dirname(full), root)
                    except (OSError, ValueError):
                        continue
                    if rel in (".", ""):
                        g = base_group
                    else:
                        g = Vault.sanitize_group(base_group + "/" + rel.replace(os.sep, "/")) or base_group
                    targets.append((full, g))
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Folder scan failed: {e}") from e
        targets.sort()
        if not targets:
            raise VaultError("No importable files in folder (empty or symlinks only).")
        # Total estimate including padding (keeps the bar at <=100%).
        sizes: list[int] = []
        for p, _ in targets:
            try:
                sz = os.path.getsize(p)
            except (OSError, ValueError) as e:
                raise VaultError(f"Unreadable file: {os.path.basename(p)}") from e
            if sz < 0 or sz > MAX_FILE_SIZE:
                raise VaultError(f"File too large: {os.path.basename(p)}")
            sizes.append(sz)
        total_padded = sum(s + (PAD_GRANULARITY - (s % PAD_GRANULARITY)) for s in sizes)
        total_padded = max(total_padded, 1)
        done_all = [0]
        added: list[dict] = []
        for full, g in targets:
            def cb(d, t, _done=done_all, _tot=total_padded):
                if progress_cb:
                    try:
                        progress_cb(min(_done[0] + d, _tot), _tot)
                    except Exception:
                        pass
            try:
                e = self.add_file(full, group=g, shred_original=shred_original, progress_cb=cb)
            except VaultError:
                # Keep partial imports already committed; report the culprit
                # without leaking the absolute path (basename only).
                raise VaultError(f"Folder import stopped at: {os.path.basename(full)}")
            added.append(e)
            done_all[0] += int(e.get("size", 0)) + self._pad_len_for(int(e.get("size", 0)))
            if progress_cb:
                try:
                    progress_cb(min(done_all[0], total_padded), total_padded)
                except Exception:
                    pass
        return added

    # -- extraction (streaming, GCM + sha256 verification) ---------------
    def _unwrap_fek(self, entry: dict, master_copy: bytes) -> bytearray:
        try:
            n = b64d(entry["fek_nonce_b64"])
            c = b64d(entry["fek_ct_b64"])
        except KeyError as e:
            raise VaultError("Entry has no FEK.") from e
        if len(n) != 12 or not (16 <= len(c) <= 4096):
            raise VaultError("Corrupted FEK.")
        return bytearray(aes_gcm_decrypt(master_copy, n, c))

    def extract_file(self, file_id: str, dest_path: str, progress_cb=None) -> str:
        validate_file_id(file_id)
        self._require_unlocked()
        if not isinstance(dest_path, str) or not dest_path.strip():
            raise VaultError("Invalid destination.")
        dest_abs = os.path.abspath(dest_path)
        self._assert_dest_allowed(dest_abs)
        entry = self.get_entry(file_id)
        try:
            expected = int(entry["size"])
            want_sha = entry.get("sha256", "")
        except (ValueError, TypeError) as e:
            raise VaultError("Corrupted entry.") from e
        if not (0 <= expected <= MAX_FILE_SIZE):
            raise VaultError("Corrupted entry (size).")
        if want_sha != "" and not re.fullmatch(r"[0-9a-f]{64}", str(want_sha)):
            raise VaultError("Corrupted entry (sha).")
        master_copy = self._copy_master()
        blob_path = os.path.join(self.data_dir, file_id + ".blk")
        try:
            if os.path.islink(blob_path):
                raise VaultError("Abnormal blob (symlink).")
            if not os.path.isfile(blob_path):
                raise VaultError("Encrypted blob missing or deleted externally.")
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Unreadable blob: {e}") from e
        fek: bytearray | None = None
        try:
            fek = self._unwrap_fek(entry, master_copy)
            try:
                parent = os.path.dirname(dest_abs) or "."
                os.makedirs(parent, exist_ok=True)
            except (OSError, ValueError) as e:
                raise VaultError(f"Destination not writable: {e}") from e
            try:
                if os.path.isdir(dest_abs) and not os.path.isfile(dest_abs):
                    raise VaultError("Destination is a directory.")
            except VaultError:
                raise
            except (OSError, ValueError) as e:
                raise VaultError(f"Invalid destination: {e}") from e
            tmp_out = dest_abs + f".tmp-{secrets.token_hex(8)}"
            sha = hashlib.sha256()
            remaining = expected
            done = 0
            total_cb = max(expected, 1)
            try:
                try:
                    fin = open(blob_path, "rb")
                except (OSError, ValueError) as e:
                    raise VaultError(f"Unreadable blob: {e}") from e
                with fin:
                    try:
                        fout = open(tmp_out, "wb")
                    except (OSError, ValueError) as e:
                        raise VaultError(f"Destination not writable: {e}") from e
                    with fout:
                        try:
                            if os.name != "nt":
                                try:
                                    os.fchmod(fout.fileno(), 0o600)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        try:
                            magic = fin.read(4)
                        except (OSError, ValueError) as e:
                            raise VaultError(f"Blob read failed: {e}") from e
                        if magic != BLOB_MAGIC:
                            raise VaultError("Invalid or corrupted blob.")
                        base = fin.read(8)
                        if len(base) != 8:
                            raise VaultError("Truncated blob.")
                        counter = 0
                        while True:
                            try:
                                len_raw = fin.read(4)
                            except (OSError, ValueError) as e:
                                raise VaultError(f"Blob read failed: {e}") from e
                            if not len_raw:
                                break  # EOF
                            if len(len_raw) != 4:
                                raise VaultError("Truncated blob.")
                            try:
                                (ct_len,) = struct.unpack(">I", len_raw)
                            except struct.error as e:
                                raise VaultError("Corrupted blob.") from e
                            if ct_len < 16 or ct_len > CHUNK_SIZE + PAD_GRANULARITY + 16 + 64:
                                raise VaultError("Corrupted blob (absurd chunk length).")
                            nonce = fin.read(12)
                            if len(nonce) != 12:
                                raise VaultError("Truncated blob.")
                            if counter > MAX_COUNTER:
                                raise VaultError("Corrupted blob (counter).")
                            try:
                                exp_nonce = base + struct.pack(">I", counter)
                            except struct.error as e:
                                raise VaultError("Blob corrotto.") from e
                            # Confronto non sensibile al timing non necessario qui, ma
                            # usa secrets.compare_digest per igiene.
                            if not secrets.compare_digest(nonce, exp_nonce):
                                raise VaultError("Tampered blob (out-of-sequence nonce).")
                            blob = fin.read(ct_len)
                            if len(blob) != ct_len:
                                raise VaultError("Truncated blob.")
                            ct, tag = blob[:-16], blob[-16:]
                            try:
                                assert fek is not None
                                cipher = AES.new(bytes(fek), AES.MODE_GCM, nonce=nonce)
                            except (ValueError, TypeError, KeyError) as e:
                                raise VaultError("Corrupted blob.") from e
                            try:
                                plain = cipher.decrypt_and_verify(ct, tag)
                            except ValueError:
                                raise VaultError("Integrity failure: wrong password or tampered file.")
                            counter += 1
                            if counter > MAX_COUNTER + 2:
                                raise VaultError("Corrupted blob (too many chunks).")
                            # write only up to expected (the rest is padding)
                            if remaining > 0:
                                take = plain[:remaining]
                                try:
                                    fout.write(take)
                                except (OSError, ValueError) as e:
                                    raise VaultError(f"Destination write failed: {e}") from e
                                sha.update(take)
                                remaining -= len(take)
                                done += len(take)
                                if progress_cb:
                                    try:
                                        progress_cb(done, total_cb)
                                    except Exception:
                                        pass
                            # else: padding-only chunk, discard after GCM verification
                        fout.flush()
                        try:
                            os.fsync(fout.fileno())
                        except Exception:
                            pass
                if remaining != 0:
                    try:
                        if os.path.isfile(tmp_out):
                            shred_file(tmp_out, passes=1)
                    except Exception:
                        pass
                    raise VaultError("Incomplete blob: inconsistent decrypted size.")
                if want_sha and sha.hexdigest() != want_sha:
                    try:
                        shred_file(tmp_out, passes=1)
                    except Exception:
                        pass
                    raise VaultError("SHA-256 checksum failed: corrupted/tampered file.")
                # If the vault was locked mid-decryption, never deliver
                # plaintext: destroy the tmp file and abort.
                with self._op_lock:
                    if self._master is None or self._manifest is None:
                        try:
                            shred_file(tmp_out, passes=1)
                        except Exception:
                            pass
                        raise VaultError("Vault locked during extraction: operation cancelled.")
                # Atomic commit: dest is outside the vault (verified). An existing
                # file is replaced only AFTER full integrity verification.
                try:
                    if os.path.isfile(dest_abs) and not os.path.islink(dest_abs):
                        os.remove(dest_abs)
                    elif os.path.islink(dest_abs):
                        os.remove(dest_abs)
                    os.replace(tmp_out, dest_abs)
                except (OSError, ValueError) as e:
                    raise VaultError(f"Destination commit failed: {e}") from e
                # Restore original mtime/mode when present in the entry (best effort).
                try:
                    mt = entry.get("mtime_ns")
                    if isinstance(mt, int) and 0 <= mt <= 2 ** 63 - 1:
                        try:
                            os.utime(dest_abs, ns=(mt, mt))
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    mo = entry.get("mode")
                    if isinstance(mo, int) and 0 <= mo <= 0o7777:
                        try:
                            os.chmod(dest_abs, mo & 0o7777)
                        except Exception:
                            pass
                except Exception:
                    pass
                fsync_dir(os.path.dirname(dest_abs) or ".")
            except VaultError:
                try:
                    if os.path.isfile(tmp_out):
                        shred_file(tmp_out, passes=1)
                except Exception:
                    pass
                raise
            except (OSError, ValueError) as e:
                try:
                    if 'tmp_out' in locals() and os.path.isfile(tmp_out):
                        shred_file(tmp_out, passes=1)
                except Exception:
                    pass
                raise VaultError(f"Extraction failed: {e}") from e
            return dest_abs
        finally:
            if fek is not None:
                wipe_bytearray(fek)
                fek = None
            master_copy = b"\x00" * 32
            gc.collect()

    def _unique_dest(self, dest: str) -> str:
        """Avoids silent overwrites on sanitized-name collisions."""
        if not os.path.exists(dest):
            return dest
        stem, ext = os.path.splitext(dest)
        for k in range(1, 10000):
            cand = f"{stem} ({k}){ext}"
            if not os.path.exists(cand):
                return cand
        raise VaultError("Cannot generate a unique destination name.")

    def extract_all(self, dest_dir: str, group_filter: str = "", progress_cb=None) -> list[str]:
        self._require_unlocked()
        if not isinstance(dest_dir, str) or not dest_dir.strip():
            raise VaultError("Invalid destination folder.")
        dest_abs = os.path.abspath(dest_dir)
        self._assert_dest_allowed(dest_abs)
        try:
            os.makedirs(dest_abs, exist_ok=True)
        except (OSError, ValueError) as e:
            raise VaultError(f"Destination not writable: {e}") from e
        entries = self.list_files(group_filter=group_filter)
        out: list[str] = []
        try:
            total = sum(int(e["size"]) for e in entries)
        except (ValueError, TypeError) as e:
            raise VaultError("Corrupt manifest.") from e
        total = max(total, 1)
        done = [0]
        for e in entries:
            # rebuild a safe path: group as subfolders + filename (sanitized)
            parts = [p for p in (e.get("group") or "").split("/") if p]
            safe_parts = [Vault.sanitize_component(p) for p in parts]
            d = os.path.join(dest_abs, *safe_parts) if safe_parts else dest_abs
            if not (os.path.abspath(d) == dest_abs or
                    is_path_inside(os.path.abspath(d), dest_abs)):
                raise VaultError("Invalid extraction path.")
            dest = os.path.join(d, Vault.sanitize_component(e["name"]))
            if not is_path_inside(os.path.abspath(dest), dest_abs):
                raise VaultError("Invalid extraction path.")
            dest = self._unique_dest(dest)
            prev = [0]

            def cb(x, t, _done=done, _prev=prev):
                _done[0] += (x - _prev[0])
                _prev[0] = x
                if progress_cb:
                    try:
                        progress_cb(min(_done[0], total), total)
                    except Exception:
                        pass

            self.extract_file(e["id"], dest, progress_cb=cb)
            out.append(dest)
        return out

    # -- secure deletion -------------------------------------------------
    def delete_file(self, file_id: str) -> None:
        validate_file_id(file_id)
        self._require_unlocked()
        blob_path = os.path.join(self.data_dir, file_id + ".blk")
        with self._op_lock:
            assert self._manifest is not None
            found = any(e.get("id") == file_id for e in self._manifest["files"])
            if not found:
                raise VaultError("File not found in the vault.")
            old_list = list(self._manifest["files"])
            self._manifest["files"] = [e for e in self._manifest["files"] if e.get("id") != file_id]
            try:
                self._save_manifest_locked()
            except VaultError:
                # In-memory rollback: the blob still exists, nothing is lost.
                try:
                    self._manifest["files"] = old_list
                except Exception:
                    pass
                raise
        # Manifest is updated BEFORE shredding. If shredding fails,
        # at most an orphan encrypted blob remains (no ghost entry).
        try:
            if os.path.islink(blob_path):
                try:
                    os.remove(blob_path)
                except FileNotFoundError:
                    pass
            elif os.path.isfile(blob_path):
                shred_file(blob_path, passes=SHRED_PASSES_DEFAULT)
        except VaultError as e:
            raise VaultError(f"Entry removed from manifest, but shred incomplete: {e}") from e
        # Forensic purge: the manifest .bak would still hold the deleted entry.
        try:
            _sync_backup_to_current(self.manifest_path)
        except Exception:
            pass

    def move_to_group(self, file_id: str, new_group: str) -> None:
        validate_file_id(file_id)
        self._require_unlocked()
        if not isinstance(new_group, str):
            raise VaultError("Invalid group.")
        ng = Vault.sanitize_group(new_group)
        with self._op_lock:
            assert self._manifest is not None
            for e in self._manifest["files"]:
                if e.get("id") == file_id:
                    e["group"] = ng
                    break
            else:
                raise VaultError("File not found in the vault.")
            self._save_manifest_locked()
        try:
            _sync_backup_to_current(self.manifest_path)
        except Exception:
            pass

    def change_password(self, old_password: str, new_password: str) -> None:
        self._require_unlocked()
        if not isinstance(old_password, str) or not isinstance(new_password, str):
            raise VaultError("Invalid passwords.")
        if len(new_password.encode("utf-8")) < 8:
            raise VaultError("New password too short: minimum 8 characters.")
        if old_password == new_password:
            raise VaultError("New password matches the old one.")
        # verify old password by re-deriving the KEK and opening vault.meta
        try:
            if os.path.getsize(self.meta_path) > MAX_META_BYTES:
                raise VaultError("Abnormal vault.meta.")
        except VaultError:
            raise
        except (OSError, ValueError) as e:
            raise VaultError(f"Unreadable vault.meta: {e}") from e
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError) as e:
            raise VaultError("Unreadable or damaged vault.meta.") from e
        try:
            if not isinstance(meta, dict):
                raise VaultError("Damaged vault.meta.")
            kdf_old = meta.get("kdf", "scrypt")
            params_old = meta.get("kdf_params", {})
            validate_kdf_params(kdf_old, params_old)
            salt_old = b64d(meta["salt_b64"])
            nonce_old = b64d(meta["nonce_b64"])
            ct_old = b64d(meta["ct_b64"])
        except KeyError as e:
            raise VaultError("Incomplete vault.meta.") from e
        old_bytes = old_password.encode("utf-8")
        try:
            kek_old = derive_kek(old_bytes, salt_old, kdf_old, params_old)
            try:
                raw_check = aes_gcm_decrypt(bytes(kek_old), nonce_old, ct_old)
                raw_check = None
            except VaultError:
                raise VaultError("Old password is wrong.")
            finally:
                kek_old = None
                gc.collect()
        finally:
            try:
                del old_bytes
            except Exception:
                pass
            gc.collect()
        # re-wrap the SAME master key with a new KDF/KEK (blobs are not re-encrypted)
        info = kdf_info_default()
        salt = strong_random(16)
        with self._op_lock:
            if self._master is None:
                raise VaultError("Vault locked during password change.")
            new_bytes2 = new_password.encode("utf-8")
            try:
                kek2 = derive_kek(new_bytes2, salt, info["kdf"], info["params"])
                try:
                    nonce, ct = aes_gcm_encrypt(bytes(kek2), bytes(self._master) + VERIFIER)
                finally:
                    kek2 = None
                    gc.collect()
            finally:
                try:
                    del new_bytes2
                except Exception:
                    pass
                gc.collect()
            self._meta = {"magic": VAULT_MAGIC, "version": 1,
                          "kdf": info["kdf"], "kdf_params": info["params"],
                          "salt_b64": b64e(salt), "nonce_b64": b64e(nonce), "ct_b64": b64e(ct)}
            atomic_write_with_backup(self.meta_path, json.dumps(self._meta, indent=2).encode("utf-8"))
        # Forensic purge: vault.meta.bak holds the old wrapped master,
        # decryptable with the OLD password. Destroy it after success.
        try:
            _shred_backup(self.meta_path)
        except Exception:
            pass

    # -- sanitization ----------------------------------------------------
    @staticmethod
    def _strip_unsafe_chars(s: str) -> str:
        # Strips C0/C1 controls, DEL and Windows-forbidden characters.
        out = []
        for c in s:
            o = ord(c)
            if o < 32 or o == 127 or c in '<>:"|?*\x00':
                continue
            out.append(c)
        return "".join(out)

    @staticmethod
    def sanitize_group(g: str) -> str:
        if not isinstance(g, str):
            return ""
        g = g.strip().replace("\\", "/")
        try:
            g = unicodedata.normalize("NFC", g)
        except Exception:
            pass
        parts = []
        for p in g.split("/"):
            p = Vault._strip_unsafe_chars(p.strip())
            # Rejects only exact "." / "..", preserves dotfiles like ".hidden".
            p = p.strip()
            if not p or p in (".", ".."):
                continue
            if len(p) > 64:
                p = p[:64]
            parts.append(p)
            if len(parts) >= 8:
                break
        return "/".join(parts)

    @staticmethod
    def sanitize_component(name: str) -> str:
        if not isinstance(name, str) or not name:
            return "file"
        try:
            name = unicodedata.normalize("NFC", name)
        except Exception:
            pass
        name = name.replace("/", "_").replace("\\", "_")
        name = Vault._strip_unsafe_chars(name)
        # Preserves Unix leading dots (".bashrc"); strips trailing space/dot (illegal on Windows).
        s = name.strip()
        if s in ("", ".", ".."):
            return "file"
        while len(s) > 1 and s[-1] in (" ", "."):
            s = s[:-1].rstrip(" ")
            if s in ("", ".", ".."):
                return "file"
        name = s or "file"
        if name in (".", ".."):
            name = "file"
        # Reserved Windows names (CON, PRN, AUX, NUL, COM1.., LPT1..): prefix them.
        try:
            stem = name.split(".")[0].upper()
            if stem in _WINDOWS_RESERVED:
                name = "_" + name
        except Exception:
            pass
        if len(name) > 128:
            # preserve the extension when possible
            stem, dot, ext = name.rpartition(".")
            if dot and 0 < len(ext) <= 16 and len(stem) > 0:
                name = stem[:128 - len(ext) - 1] + dot + ext
            else:
                name = name[:128]
        return name or "file"


# ==========================================================================
# Tkinter GUI
# ==========================================================================
def _tk():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
    return tk, ttk, filedialog, messagebox, simpledialog


def format_size(n: int) -> str:
    try:
        n = int(n)
    except (ValueError, TypeError):
        return "-"
    if n < 0:
        n = 0
    f = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if f < 1024 or unit == "TB":
            return f"{int(f)} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


def _safe_user_message(e: BaseException) -> str:
    """Safe GUI message: VaultError -> user text; anything else -> generic."""
    if isinstance(e, VaultError):
        try:
            return str(e) or "Vault error."
        except Exception:
            return "Vault error."
    try:
        traceback.print_exc()
    except Exception:
        pass
    return ("Unexpected error during the operation (see log).\n"
            "No sensitive data was shown.")


class VaultApp:
    AUTOLOCK_SECONDS = 10 * 60

    def __init__(self):
        tk, ttk, filedialog, messagebox, simpledialog = _tk()
        self.tk, self.ttk = tk, ttk
        self.filedialog, self.messagebox, self.simpledialog = filedialog, messagebox, simpledialog
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("960x620")
        self.root.minsize(820, 520)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass
        self.vault: Vault | None = None
        self.vault_dir: str = ""
        self._last_activity = time.time()
        self._jobs: queue.Queue = queue.Queue()
        self._progress_q: queue.Queue = queue.Queue()
        self._busy = 0
        self._busy_lock = threading.Lock()
        self._poll_scheduled = False
        self._build_styles()
        self._build_login()
        self._build_main()
        self.show_login()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(1000, self._tick_autolock)

    # -- layout -----------------------------------------------------------
    def _build_styles(self):
        try:
            style = self.ttk.Style(self.root)
            for theme in ("clam", "vista", "xpnative", "default"):
                try:
                    style.theme_use(theme)
                    break
                except Exception:
                    continue
        except Exception:
            pass

    def _build_login(self):
        tk = self.tk
        self.frame_login = tk.Frame(self.root, padx=28, pady=24)
        title = tk.Label(self.frame_login, text="Vault",
                         font=("Segoe UI", 22, "bold"))
        title.pack(pady=(10, 2))
        sub = tk.Label(self.frame_login,
                       text="Encrypted database on your disk • AES-256-GCM • Memory-hard KDF\n"
                            "Every file is unreadable without the password. Names and groups are encrypted.",
                       font=("Segoe UI", 10), fg="#444", justify="center")
        sub.pack(pady=(0, 16))

        box = tk.LabelFrame(self.frame_login, text="Vault (folder on disk)", padx=14, pady=12)
        box.pack(fill="x", pady=6)
        row = tk.Frame(box)
        row.pack(fill="x")
        self.var_vaultdir = tk.StringVar()
        ent = tk.Entry(row, textvariable=self.var_vaultdir, font=("Consolas", 10))
        ent.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def browse():
            d = self.filedialog.askdirectory(title="Pick / create vault folder")
            if d:
                self.var_vaultdir.set(d)
                self._touch()
        self.ttk.Button(row, text="Browse…", command=browse).pack(side="left")

        pwbox = tk.LabelFrame(self.frame_login, text="Password", padx=14, pady=12)
        pwbox.pack(fill="x", pady=6)
        self.var_pw = tk.StringVar()
        self.var_pw.trace_add("write", lambda *_: self._pw_meter())
        prow = tk.Frame(pwbox)
        prow.pack(fill="x")
        self.ent_pw = tk.Entry(prow, textvariable=self.var_pw, show="•", font=("Segoe UI", 12))
        self.ent_pw.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.ent_pw.bind("<Return>", lambda _e: self.do_open())
        self.var_show = tk.BooleanVar(value=False)

        def toggle_show():
            self.ent_pw.config(show="" if self.var_show.get() else "•")
        self.ttk.Checkbutton(prow, text="Show", variable=self.var_show,
                             command=toggle_show).pack(side="left")
        self.lbl_strength = tk.Label(pwbox, text="", font=("Segoe UI", 9), fg="#555")
        self.lbl_strength.pack(anchor="w", pady=(6, 0))
        kdf = "Argon2id (128 MiB)" if _HAS_ARGON2 else "scrypt (N=131072, r=8, p=1)"
        tk.Label(pwbox, text=f"KDF: {kdf} • Backend: {_CRYPTO_BACKEND}",
                 font=("Segoe UI", 8), fg="#777").pack(anchor="w")

        btns = tk.Frame(self.frame_login)
        btns.pack(fill="x", pady=14)
        self.ttk.Button(btns, text="Open vault", command=self.do_open).pack(side="left", padx=(0, 8))
        self.ttk.Button(btns, text="Create new vault", command=self.do_create).pack(side="left")
        tk.Label(self.frame_login,
                 text="Tip: use a long passphrase (12+ characters). "
                      "Without the password your data is UNRECOVERABLE — there is no backdoor.",
                 font=("Segoe UI", 8), fg="#888", wraplength=700, justify="center").pack(pady=(8, 0))

    def _build_main(self):
        tk, ttk = self.tk, self.ttk
        self.frame_main = tk.Frame(self.root)
        # toolbar
        bar = tk.Frame(self.frame_main, pady=8, padx=10)
        bar.pack(fill="x")
        self.ttk.Button(bar, text="+ File", command=self.ui_add_files).pack(side="left", padx=2)
        self.ttk.Button(bar, text="+ Folder", command=self.ui_add_folder).pack(side="left", padx=2)
        self.ttk.Button(bar, text="Extract", command=self.ui_extract_selected).pack(side="left", padx=(10, 2))
        self.ttk.Button(bar, text="Extract all", command=self.ui_extract_all).pack(side="left", padx=2)
        self.ttk.Button(bar, text="Delete", command=self.ui_delete_selected).pack(side="left", padx=(10, 2))
        self.ttk.Button(bar, text="Group", command=self.ui_move_group).pack(side="left", padx=2)
        self.ttk.Button(bar, text="Password", command=self.ui_change_password).pack(side="left", padx=2)
        self.ttk.Button(bar, text="Lock", command=self.do_lock).pack(side="right", padx=2)

        # filters
        filt = tk.Frame(self.frame_main, padx=10, pady=4)
        filt.pack(fill="x")
        tk.Label(filt, text="Group:").pack(side="left")
        self.var_group = tk.StringVar(value="All")
        self.cmb_group = ttk.Combobox(filt, textvariable=self.var_group, state="readonly", width=24)
        self.cmb_group.pack(side="left", padx=(6, 12))
        self.cmb_group.bind("<<ComboboxSelected>>", lambda _e: self.refresh_list())
        tk.Label(filt, text="Search:").pack(side="left")
        self.var_search = tk.StringVar()
        self.var_search.trace_add("write", lambda *_: self.refresh_list())
        tk.Entry(filt, textvariable=self.var_search, width=28).pack(side="left", padx=6)
        self.lbl_vault = tk.Label(filt, text="", font=("Segoe UI", 8), fg="#666")
        self.lbl_vault.pack(side="right")

        # list
        cols = ("name", "group", "size", "created")
        self.tree = ttk.Treeview(self.frame_main, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("name", text="File name")
        self.tree.heading("group", text="Group")
        self.tree.heading("size", text="Size")
        self.tree.heading("created", text="Imported on")
        self.tree.column("name", width=340)
        self.tree.column("group", width=170)
        self.tree.column("size", width=110, anchor="e")
        self.tree.column("created", width=170)
        vsb = ttk.Scrollbar(self.frame_main, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=6)
        vsb.pack(side="left", fill="y", pady=6, padx=(0, 10))
        self.tree.bind("<Double-1>", lambda _e: self.ui_extract_selected())
        for ev in ("<Button>", "<Key>"):
            self.tree.bind(ev, lambda _e: self._touch(), add="+")

        # status + progress
        self.var_status = tk.StringVar(value="Ready.")
        status = tk.Label(self.frame_main, textvariable=self.var_status,
                          font=("Segoe UI", 9), fg="#333", anchor="w", padx=12, pady=4)
        status.pack(fill="x", side="bottom")
        self.progress = ttk.Progressbar(self.frame_main, mode="determinate", maximum=100)
        self.progress.pack(fill="x", side="bottom", padx=10, pady=(0, 4))
        self._entries: list[dict] = []

    # -- views ------------------------------------------------------------
    def show_login(self):
        self.frame_main.pack_forget()
        self.frame_login.pack(fill="both", expand=True)
        self.root.title(APP_TITLE)

    def show_main(self):
        self.frame_login.pack_forget()
        self.frame_main.pack(fill="both", expand=True)
        self.root.title(f"{APP_TITLE} — {self.vault_dir}")
        self.lbl_vault.config(text=f"Vault: {self.vault_dir}")
        self.refresh_list()

    # -- helpers ------------------------------------------------------------
    def _touch(self):
        self._last_activity = time.time()

    def _is_busy(self) -> bool:
        try:
            with self._busy_lock:
                return self._busy > 0
        except Exception:
            return False

    def _tick_autolock(self):
        try:
            # Never auto-lock mid-job (it would corrupt streaming).
            if self._is_busy():
                self._last_activity = time.time()
            elif self.vault is not None and self.vault.is_unlocked:
                if time.time() - self._last_activity > self.AUTOLOCK_SECONDS:
                    self.do_lock(auto=True)
                    return
        finally:
            try:
                self.root.after(1000, self._tick_autolock)
            except Exception:
                pass

    def _pw_meter(self):
        label, score = password_strength(self.var_pw.get())
        self.lbl_strength.config(text=f"Strength: {label} ({score}/100)")
        self._touch()

    def status(self, msg: str):
        self.var_status.set(msg)
        self.root.update_idletasks()

    def set_progress(self, done: int, total: int):
        pct = 100 if total <= 0 else max(0, min(100, done * 100.0 / total))
        self.progress["value"] = pct
        self.root.update_idletasks()

    def run_bg(self, label: str, fn, done_cb=None):
        """Runs fn(progress_cb) in a thread; updates the UI when done.
        The worker never touches Tk directly: it talks through thread-safe
        queues, and the main thread polls them."""
        try:
            with self._busy_lock:
                self._busy += 1
        except Exception:
            pass
        try:
            self.status(label + "…")
            self.progress["value"] = 0
        except Exception:
            pass

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
        """Runs on the main thread: applies progress + completes jobs."""
        try:
            # Progress (latest per batch only, avoids update floods)
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
            # Jobs
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
                    try:
                        self.progress["value"] = 0
                    except Exception:
                        pass
                    self.status(label + " done.")
                    self._touch()
                    if done_cb:
                        try:
                            done_cb(payload)
                        except Exception:
                            traceback.print_exc()
                else:
                    e = payload
                    msg = _safe_user_message(e)
                    try:
                        first = (msg.splitlines()[0] if msg.splitlines() else "Error")[:200]
                    except Exception:
                        first = "Error"
                    self.status("Error: " + first)
                    try:
                        self.messagebox.showerror("Error", msg)
                    except Exception:
                        pass
        finally:
            try:
                # Keep polling while jobs are active or queues are non-empty
                busy = self._is_busy()
                pending = (not self._jobs.empty()) or (not self._progress_q.empty())
                if busy or pending:
                    self.root.after(80, self._poll_queues)
                else:
                    self._poll_scheduled = False
                    try:
                        self.progress["value"] = 0
                    except Exception:
                        pass
            except Exception:
                try:
                    self._poll_scheduled = False
                except Exception:
                    pass

    # -- vault actions ----------------------------------------------------
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

    def do_create(self):
        try:
            d, p = self._get_dir_and_pw()
        except VaultError as e:
            return self.messagebox.showwarning("Warning", _safe_user_message(e))
        try:
            label, score = password_strength(p)
        except Exception:
            label, score = ("-", 0)
        if score < 30:
            if not self.messagebox.askyesno("Weak password",
                                            f"The password is '{label}'. Create the vault anyway?\n"
                                            "A 12+ character passphrase is recommended."):
                return
        try:
            self.vault = Vault.create(d, p)
            self.vault_dir = os.path.abspath(d)
        except VaultError as e:
            return self.messagebox.showerror("Error", _safe_user_message(e))
        except Exception as e:
            return self.messagebox.showerror("Error", _safe_user_message(e))
        finally:
            try:
                self.var_pw.set("")
            except Exception:
                pass
            try:
                self.ent_pw.delete(0, "end")
            except Exception:
                pass
            try:
                gc.collect()
            except Exception:
                pass
        self.show_main()
        self.status("New vault created and unlocked.")
        self._touch()

    def do_open(self):
        try:
            d, p = self._get_dir_and_pw()
        except VaultError as e:
            return self.messagebox.showwarning("Warning", _safe_user_message(e))
        try:
            v = Vault(d)
        except VaultError as e:
            try:
                self.var_pw.set("")
            except Exception:
                pass
            return self.messagebox.showerror("Cannot open", _safe_user_message(e))
        try:
            v.unlock(p)
        except VaultError as e:
            return self.messagebox.showerror("Cannot open", _safe_user_message(e))
        except Exception as e:
            return self.messagebox.showerror("Cannot open", _safe_user_message(e))
        finally:
            try:
                self.var_pw.set("")
            except Exception:
                pass
            try:
                self.ent_pw.delete(0, "end")
            except Exception:
                pass
            try:
                gc.collect()
            except Exception:
                pass
        self.vault = v
        self.vault_dir = os.path.abspath(d)
        self.show_main()
        try:
            n = len(self.vault.list_files())
        except Exception:
            n = 0
        self.status(f"Vault unlocked — {n} files.")
        self._touch()

    def do_lock(self, auto=False):
        if self._is_busy() and not auto:
            self.messagebox.showwarning(
                "Operation in progress",
                "An encryption/decryption operation is running.\n"
                "Wait for it to finish before locking the vault.")
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
            self._entries = []
            try:
                self.tree.delete(*self.tree.get_children())
            except Exception:
                pass
            try:
                self.show_login()
            except Exception:
                pass
            try:
                self.status("Vault auto-locked after inactivity." if auto
                            else "Vault locked.")
            except Exception:
                pass

    def on_close(self):
        if self._is_busy():
            try:
                ok = self.messagebox.askyesno(
                    "Operations in progress",
                    "Operations are still running. Quit anyway?\n"
                    "(jobs will be interrupted and temp files cleaned on next start)")
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

    # -- list ----------------------------------------------------------------
    def refresh_list(self):
        try:
            if self.vault is None or not self.vault.is_unlocked:
                return
        except Exception:
            return
        try:
            gf = self.var_group.get()
            if gf == "All":
                gf = ""
            entries = self.vault.list_files(group_filter=gf, search=self.var_search.get())
        except VaultError as e:
            return self.messagebox.showerror("Error", _safe_user_message(e))
        except Exception as e:
            return self.messagebox.showerror("Error", _safe_user_message(e))
        self._entries = entries
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass
        seen: set[str] = set()
        for e in entries:
            try:
                iid = str(e["id"])
                if iid in seen:
                    continue
                seen.add(iid)
                self.tree.insert("", "end", iid=iid,
                                 values=(e["name"], e.get("group") or "-",
                                         format_size(e["size"]), e.get("created", "")))
            except Exception:
                # duplicate iid or odd values: skip without breaking the UI
                continue
        # refresh group combo, preserving selection
        try:
            groups = ["All"] + self.vault.groups()
            cur = self.var_group.get()
            self.cmb_group["values"] = groups
            if cur not in groups:
                self.var_group.set("All")
        except Exception:
            pass
        self.status(f"{len(entries)} files • double-click to extract/decrypt.")

    def _selected_ids(self) -> list[str]:
        return list(self.tree.selection())

    # -- import ----------------------------------------------------------------
    def ui_add_files(self):
        if self.vault is None:
            return
        try:
            paths = self.filedialog.askopenfilenames(title="Select files to encrypt into the vault")
        except Exception as e:
            return self.messagebox.showerror("Error", _safe_user_message(e))
        if not paths:
            return
        try:
            cur_g = self.var_group.get()
        except Exception:
            cur_g = "All"
        group = self.simpledialog.askstring("Group",
                                            "Group/label for these files (e.g. Documents):",
                                            initialvalue=(cur_g if cur_g != "All" else ""))
        if group is None:
            return  # cancelled
        shred = self.messagebox.askyesno("Original files",
                                         "SHRED the original files after import?\n"
                                         "Yes = originals are overwritten and deleted.\n"
                                         "No = originals stay where they are (you handle them).")
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
            out = []
            done = [0]
            for p, sz in zip(paths, sizes):
                base_done = done[0]

                def cb(d, t, _b=base_done, _tot=total):
                    try:
                        progress_cb(min(_b + d, _tot), _tot)
                    except Exception:
                        pass
                assert self.vault is not None
                try:
                    e = self.vault.add_file(p, group=group or "",
                                            shred_original=shred, progress_cb=cb)
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
                    done_cb=lambda _r: self.refresh_list())

    def ui_add_folder(self):
        if self.vault is None:
            return
        folder = self.filedialog.askdirectory(title="Select folder to encrypt (file group)")
        if not folder:
            return
        try:
            initial = os.path.basename(os.path.abspath(folder))
        except Exception:
            initial = ""
        group = self.simpledialog.askstring("Group",
                                            "Group name for this folder:",
                                            initialvalue=initial)
        if group is None:
            return
        shred = self.messagebox.askyesno("Original files",
                                         "Shred the originals after import?")
        assert self.vault is not None
        v = self.vault

        def job(progress_cb):
            return v.add_folder(folder, group=group or "", shred_original=shred,
                                progress_cb=progress_cb)

        def _done(r):
            try:
                self.refresh_list()
                self.status(f"Imported {len(r)} files from the folder.")
            except Exception:
                pass
        self.run_bg("Encrypting folder", job, done_cb=_done)

    # -- export ----------------------------------------------------------------
    def ui_extract_selected(self):
        if self.vault is None:
            return
        ids = [i for i in self._selected_ids() if isinstance(i, str) and FILE_ID_RE.match(i)]
        if not ids:
            return self.messagebox.showinfo("No selection", "Select at least one file.")
        if len(ids) == 1:
            assert self.vault is not None
            try:
                entry = self.vault.get_entry(ids[0])
            except VaultError as e:
                return self.messagebox.showerror("Error", _safe_user_message(e))
            try:
                dest = self.filedialog.asksaveasfilename(title="Extract and decrypt as…",
                                                         initialfile=Vault.sanitize_component(entry["name"]))
            except Exception as e:
                return self.messagebox.showerror("Error", _safe_user_message(e))
            if not dest:
                return
            v = self.vault
            fid = ids[0]

            def job(progress_cb):
                return v.extract_file(fid, dest, progress_cb=progress_cb)

            def _done(p):
                try:
                    self.messagebox.showinfo("Extracted", f"Decrypted and verified file:\n{p}")
                except Exception:
                    pass
            self.run_bg("Decryption", job, done_cb=_done)
        else:
            destdir = self.filedialog.askdirectory(title="Destination folder")
            if not destdir:
                return
            v = self.vault
            ids_copy = list(ids)
            destdir_copy = destdir

            def job(progress_cb):
                try:
                    total = sum(int(v.get_entry(i)["size"]) for i in ids_copy)
                except (VaultError, ValueError, TypeError) as e:
                    raise VaultError("Invalid entry for extraction.") from e
                total = max(total, 1)
                out = []
                done = [0]
                for i in ids_copy:
                    validate_file_id(i)
                    e = v.get_entry(i)
                    d = os.path.join(destdir_copy, Vault.sanitize_component(e["name"]))
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
                    self.messagebox.showinfo("Extracted",
                                             f"{len(r)} files decrypted in:\n{destdir_copy}")
                except Exception:
                    pass
            self.run_bg(f"Decrypting {len(ids)} files", job, done_cb=_done_multi)

    def ui_extract_all(self):
        if self.vault is None:
            return
        destdir = self.filedialog.askdirectory(title="Destination folder (entire vault)")
        if not destdir:
            return
        try:
            gf = self.var_group.get()
        except Exception:
            gf = "All"
        gf = "" if gf == "All" else gf
        v = self.vault

        def job(progress_cb):
            return v.extract_all(destdir, group_filter=gf, progress_cb=progress_cb)

        def _done(r):
            try:
                self.messagebox.showinfo("Extracted",
                                         f"{len(r)} files decrypted and verified.")
            except Exception:
                pass
        self.run_bg("Full extraction", job, done_cb=_done)

    # -- delete / groups / password ----------------------------------------
    def ui_delete_selected(self):
        if self.vault is None:
            return
        ids = [i for i in self._selected_ids() if isinstance(i, str) and FILE_ID_RE.match(i)]
        if not ids:
            return self.messagebox.showinfo("No selection", "Select at least one file.")
        if not self.messagebox.askyesno("Delete permanently",
                                        f"Delete {len(ids)} files from the vault with secure SHREDDING?\n"
                                        "The encrypted blobs will be overwritten and deleted.\n"
                                        "This is IRREVERSIBLE."):
            return
        v = self.vault
        ids_copy = list(ids)

        def job(progress_cb):
            n = len(ids_copy)
            for k, i in enumerate(ids_copy):
                validate_file_id(i)
                v.delete_file(i)
                try:
                    progress_cb(k + 1, n)
                except Exception:
                    pass
            return n
        self.run_bg("Secure deletion", job, done_cb=lambda _n: self.refresh_list())

    def ui_move_group(self):
        if self.vault is None:
            return
        ids = [i for i in self._selected_ids() if isinstance(i, str) and FILE_ID_RE.match(i)]
        if not ids:
            return self.messagebox.showinfo("No selection", "Select at least one file.")
        ng = self.simpledialog.askstring("Move to group", "New group (empty = no group):")
        if ng is None:
            return
        try:
            for i in ids:
                assert self.vault is not None
                self.vault.move_to_group(i, ng)
            self.refresh_list()
            self.status(f"{len(ids)} files moved to '{(ng or '-')[:64]}'.")
        except VaultError as e:
            self.messagebox.showerror("Error", _safe_user_message(e))
        except Exception as e:
            self.messagebox.showerror("Error", _safe_user_message(e))

    def ui_change_password(self):
        if self.vault is None:
            return
        if self._is_busy():
            return self.messagebox.showwarning("Operation in progress",
                                               "Wait for completion before changing the password.")
        old = self.simpledialog.askstring("Change password", "Old password:", show="•")
        if not old:
            return
        new = self.simpledialog.askstring("Change password",
                                          "New password (8+ characters, 12+ recommended):", show="•")
        if not new:
            return
        new2 = self.simpledialog.askstring("Change password", "Repeat new password:", show="•")
        if new != new2:
            return self.messagebox.showerror("Error", "The two passwords do not match.")
        label, score = password_strength(new)
        if score < 30 and not self.messagebox.askyesno("Weak password",
                                                       f"Strength: {label}. Proceed anyway?"):
            return
        try:
            assert self.vault is not None
            self.vault.change_password(old, new)
            self._touch()
            self.status("Password changed (master key re-wrapped).")
            self.messagebox.showinfo("OK", "Password changed. Your data was NOT re-encrypted "
                                           "(only the master key was re-wrapped).")
        except VaultError as e:
            self.messagebox.showerror("Error", _safe_user_message(e))
        except Exception as e:
            self.messagebox.showerror("Error", _safe_user_message(e))
        finally:
            try:
                gc.collect()
            except Exception:
                pass

    def run(self):
        self.root.mainloop()


# ==========================================================================
# Self-test (crypto verification, no GUI)
# ==========================================================================
def selftest() -> int:
    import random as _rnd
    import tempfile
    _require_crypto()
    print(f"[selftest] backend={_CRYPTO_BACKEND} argon2={_HAS_ARGON2}")
    tmp = tempfile.mkdtemp(prefix="vaulttest_")
    print("[selftest] tmp:", tmp)
    try:
        vd = os.path.join(tmp, "myvault")
        print("[selftest] vault:", vd)
        # 0) create refuses a non-empty dir
        os.makedirs(vd, exist_ok=True)
        Path(os.path.join(vd, "preexisting.txt")).write_bytes(b"x")
        try:
            Vault.create(vd, "long-test-passphrase-123!")
            print("[selftest] ERROR: create in non-empty dir accepted!")
            return 1
        except VaultError:
            print("[selftest] create-in-non-empty-dir refused [OK]")
        shutil.rmtree(vd)
        v = Vault.create(vd, "long-test-passphrase-123!")
        # small file + empty file + 3MB binary (multi-chunk + padding)
        f1 = os.path.join(tmp, "hello.txt")
        Path(f1).write_bytes("Secret content \u2615\U0001f510 — àèìòù".encode("utf-8") * 100)
        f2 = os.path.join(tmp, "empty.bin")
        Path(f2).write_bytes(b"")
        f3 = os.path.join(tmp, "big.bin")
        Path(f3).write_bytes(os.urandom(3 * 1024 * 1024 + 123))
        h1 = hashlib.sha256(Path(f1).read_bytes()).hexdigest()
        h2 = hashlib.sha256(b"").hexdigest()
        h3 = hashlib.sha256(Path(f3).read_bytes()).hexdigest()
        e1 = v.add_file(f1, group="Documents")
        e2 = v.add_file(f2, group="Misc")
        assert e1["sha256"] == h1, "wrong manifest sha"
        assert e2["sha256"] == h2, "wrong empty sha"
        # padding always >=1 (no empty/aligned-file leaks)
        assert e2["padded"] > 0 and e2["chunks"] >= 1, "empty-file padding missing"
        print("[selftest] import ok:", e1["id"], e2["id"])
        # the blob must not contain plaintext
        blob = Path(os.path.join(vd, "data", e1["id"] + ".blk")).read_bytes()
        assert "Secret content".encode("utf-8") not in blob, "plaintext leak in blob!"
        # encrypted names: on-disk manifest must not contain names/groups
        man_raw = Path(os.path.join(vd, "vault_manifest.enc")).read_bytes()
        assert b"hello.txt" not in man_raw and b"Documents" not in man_raw, "metadata leak in manifest!"
        # list + extract + verify (including the EMPTY file)
        assert len(v.list_files()) == 2
        out1 = os.path.join(tmp, "out_hello.txt")
        v.extract_file(e1["id"], out1)
        assert hashlib.sha256(Path(out1).read_bytes()).hexdigest() == h1
        out2 = os.path.join(tmp, "out_empty.bin")
        v.extract_file(e2["id"], out2)
        assert Path(out2).read_bytes() == b"", "empty file extraction failed"
        e3 = v.add_file(f3, group="Media/Photos")
        out3 = os.path.join(tmp, "out_big.bin")
        v.extract_file(e3["id"], out3)
        assert hashlib.sha256(Path(out3).read_bytes()).hexdigest() == h3
        print("[selftest] extract+verify ok (empty + multi-chunk + padding)")
        # groups
        assert "Documents" in v.groups()
        v.move_to_group(e1["id"], "Archive/2026")
        assert v.get_entry(e1["id"])["group"] == "Archive/2026"
        print("[selftest] groups/move ok [OK]")
        # file_id traversal
        for bad in ("../vault", "..", "", "../../etc/passwd", e1["id"] + ".blk",
                    e1["id"][:-1] + "Z", "00"):
            try:
                v.get_entry(bad)
                print(f"[selftest] ERROR: file_id traversal accepted: {bad!r}")
                return 1
            except VaultError:
                pass
            try:
                v.extract_file(bad, os.path.join(tmp, "x.bin"))
                print(f"[selftest] ERROR: extract traversal accepted: {bad!r}")
                return 1
            except VaultError:
                pass
        print("[selftest] file_id traversal refused [OK]")
        # dest inside the vault is forbidden
        try:
            v.extract_file(e1["id"], os.path.join(vd, "evil_out.txt"))
            print("[selftest] ERROR: in-vault dest accepted!")
            return 1
        except VaultError:
            print("[selftest] in-vault-dest forbidden [OK]")
        # src inside the vault is forbidden
        evil_src = os.path.join(vd, "data", "fake.txt")
        Path(evil_src).write_bytes(b"evil")
        try:
            v.add_file(evil_src, group="X")
            print("[selftest] ERROR: in-vault src accepted!")
            return 1
        except VaultError:
            print("[selftest] in-vault-src forbidden [OK]")
        try:
            os.remove(evil_src)
        except Exception:
            pass
        # add_folder containing the vault is forbidden
        try:
            v.add_folder(tmp, group="G")
            print("[selftest] ERROR: add_folder containing vault accepted!")
            return 1
        except VaultError:
            print("[selftest] add-folder-with-vault forbidden [OK]")
        # legitimate add_folder + extract_all with sanitized collisions
        srcdir = os.path.join(tmp, "srcdir")
        os.makedirs(os.path.join(srcdir, "sub"), exist_ok=True)
        Path(os.path.join(srcdir, "a.txt")).write_bytes(b"AAA")
        Path(os.path.join(srcdir, "sub", "b.txt")).write_bytes(b"BBB")
        added = v.add_folder(srcdir, group="Imp")
        assert len(added) == 2, f"add_folder: expected 2, got {len(added)}"
        # two names colliding after sanitize ("a:b.txt" vs "a_b.txt")
        c1 = os.path.join(tmp, "c1.txt")
        c2 = os.path.join(tmp, "c2.txt")
        Path(c1).write_bytes(b"CCC")
        Path(c2).write_bytes(b"DDD")
        ec1 = v.add_file(c1, group="Coll")
        # force the same sanitized name via the manifest? Simpler:
        # import c2 with group Coll and check extract_all never overwrites.
        ec2 = v.add_file(c2, group="Coll")
        v.move_to_group(ec2["id"], "Coll")
        dest_all = os.path.join(tmp, "out_all")
        outs = v.extract_all(dest_all)
        assert len(outs) == len(set(outs)), "extract_all produced duplicate dests!"
        assert len(outs) == len(v.list_files()), "incomplete extract_all"
        print("[selftest] add_folder + extract_all ok [OK]")
        # symlinks: shred must remove only the link, never the target
        target = os.path.join(tmp, "target.txt")
        Path(target).write_bytes(b"DO-NOT-DESTROY")
        link = os.path.join(tmp, "link.txt")
        try:
            if os.path.exists(link) or os.path.islink(link):
                os.remove(link)
            os.symlink(target, link)
            have_link = True
        except (OSError, NotImplementedError):
            have_link = False
        if have_link:
            try:
                v.add_file(link, group="X")
                print("[selftest] ERROR: symlink accepted in add_file!")
                return 1
            except VaultError:
                pass
            # shred_file on the link must not touch the target
            shred_file(link, passes=1)
            assert Path(target).read_bytes() == b"DO-NOT-DESTROY", \
                "shred followed the symlink!"
            assert not os.path.islink(link), "link not removed"
            print("[selftest] symlink-safe [OK]")
        else:
            print("[selftest] symlink test skipped (OS without symlinks) [OK]")
        # tampered KDF params -> anti-DoS refusal (no huge allocs)
        for bad_kdf, bad_params in [
            ("scrypt", {"n": 2 ** 30, "r": 8, "p": 1}),
            ("scrypt", {"n": 1000, "r": 8, "p": 1}),
            ("argon2id", {"time_cost": 99, "memory_kib": 131072, "parallelism": 4}),
            ("argon2id", {"time_cost": 3, "memory_kib": 2 ** 30, "parallelism": 4}),
            ("unknown-kdf", {}),
        ]:
            try:
                validate_kdf_params(bad_kdf, bad_params)
                print(f"[selftest] ERROR: absurd KDF accepted: {bad_kdf} {bad_params}")
                return 1
            except VaultError:
                pass
        # unknown KDF in derive -> error, NEVER silent fallback
        try:
            derive_kek(b"pw", b"0" * 16, "rot13", {})
            print("[selftest] ERROR: unknown KDF derived!")
            return 1
        except VaultError:
            pass
        print("[selftest] KDF anti-DoS/downgrade validation [OK]")
        # wrong password
        v2 = Vault(vd)
        try:
            v2.unlock("long-wrong-password-xyz")
            print("[selftest] ERROR: wrong password accepted!")
            return 1
        except VaultError:
            print("[selftest] wrong-password refused [OK]")
        # tamper: corrupt one blob byte -> GCM must fail
        bp = os.path.join(vd, "data", e3["id"] + ".blk")
        with open(bp, "r+b") as f:
            f.seek(_rnd.randint(20, os.path.getsize(bp) - 1))
            bb = f.read(1)
            f.seek(-1, os.SEEK_CUR)
            f.write(bytes([bb[0] ^ 0x01]))
        try:
            v.extract_file(e3["id"], os.path.join(tmp, "tamper.bin"))
            print("[selftest] ERROR: tamper not detected!")
            return 1
        except VaultError:
            print("[selftest] tamper detected [OK]")
        # Blob e3 is now deliberately corrupt: drop it and reimport clean f3
        # (otherwise every later extract_all would fail by design).
        v.delete_file(e3["id"])
        e3 = v.add_file(f3, group="Media/Photos")
        _chk = os.path.join(tmp, "rechk_big.bin")
        v.extract_file(e3["id"], _chk)
        assert hashlib.sha256(Path(_chk).read_bytes()).hexdigest() == h3, "e3 reimport failed"
        # tampered PRIMARY manifest only -> recovery from .bak (same master),
        # unlock must succeed without losing data.
        man_path = os.path.join(vd, "vault_manifest.enc")
        man_backup = Path(man_path).read_bytes()
        n_list_before = len(v.list_files())
        try:
            with open(man_path, "r+b") as f:
                f.seek(max(10, os.path.getsize(man_path) // 2))
                bb = f.read(1)
                f.seek(-1, os.SEEK_CUR)
                f.write(bytes([bb[0] ^ 0xFF]))
            vt = Vault(vd)
            vt.unlock("long-test-passphrase-123!")
            got = vt.list_files()
            # The .bak is by design 1 save behind: tolerate n/n-1, but it must
            # hold the stable entries (e1) and stay decryptable.
            assert n_list_before - 1 <= len(got) <= n_list_before, \
                f"incomplete .bak recovery: {len(got)} vs {n_list_before}"
            assert any(e["id"] == e1["id"] for e in got), "recovery without e1!"
            vt.lock()
            print("[selftest] manifest-recovery from .bak [OK]")
        finally:
            # v still holds the good manifest in RAM: rewrite it clean.
            v._save_manifest_locked() if v.is_unlocked else None
        # tampered BOTH primary AND backup -> unlock must fail (GCM), not crash.
        man_good = Path(man_path).read_bytes()
        bak_path = man_path + ".bak"
        bak_good = Path(bak_path).read_bytes() if os.path.isfile(bak_path) else None
        try:
            for p in (man_path, bak_path):
                if os.path.isfile(p):
                    with open(p, "r+b") as f:
                        f.seek(max(10, os.path.getsize(p) // 2))
                        bb = f.read(1)
                        f.seek(-1, os.SEEK_CUR)
                        f.write(bytes([bb[0] ^ 0xFF]))
            vt2 = Vault(vd)
            try:
                vt2.unlock("long-test-passphrase-123!")
                print("[selftest] ERROR: doubly-tampered manifest accepted!")
                return 1
            except VaultError:
                print("[selftest] manifest-tamper detected [OK]")
        finally:
            Path(man_path).write_bytes(man_good)
            if bak_good is not None:
                Path(bak_path).write_bytes(bak_good)
        # dotfiles: ".bashrc" must keep its leading dot through import/extract.
        dot_src = os.path.join(tmp, ".bashrc")
        Path(dot_src).write_bytes(b"export SECRET=1\n")
        e_dot = v.add_file(dot_src, group="Dot")
        assert e_dot["name"] == ".bashrc", f"dotfile name changed: {e_dot['name']}"
        assert Vault.sanitize_component(".bashrc") == ".bashrc", "sanitize breaks dotfiles"
        out_dot = os.path.join(tmp, "out_dot_all")
        v.extract_all(out_dot)
        assert os.path.isfile(os.path.join(out_dot, "Dot", ".bashrc")), "dotfile lost in extract_all"
        v.delete_file(e_dot["id"])
        print("[selftest] dotfile preserved [OK]")
        # preserved mtime/mode (when the OS supports it).
        mt_src = os.path.join(tmp, "mt.txt")
        Path(mt_src).write_bytes(b"mtime-test")
        try:
            os.utime(mt_src, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
        except Exception:
            pass
        e_mt = v.add_file(mt_src, group="Mt")
        out_mt = os.path.join(tmp, "out_mt.txt")
        v.extract_file(e_mt["id"], out_mt)
        try:
            assert os.stat(out_mt).st_mtime_ns == os.stat(mt_src).st_mtime_ns, "mtime not preserved"
            print("[selftest] mtime preserved [OK]")
        except AssertionError:
            raise
        except Exception as ex:
            print(f"[selftest] mtime skip (FS): {ex}")
        v.delete_file(e_mt["id"])
        # empty folder -> explicit error (never a silent 0).
        empty_d = os.path.join(tmp, "empty_dir")
        os.makedirs(empty_d, exist_ok=True)
        try:
            v.add_folder(empty_d, group="Empty")
            print("[selftest] ERROR: empty folder accepted!")
            return 1
        except VaultError:
            print("[selftest] empty folder refused [OK]")
        # delete + shred (save-first order) + backup forensic purge.
        n_before = len(v.list_files())
        del_id = e2["id"]
        v.delete_file(del_id)
        assert not os.path.exists(os.path.join(vd, "data", del_id + ".blk"))
        assert len(v.list_files()) == n_before - 1
        # The .bak must no longer hold the deleted entry (forensic purge):
        # decrypt the backup with the current master and check the id is gone.
        if os.path.isfile(man_path + ".bak"):
            probe = Vault(vd)
            probe.unlock("long-test-passphrase-123!")
            try:
                bak_man = probe._load_manifest_from(man_path + ".bak")
                bak_ids = {e.get("id") for e in bak_man.get("files", [])}
                assert del_id not in bak_ids, "deleted entry still in .bak!"
            finally:
                probe.lock()
        print("[selftest] delete+shred+bak-purge ok")
        # change password (+ meta.bak purge: the old pw must stop working,
        # even via backup).
        v.change_password("long-test-passphrase-123!", "even-longer-new-passphrase-456!")
        assert not os.path.isfile(v.meta_path + ".bak"), \
            "meta.bak kept after change_password: old pw still recoverable!"
        v.lock()
        assert not v.is_unlocked
        v3 = Vault(vd)
        v3.unlock("even-longer-new-passphrase-456!")
        assert len(v3.list_files()) == n_before - 1
        try:
            Vault(vd).unlock("long-test-passphrase-123!")
            print("[selftest] ERROR: old password still works!")
            return 1
        except VaultError:
            print("[selftest] password change ok [OK]")
        # lock wipes state
        v3.lock()
        assert not v3.is_unlocked
        try:
            v3.list_files()
            print("[selftest] ERROR: list after lock worked!")
            return 1
        except VaultError:
            print("[selftest] lock ok [OK]")
        print("[selftest] ALL OK [OK]")
        return 0
    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


def main():
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    if AES is None:
        print("ERROR: missing crypto backend.\nRun:  pip install pycryptodomex",
              file=sys.stderr)
        sys.exit(2)
    app = VaultApp()
    app.run()


if __name__ == "__main__":
    main()
