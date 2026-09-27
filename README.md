# Vault — Encrypted On-Disk Database

**Vault** turns any folder on your disk into a private encrypted database.
Every file you import is encrypted with **AES-256-GCM** and stored as an
anonymous blob: without the password, names, groups, contents and exact sizes
are unreadable. There is no backdoor and no recovery — lost password means
lost data.

> ⚠️ **Windows Smart App Control notice — please read before downloading.**
> Smart App Control may block the prebuilt `Vault.exe` with a message like
> *"Smart App Control blocked this file"* or *"An Application Control policy
> has blocked this file."*
> This happens because the executable is **not signed with a
> Microsoft-trusted (EV) certificate and has no reputation yet** — not because
> anything was found wrong with it. **Right now there is nothing that can be
> done about it from our side:** self-signing, antivirus exclusions and
> re-downloads do **not** satisfy Smart App Control. Your options are:
> 1. **Build from source** (instructions below) and run it — or
> 2. **Turn Smart App Control off**: Windows Security → App & browser control
>    → Smart App Control settings → Off (requires administrator rights, and
>    please note: once fully off, it can only be re-enabled by resetting /
>    reinstalling Windows).
>
> A trusted EV code-signing certificate (paid, plus accumulated reputation) is
> the only real long-term fix, and it is planned before any official public
> release. Until then, building from source is the recommended way to run
> Vault.

## Features

- AES-256-GCM streaming encryption (1 MB chunks, constant RAM even for GB files)
- Unique 256-bit key per file, wrapped by a 256-bit master key — the password never touches your data directly
- Memory-hard KDF: Argon2id when available, otherwise scrypt
- Fully encrypted manifest (file names and groups are hidden on disk)
- Random blob names + 512-byte padding against size analysis
- Tamper detection per chunk (GCM) + SHA-256 verification on extract
- Secure deletion with 3-pass shredding
- Whole-folder import with automatic `Group/subfolder` organization
- Groups, search, sorting, password change (instant — only the master key is re-wrapped)
- Auto-lock after 10 minutes of inactivity, keys wiped from RAM
- 100% offline — no network, no telemetry

## Frontends

All frontends share the same proven core in `vault.py`, so vaults are
compatible no matter which one you use:

| Frontend | Location | Notes |
|---|---|---|
| C# WPF desktop app (recommended) | `VaultApp/` | Dark UI, drives the Python core through `vault_bridge.py` |
| Python + CustomTkinter | `vault_gui.py` | Dark card-based UI, same core |
| Python + Tkinter (legacy) | `vault.py` | Original single-file app, includes `--selftest` |

## Quick start

**C# app** (needs .NET 8 SDK + Python with `pycryptodomex` on PATH):

```powershell
cd VaultApp
dotnet run -c Release
```

**Python GUI:**

```powershell
pip install -r requirements.txt
python vault.py
# or: python vault_gui.py
```

**Self-test** (crypto verification, tamper, wrong password, shredding):

```powershell
python vault.py --selftest
```

## How to use

1. **Create new vault** — pick an empty folder + a long passphrase (12+ characters).
2. **+ File / + Folder** — import files or whole folders (each subfolder becomes `Group/subfolder`).
3. **Extract** — decrypt to a folder of your choice (integrity is verified automatically).
4. **Delete** — removes blobs with secure shredding. Irreversible.
5. **Password** — change it any time (instant, data is not re-encrypted).
6. **Lock** — wipes keys from memory when you are done.

When asked whether to destroy the originals, answer **Yes** if you want the
plaintext files shredded after import.

## Security model (honest summary)

- Encryption: AES-256-GCM, unique nonces (random base + counter), per-chunk authentication.
- Keys: 256-bit CSPRNG master key + unique file keys; password only feeds the KDF.
- KDF: Argon2id (128 MiB) when `argon2-cffi` is installed, else scrypt N=131072.
- Metadata: encrypted manifest, random blob names, padded sizes.
- Deletion: 3-pass overwrite + fsync + anonymous rename; atomic manifest writes.

Honest limits (no pure software can remove these): on SSD/NVMe, wear-leveling
may retain unreachable physical copies — combine with full-disk encryption
(BitLocker/LUKS/FileVault) for maximum security. RAM/swap can retain
fragments — press **Lock** when finished.

## Project layout

```
vault.py       # proven core (Vault) + legacy GUI + --selftest
vault_bridge.py       # JSON-line IPC server over stdio (used by the C# app)
vault_gui.py   # CustomTkinter GUI (same core)
VaultApp/             # C# WPF frontend (.NET 8, no crypto reimplementation)
requirements.txt      # Python dependencies
Vault.spec          # PyInstaller spec for the legacy GUI
```

## Building the Windows exe

```powershell
cd VaultApp
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o bin/publish-vault
```

`vault.py` and `vault_bridge.py` are copied next to the exe
automatically and are required at runtime, together with a Python
installation (`pip install pycryptodomex`, `argon2-cffi` recommended).

## License

MIT — see the `LICENSE` file. Copyright (c) 2026 RBTDevsss.
