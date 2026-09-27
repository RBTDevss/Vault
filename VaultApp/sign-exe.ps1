# Re-sign the exe after every publish (rebuilding wipes the signature).
# Usage:  powershell -ExecutionPolicy Bypass -File sign-exe.ps1 [-Path bin\publish-vault\Vault.exe]
param([string]$Path = "bin\publish-vault\Vault.exe")
$ErrorActionPreference = "Stop"
$cert = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.FriendlyName -eq "PrivateVault dev" } | Select-Object -First 1
if (-not $cert) { throw "Certificate 'PrivateVault dev' not found in CurrentUser\My." }
$sig = Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -HashAlgorithm SHA256
$sig | Select-Object Status, Path
if ($sig.Status -ne "Valid") { throw "Signature not valid: $($sig.Status) $($sig.StatusMessage)" }
Write-Host "OK: exe signed and trusted by Smart App Control (this PC/user only)."
