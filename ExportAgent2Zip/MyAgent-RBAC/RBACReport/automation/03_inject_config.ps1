<#
.SYNOPSIS Inject generated IDs into HTML/JSON/PS1 files in staged copy.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId, [string]$Root, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "automation\helpers.psm1") -Force

Write-Banner "[3/5] Inject configuration tokens"
$gen = Get-GeneratedConfig $Root

if (-not $gen.EntraClientId) { Write-Warning "  EntraClientId missing — re-run with full setup"; return }
if (-not $gen.BackendFqdn)   { Write-Warning "  BackendFqdn missing — re-run with full setup"; return }

# Generate Teams app GUID once
if (-not $gen.TeamsAppId) {
    $teamsId = [guid]::NewGuid().ToString()
    Set-GeneratedValue $Root "TeamsAppId" $teamsId
    $gen = Get-GeneratedConfig $Root
}

$tokens = @{
    "{{ENTRA_CLIENT_ID}}" = $gen.EntraClientId
    "{{TEAMS_APP_ID}}"    = $gen.TeamsAppId
    "{{BACKEND_FQDN}}"    = $gen.BackendFqdn
    "{{TENANT_ID}}"       = $TenantId
}

$targets = @(
    "webapp\*.html",
    "teams\appPackage\manifest.json"
)

$count = 0
foreach ($pattern in $targets) {
    $files = Get-ChildItem -Path (Join-Path $Root $pattern) -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $text = Get-Content $f.FullName -Raw
        $orig = $text
        foreach ($k in $tokens.Keys) { $text = $text.Replace($k, $tokens[$k]) }
        if ($text -ne $orig) {
            if ($DryRun) { Write-Host "  [DRY-RUN] would update $($f.Name)" }
            else {
                Set-Content -Path $f.FullName -Value $text -Encoding UTF8 -NoNewline
                Write-Host "  injected: $($f.FullName.Substring($Root.Length+1))" -ForegroundColor DarkGray
                $count++
            }
        }
    }
}

# Add SPA redirect URI to Entra app now that FQDN is known
$spaUri = "https://$($gen.BackendFqdn)"
$brkUri = "brk-multihub://$($gen.BackendFqdn)"
Write-Host "  Adding redirect URIs to Entra app…"
try {
    az ad app update --id $gen.EntraClientId --set "spa.redirectUris=['$spaUri','$spaUri/auth-end.html','$brkUri']" 2>$null | Out-Null
} catch { Write-Warning "  Failed to update redirect URIs — add manually: $spaUri" }

Write-Host "  $count file(s) updated" -ForegroundColor Green
