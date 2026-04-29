<#
.SYNOPSIS Stage webapp/ + teams/ into auto-deploy/staged/ and inject tokens.
          NEVER modifies any file in the repo source tree.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId,
    [string]$Root, [string]$RepoRoot, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "scripts\helpers.psm1") -Force

Write-Banner "[3/5] Stage + inject configuration tokens"
$gen = Get-GeneratedConfig $Root

if (-not $gen.EntraClientId) { Write-Warning "  EntraClientId missing — re-run with full setup"; return }
if (-not $gen.BackendFqdn)   { Write-Warning "  BackendFqdn missing — re-run with full setup"; return }

if (-not $gen.TeamsAppId) {
    $teamsId = [guid]::NewGuid().ToString()
    Set-GeneratedValue $Root "TeamsAppId" $teamsId
    $gen = Get-GeneratedConfig $Root
}

$tokens = @{
    "ffb6f10d-6991-430e-b3d6-23a0101a92b1" = $gen.EntraClientId   # hardcoded clientId in HTML
    "{{ENTRA_CLIENT_ID}}" = $gen.EntraClientId
    "{{TEAMS_APP_ID}}"    = $gen.TeamsAppId
    "{{BACKEND_FQDN}}"    = $gen.BackendFqdn
    "{{TENANT_ID}}"       = $TenantId
}

# ---------- Stage area (NEVER touches $RepoRoot/webapp or $RepoRoot/teams) ----------
$stageRoot = Join-Path $Root "staged"
if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
New-Item $stageRoot -ItemType Directory | Out-Null

$copyMap = @{
    (Join-Path $RepoRoot "webapp")            = (Join-Path $stageRoot "webapp")
    (Join-Path $RepoRoot "teams\appPackage")  = (Join-Path $stageRoot "teams\appPackage")
}
foreach ($src in $copyMap.Keys) {
    if (Test-Path $src) {
        Copy-Item $src $copyMap[$src] -Recurse -Force
        Write-Host "  staged: $src -> $($copyMap[$src])" -ForegroundColor DarkGray
    }
}

$count = 0
$targets = @(
    Join-Path $stageRoot "webapp\*.html"
    Join-Path $stageRoot "teams\appPackage\manifest.json"
)
foreach ($pattern in $targets) {
    $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $text = Get-Content $f.FullName -Raw
        $orig = $text
        foreach ($k in $tokens.Keys) { $text = $text.Replace($k, $tokens[$k]) }
        if ($text -ne $orig) {
            if ($DryRun) { Write-Host "  [DRY-RUN] would update $($f.Name)" }
            else {
                Set-Content -Path $f.FullName -Value $text -Encoding UTF8 -NoNewline
                Write-Host "  injected: $($f.FullName.Substring($stageRoot.Length+1))" -ForegroundColor DarkGray
                $count++
            }
        }
    }
}

# Update Entra app SPA redirect URIs now that FQDN is known
$spaUri = "https://$($gen.BackendFqdn)"
$brkUri = "brk-multihub://$($gen.BackendFqdn)"
Write-Host "  Adding redirect URIs to Entra app…"
try {
    az ad app update --id $gen.EntraClientId --set "spa.redirectUris=['$spaUri','$spaUri/auth-end.html','$brkUri']" 2>$null | Out-Null
} catch { Write-Warning "  Failed to update redirect URIs — add manually: $spaUri" }

Set-GeneratedValue $Root "StagePath" $stageRoot
Write-Host "  $count file(s) updated in stage area" -ForegroundColor Green
