<#
.SYNOPSIS Package Teams app zip from staged manifest.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId,
    [string]$Root, [string]$RepoRoot, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "scripts\helpers.psm1") -Force

Write-Banner "[5/5] Teams app package"
$gen = Get-GeneratedConfig $Root
$pkgDir = Join-Path $gen.StagePath "teams\appPackage"
if (-not (Test-Path $pkgDir)) { Write-Host "  No teams/appPackage staged — skipping"; return }

$buildDir = Join-Path $Root ".generated\teams"
New-Item $buildDir -ItemType Directory -Force | Out-Null
$zipPath = Join-Path $buildDir "$BrandName-teams-app.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

if ($DryRun) { Write-Host "  [DRY-RUN] would package $zipPath"; return }

$files = @(
    Join-Path $pkgDir "manifest.json",
    Join-Path $pkgDir "color.png",
    Join-Path $pkgDir "outline.png"
) | Where-Object { Test-Path $_ }

Compress-Archive -Path $files -DestinationPath $zipPath -Force
Set-GeneratedValue $Root "TeamsAppZip" $zipPath

Write-Host "  Teams app zip: $zipPath" -ForegroundColor Green
