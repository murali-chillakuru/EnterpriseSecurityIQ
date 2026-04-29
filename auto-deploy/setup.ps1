<#
.SYNOPSIS
    One-command end-to-end deploy for the EnterpriseSecurityIQ repo.

.DESCRIPTION
    Provisions a fresh Azure environment for ANY brand without modifying any
    repo file. Builds a temporary staged copy of webapp/ + teams/ with brand
    tokens injected, then builds + deploys.

    Order of operations:
      1. Entra app registration (SPA + Web redirects, Graph + ARM scopes)
      2. Azure infra via Infra-Foundary-New/deploy.ps1
      3. Stage webapp/ + teams/ into auto-deploy/staged/, inject tokens
      4. ACR build from temp context, deploy to Container App
      5. Package Teams app zip

    Idempotent state in auto-deploy/.generated/runtime.json.

.PARAMETER BrandName
    Resource prefix and display brand. REQUIRED.

.PARAMETER Location
    Azure region for Foundry. Default: swedencentral

.PARAMETER ContainerAppsLocation
    Azure region for Container App. Default: northeurope

.PARAMETER SubscriptionId
    Azure subscription ID or name. REQUIRED.

.PARAMETER SkipEntra/SkipInfra/SkipBuild/SkipTeams
    Skip individual phases.

.EXAMPLE
    .\auto-deploy\setup.ps1 -BrandName "MyBrand" -SubscriptionId "AI"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$BrandName,
    [string]$Location               = "swedencentral",
    [string]$ContainerAppsLocation  = "northeurope",
    [Parameter(Mandatory=$true)] [string]$SubscriptionId,
    [switch]$SkipEntra,
    [switch]$SkipInfra,
    [switch]$SkipBuild,
    [switch]$SkipTeams,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root     = $PSScriptRoot
$repoRoot = Split-Path $root -Parent
Import-Module (Join-Path $root "scripts\helpers.psm1") -Force

Write-Banner "EnterpriseSecurityIQ auto-deploy — $BrandName"
Write-Host "  Repo root:    $repoRoot"
Write-Host "  Subscription: $SubscriptionId"
Write-Host "  Region:       $Location (Container Apps: $ContainerAppsLocation)"
Write-Host ""

az account set --subscription $SubscriptionId | Out-Null

$ctx = @{
    BrandName             = $BrandName
    Location              = $Location
    ContainerAppsLocation = $ContainerAppsLocation
    SubscriptionId        = (az account show --query id -o tsv)
    TenantId              = (az account show --query tenantId -o tsv)
    Root                  = $root
    RepoRoot              = $repoRoot
    DryRun                = $DryRun.IsPresent
}

if (-not $SkipEntra)  { & (Join-Path $root "scripts\01_provision_entra.ps1")  @ctx }
if (-not $SkipInfra)  { & (Join-Path $root "scripts\02_provision_infra.ps1")  @ctx }
& (Join-Path $root "scripts\03_inject_config.ps1") @ctx
if (-not $SkipBuild)  { & (Join-Path $root "scripts\04_build_and_deploy.ps1") @ctx }
if (-not $SkipTeams)  { & (Join-Path $root "scripts\05_publish_teams_app.ps1") @ctx }

Write-Banner "Auto-deploy complete"
$gen = Get-GeneratedConfig $root
Write-Host "  URL:        https://$($gen.BackendFqdn)/" -ForegroundColor Green
if ($gen.TeamsAppZip) { Write-Host "  Teams app:  $($gen.TeamsAppZip)" -ForegroundColor Green }
