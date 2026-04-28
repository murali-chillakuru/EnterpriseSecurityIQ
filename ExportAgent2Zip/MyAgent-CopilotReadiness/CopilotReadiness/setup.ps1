<#
.SYNOPSIS
    One-command setup for CopilotReadinessIQ (CopilotReadiness) on Azure + Teams.

.DESCRIPTION
    Orchestrates the full provisioning flow:
      1. Entra app registration (SPA + Teams + scopes + admin consent)
      2. Azure infra (Foundry + ACR + Container App + Storage)
      3. Token injection into webapp + manifest + deploy script
      4. ACR build + Container App deploy
      5. Teams app package generation

    Idempotent — re-runnable. State stored in automation/.generated.json.

.PARAMETER BrandName
    Resource prefix and display brand. Default: CopilotReadinessIQ

.PARAMETER Location
    Azure region for Foundry. Default: swedencentral

.PARAMETER ContainerAppsLocation
    Azure region for Container App. Default: northeurope

.PARAMETER SubscriptionId
    Azure subscription ID (or name). Required.

.PARAMETER SkipEntra / SkipInfra / SkipBuild / SkipTeams
    Skip individual phases.
#>
[CmdletBinding()]
param(
    [string]$BrandName              = "CopilotReadinessIQ",
    [string]$Location               = "swedencentral",
    [string]$ContainerAppsLocation  = "northeurope",
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    [switch]$SkipEntra,
    [switch]$SkipInfra,
    [switch]$SkipBuild,
    [switch]$SkipTeams,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Import-Module (Join-Path $root "automation\helpers.psm1") -Force

Write-Banner "Setup — $BrandName (CopilotReadiness)"
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
    DryRun                = $DryRun.IsPresent
}

if (-not $SkipEntra)  { & (Join-Path $root "automation\01_provision_entra.ps1") @ctx }
if (-not $SkipInfra)  { & (Join-Path $root "automation\02_provision_infra.ps1") @ctx }
& (Join-Path $root "automation\03_inject_config.ps1") @ctx
if (-not $SkipBuild)  { & (Join-Path $root "automation\04_build_and_deploy.ps1") @ctx }
if (-not $SkipTeams)  { & (Join-Path $root "automation\05_publish_teams_app.ps1") @ctx }

Write-Banner "Setup complete"
$gen = Get-GeneratedConfig $root
Write-Host "  URL:        https://$($gen.BackendFqdn)/" -ForegroundColor Green
Write-Host "  Teams app:  $($gen.TeamsAppZip)" -ForegroundColor Green
