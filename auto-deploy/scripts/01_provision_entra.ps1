<#
.SYNOPSIS Provision Entra app registration with SPA + Teams config.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId,
    [string]$Root, [string]$RepoRoot, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "scripts\helpers.psm1") -Force

Write-Banner "[1/5] Entra app registration"
$gen = Get-GeneratedConfig $Root
if ($gen.EntraClientId) {
    Write-Host "  Already provisioned: $($gen.EntraClientId)" -ForegroundColor DarkGray
    return
}

$displayName = "$BrandName-Agent"
Write-Host "  Creating app: $displayName"
if ($DryRun) { Write-Host "  [DRY-RUN] would create"; return }

$clientId = az ad app create --display-name $displayName --sign-in-audience AzureADMyOrg --query appId -o tsv
if (-not $clientId) { throw "Failed to create app registration" }
Write-Host "  ClientId: $clientId" -ForegroundColor Green

# Microsoft Graph User.Read delegated
az ad app permission add --id $clientId --api 00000003-0000-0000-c000-000000000000 `
    --api-permissions "e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope" 2>$null | Out-Null
# ARM user_impersonation delegated
az ad app permission add --id $clientId --api 797f4846-ba00-4fd7-ba43-dac1f8f63013 `
    --api-permissions "41094075-9dad-400e-a0bd-54e686782033=Scope" 2>$null | Out-Null

try { az ad app permission admin-consent --id $clientId 2>$null | Out-Null }
catch { Write-Warning "  Admin consent failed — grant manually: az ad app permission admin-consent --id $clientId" }

az ad sp create --id $clientId 2>$null | Out-Null

Set-GeneratedValue $Root "EntraClientId" $clientId
Set-GeneratedValue $Root "EntraDisplayName" $displayName
