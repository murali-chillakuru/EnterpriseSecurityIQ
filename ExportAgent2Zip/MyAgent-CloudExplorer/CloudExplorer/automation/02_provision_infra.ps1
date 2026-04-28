<#
.SYNOPSIS Provision Foundry + ACR + Container App via existing Infra-Foundary-New/deploy.ps1.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId, [string]$Root, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "automation\helpers.psm1") -Force

Write-Banner "[2/5] Azure infra (Foundry + ACR + Container App)"
$names = Compute-ResourceNames -BrandName $BrandName
$gen   = Get-GeneratedConfig $Root

if ($gen.BackendFqdn) {
    Write-Host "  Already provisioned: $($gen.BackendFqdn)" -ForegroundColor DarkGray
    return
}

if ($DryRun) { Write-Host "  [DRY-RUN] would deploy with: $($names | ConvertTo-Json -Compress)"; return }

$deploy = Join-Path $Root "Infra-Foundary-New\deploy.ps1"
if (-not (Test-Path $deploy)) { throw "deploy.ps1 not found at $deploy" }

# Find subscription name from id
$subName = az account show --subscription $SubscriptionId --query name -o tsv

& $deploy `
    -BaseName              $BrandName `
    -Location              $Location `
    -ContainerAppsLocation $ContainerAppsLocation `
    -SubscriptionName      $subName

# Capture FQDN
$fqdn = az containerapp show -g $names.ResourceGroup -n $names.ContainerAppName --query "properties.configuration.ingress.fqdn" -o tsv
if (-not $fqdn) { throw "Container App FQDN not found" }
Write-Host "  FQDN: $fqdn" -ForegroundColor Green

Set-GeneratedValue $Root "BackendFqdn"      $fqdn
Set-GeneratedValue $Root "ResourceGroup"    $names.ResourceGroup
Set-GeneratedValue $Root "AcrName"          $names.AcrName
Set-GeneratedValue $Root "ContainerAppName" $names.ContainerAppName
