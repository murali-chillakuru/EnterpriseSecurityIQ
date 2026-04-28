<#
.SYNOPSIS ACR build + Container App update.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId, [string]$Root, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "automation\helpers.psm1") -Force

Write-Banner "[4/5] Build & deploy container image"
$gen = Get-GeneratedConfig $Root
if (-not $gen.AcrName) { throw "ACR not provisioned — run 02_provision_infra.ps1 first" }

$tag = "v" + (Get-Date -Format "yyyyMMddHHmmss")
Set-GeneratedValue $Root "ImageTag" $tag

if ($DryRun) { Write-Host "  [DRY-RUN] would build & deploy $tag"; return }

$ctx = Join-Path $env:TEMP "${BrandName}-ctx"
if (Test-Path $ctx) { Remove-Item $ctx -Recurse -Force }
New-Item $ctx -ItemType Directory | Out-Null
New-Item "$ctx\AIAgent" -ItemType Directory | Out-Null
Copy-Item (Join-Path $Root "AIAgent\requirements.txt") "$ctx\AIAgent\requirements.txt"
Copy-Item (Join-Path $Root "AIAgent\app")  "$ctx\AIAgent\app"  -Recurse
Copy-Item (Join-Path $Root "AIAgent\main.py") "$ctx\AIAgent\main.py"
Copy-Item (Join-Path $Root "webapp") "$ctx\webapp" -Recurse

Write-Host "  Building image $tag in ACR $($gen.AcrName) …"
az acr build --registry $gen.AcrName --image "$($gen.ContainerAppName):$tag" `
    --file "AIAgent/Dockerfile" $ctx --no-logs

Write-Host "  Deploying $tag to Container App …"
az containerapp update --name $gen.ContainerAppName --resource-group $gen.ResourceGroup `
    --image "$($gen.AcrName).azurecr.io/$($gen.ContainerAppName):$tag" -o table

Write-Host "  Deployed: https://$($gen.BackendFqdn)/" -ForegroundColor Green
