<#
.SYNOPSIS ACR build + Container App update from temp context (uses staged webapp).
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId,
    [string]$Root, [string]$RepoRoot, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "scripts\helpers.psm1") -Force

Write-Banner "[4/5] Build & deploy container image"
$gen = Get-GeneratedConfig $Root
if (-not $gen.AcrName) { throw "ACR not provisioned — run 02_provision_infra.ps1 first" }
if (-not $gen.StagePath -or -not (Test-Path $gen.StagePath)) { throw "Stage area missing — run 03_inject_config.ps1 first" }

$tag = "v" + (Get-Date -Format "yyyyMMddHHmmss")
Set-GeneratedValue $Root "ImageTag" $tag

if ($DryRun) { Write-Host "  [DRY-RUN] would build & deploy $tag"; return }

$ctx = Join-Path $env:TEMP "${BrandName}-ctx"
if (Test-Path $ctx) { Remove-Item $ctx -Recurse -Force }
New-Item $ctx -ItemType Directory | Out-Null
New-Item "$ctx\AIAgent" -ItemType Directory | Out-Null

# Backend (from repo — read-only)
Copy-Item (Join-Path $RepoRoot "AIAgent\requirements.txt") "$ctx\AIAgent\requirements.txt"
Copy-Item (Join-Path $RepoRoot "AIAgent\app")              "$ctx\AIAgent\app"  -Recurse
Copy-Item (Join-Path $RepoRoot "AIAgent\main.py")          "$ctx\AIAgent\main.py"

# Webapp (from STAGED — has injected tokens, NOT the repo source)
Copy-Item (Join-Path $gen.StagePath "webapp") "$ctx\webapp" -Recurse

Write-Host "  Building image $tag in ACR $($gen.AcrName) …"
az acr build --registry $gen.AcrName --image "$($gen.ContainerAppName):$tag" `
    --file "AIAgent/Dockerfile" $ctx --no-logs

# Copy Dockerfile from repo (read-only) into context for ACR build path
# (already referenced via --file flag pointing to repo; nothing copied)

Write-Host "  Deploying $tag to Container App …"
az containerapp update --name $gen.ContainerAppName --resource-group $gen.ResourceGroup `
    --image "$($gen.AcrName).azurecr.io/$($gen.ContainerAppName):$tag" -o table

Write-Host "  Deployed: https://$($gen.BackendFqdn)/" -ForegroundColor Green
