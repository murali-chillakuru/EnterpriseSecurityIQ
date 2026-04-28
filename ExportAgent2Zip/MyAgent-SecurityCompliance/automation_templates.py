"""
PowerShell automation templates inserted into the staged copy.

The packager substitutes {{DEFAULT_BRAND}} and {{AGENT_NAME}} before writing.
At runtime, the scripts substitute deploy-time tokens like {{ENTRA_CLIENT_ID}},
{{TEAMS_APP_ID}}, {{BACKEND_FQDN}} etc. into the staged HTML/JSON files.
"""

SETUP_PS1 = r'''<#
.SYNOPSIS
    One-command setup for {{DEFAULT_BRAND}} ({{AGENT_NAME}}) on Azure + Teams.

.DESCRIPTION
    Orchestrates the full provisioning flow:
      1. Entra app registration (SPA + Teams + scopes + admin consent)
      2. Azure infra (Foundry + ACR + Container App + Storage)
      3. Token injection into webapp + manifest + deploy script
      4. ACR build + Container App deploy
      5. Teams app package generation

    Idempotent — re-runnable. State stored in automation/.generated.json.

.PARAMETER BrandName
    Resource prefix and display brand. Default: {{DEFAULT_BRAND}}

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
    [string]$BrandName              = "{{DEFAULT_BRAND}}",
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

Write-Banner "Setup — $BrandName ({{AGENT_NAME}})"
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
'''

HELPERS_PSM1 = r'''# helpers.psm1 — shared functions for automation scripts

function Write-Banner {
    param([string]$Message)
    $line = "═" * 64
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Get-GeneratedConfigPath { param([string]$Root) Join-Path $Root "automation\.generated.json" }

function Get-GeneratedConfig {
    param([string]$Root)
    $p = Get-GeneratedConfigPath $Root
    if (Test-Path $p) { return Get-Content $p -Raw | ConvertFrom-Json }
    return [pscustomobject]@{}
}

function Set-GeneratedValue {
    param([string]$Root, [string]$Key, $Value)
    $p   = Get-GeneratedConfigPath $Root
    $obj = if (Test-Path $p) { Get-Content $p -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
    if ($obj.PSObject.Properties.Name -contains $Key) { $obj.$Key = $Value }
    else { $obj | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force }
    $obj | ConvertTo-Json -Depth 5 | Set-Content $p -Encoding UTF8
}

function Compute-ResourceNames {
    param([string]$BrandName)
    $lower = $BrandName.ToLower()
    return @{
        ResourceGroup     = "$BrandName-RG"
        AIName            = "$BrandName-AI"
        ProjectName       = "$BrandName-project"
        StorageName       = "${lower}storage"
        KeyVaultName      = "$BrandName-kv"
        AppInsightsName   = "$BrandName-appinsights"
        LawName           = "$BrandName-law"
        AcrName           = "${lower}acr"
        IdentityName      = "$BrandName-identity"
        ContainerAppEnv   = "$BrandName-env"
        ContainerAppName  = "${lower}-agent"
    }
}

Export-ModuleMember -Function *
'''

PS_01_ENTRA = r'''<#
.SYNOPSIS Provision Entra app registration with SPA + Teams config.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId, [string]$Root, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "automation\helpers.psm1") -Force

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

# Add Microsoft Graph User.Read delegated permission
az ad app permission add --id $clientId --api 00000003-0000-0000-c000-000000000000 `
    --api-permissions "e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope" 2>$null | Out-Null
# Add ARM user_impersonation
az ad app permission add --id $clientId --api 797f4846-ba00-4fd7-ba43-dac1f8f63013 `
    --api-permissions "41094075-9dad-400e-a0bd-54e686782033=Scope" 2>$null | Out-Null

# Grant admin consent
try { az ad app permission admin-consent --id $clientId 2>$null | Out-Null }
catch { Write-Warning "  Admin consent failed — grant manually: az ad app permission admin-consent --id $clientId" }

# Service principal
az ad sp create --id $clientId 2>$null | Out-Null

Set-GeneratedValue $Root "EntraClientId" $clientId
Set-GeneratedValue $Root "EntraDisplayName" $displayName
Write-Host "  Saved to .generated.json" -ForegroundColor DarkGray
'''

PS_02_INFRA = r'''<#
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
'''

PS_03_INJECT = r'''<#
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
'''

PS_04_BUILD = r'''<#
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
'''

PS_05_TEAMS = r'''<#
.SYNOPSIS Package Teams app zip.
#>
[CmdletBinding()]
param(
    [string]$BrandName, [string]$Location, [string]$ContainerAppsLocation,
    [string]$SubscriptionId, [string]$TenantId, [string]$Root, [switch]$DryRun
)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "automation\helpers.psm1") -Force

Write-Banner "[5/5] Teams app package"
$gen = Get-GeneratedConfig $Root
$pkgDir = Join-Path $Root "teams\appPackage"
if (-not (Test-Path $pkgDir)) { Write-Host "  No teams/appPackage in this build — skipping"; return }

$buildDir = Join-Path $pkgDir "build"
New-Item $buildDir -ItemType Directory -Force | Out-Null
$zipPath = Join-Path $buildDir "$BrandName-teams-app.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

if ($DryRun) { Write-Host "  [DRY-RUN] would package $zipPath"; return }

# Zip manifest + icons (only)
$files = @(
    Join-Path $pkgDir "manifest.json",
    Join-Path $pkgDir "color.png",
    Join-Path $pkgDir "outline.png"
) | Where-Object { Test-Path $_ }

Compress-Archive -Path $files -DestinationPath $zipPath -Force
Set-GeneratedValue $Root "TeamsAppZip" $zipPath

Write-Host "  Teams app zip: $zipPath" -ForegroundColor Green
Write-Host "  Sideload via Teams admin center or run:"
Write-Host "    m365 teams app publish --filePath `"$zipPath`""
'''

PS_99_TEARDOWN = r'''<#
.SYNOPSIS Delete the resource group + Entra app created by setup.ps1.
#>
[CmdletBinding()]
param([string]$Root = $PSScriptRoot)
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $Root "helpers.psm1") -Force
$gen = Get-GeneratedConfig (Split-Path $Root)
if ($gen.ResourceGroup) {
    Write-Host "Deleting resource group $($gen.ResourceGroup) …"
    az group delete --name $gen.ResourceGroup --yes --no-wait
}
if ($gen.EntraClientId) {
    Write-Host "Deleting Entra app $($gen.EntraClientId) …"
    az ad app delete --id $gen.EntraClientId
}
Write-Host "Teardown initiated."
'''


AUTOMATION_FILES = {
    "setup.ps1":                    SETUP_PS1,
    "helpers.psm1":                 HELPERS_PSM1,
    "01_provision_entra.ps1":       PS_01_ENTRA,
    "02_provision_infra.ps1":       PS_02_INFRA,
    "03_inject_config.ps1":         PS_03_INJECT,
    "04_build_and_deploy.ps1":      PS_04_BUILD,
    "05_publish_teams_app.ps1":     PS_05_TEAMS,
    "99_teardown.ps1":              PS_99_TEARDOWN,
}
