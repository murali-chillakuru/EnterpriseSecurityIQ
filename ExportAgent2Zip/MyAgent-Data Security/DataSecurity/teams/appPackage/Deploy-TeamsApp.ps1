<#
.SYNOPSIS
    PostureIQ Teams App Deployment Script (Generic / Multi-Tenant)
    Supports both "Upload a custom app" (sideload) and "Submit an app to your org" (org catalog).

.DESCRIPTION
    This script:
      1. Replaces {{TEAMS_APP_ID}} and {{BACKEND_FQDN}} placeholders in manifest.json
      2. Validates the manifest, icons, and backend health
      3. Builds a ready-to-deploy PostureIQ.zip
      4. Optionally deploys via Microsoft Graph API

    The original template manifest is never modified — a working copy is used for the build.

.PARAMETER EntraAppId
    The Entra ID Application (client) ID for your tenant's app registration.
    This becomes the Teams manifest "id" and "webApplicationInfo.id".

.PARAMETER BackendFqdn
    The FQDN of your PostureIQ Container App (without https://).
    Example: esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io

.PARAMETER Mode
    Deployment mode: Validate, Build, Sideload, OrgPublish, EntraConfig, Full
      - EntraConfig : Configure Entra app registration (scope, redirects, pre-authorized clients)
      - Full        : EntraConfig + Build + Sideload in one command

.PARAMETER OutputDir
    Directory where the built PostureIQ.zip is placed. Defaults to a "build" subfolder.

.EXAMPLE
    # Validate only
    .\Deploy-TeamsApp.ps1 -EntraAppId "ffb6f10d-..." -BackendFqdn "myapp.azurecontainerapps.io" -Mode Validate

    # Build package
    .\Deploy-TeamsApp.ps1 -EntraAppId "ffb6f10d-..." -BackendFqdn "myapp.azurecontainerapps.io" -Mode Build

    # Sideload for current user
    .\Deploy-TeamsApp.ps1 -EntraAppId "ffb6f10d-..." -BackendFqdn "myapp.azurecontainerapps.io" -Mode Sideload

    # Submit to org catalog
    .\Deploy-TeamsApp.ps1 -EntraAppId "ffb6f10d-..." -BackendFqdn "myapp.azurecontainerapps.io" -Mode OrgPublish

    # Configure Entra only (API scope, SPA redirects, pre-authorized clients)
    .\Deploy-TeamsApp.ps1 -EntraAppId "ffb6f10d-..." -BackendFqdn "myapp.azurecontainerapps.io" -Mode EntraConfig

    # Full deployment (EntraConfig + Build + Sideload)
    .\Deploy-TeamsApp.ps1 -EntraAppId "ffb6f10d-..." -BackendFqdn "myapp.azurecontainerapps.io" -Mode Full
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Entra App Registration client ID (GUID)")]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$EntraAppId,

    [Parameter(Mandatory = $true, HelpMessage = "Backend FQDN (e.g. myapp.azurecontainerapps.io)")]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9\.\-]+[a-zA-Z0-9]$')]
    [string]$BackendFqdn,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Validate", "Build", "Sideload", "OrgPublish", "EntraConfig", "Full")]
    [string]$Mode = "Build",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

# ── Configuration ─────────────────────────────────────────────────────────────
$ScriptDir        = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TemplateManifest = Join-Path $ScriptDir "manifest.json"
$ColorIcon        = Join-Path $ScriptDir "color.png"
$OutlineIcon      = Join-Path $ScriptDir "outline.png"
$HealthUrl        = "https://$BackendFqdn/health"
$GraphBase        = "https://graph.microsoft.com/v1.0"

# Output directory: default to <script-dir>/build
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $ScriptDir "build"
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
$BuildManifest = Join-Path $OutputDir "manifest.json"
$BuildColor    = Join-Path $OutputDir "color.png"
$BuildOutline  = Join-Path $OutputDir "outline.png"
$ZipPath       = Join-Path $OutputDir "PostureIQ.zip"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Status($Icon, $Message, $Color = "White") {
    Write-Host "  $Icon " -NoNewline -ForegroundColor $Color
    Write-Host $Message
}
function Write-Pass($Msg)  { Write-Status "[PASS]" $Msg "Green" }
function Write-Fail($Msg)  { Write-Status "[FAIL]" $Msg "Red" }
function Write-Info($Msg)  { Write-Status "[INFO]" $Msg "Cyan" }
function Write-Warn($Msg)  { Write-Status "[WARN]" $Msg "Yellow" }

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 0 — RESOLVE TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-ResolveTemplate {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PHASE 0 — RESOLVE TEMPLATE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

    # Read template
    if (-not (Test-Path $TemplateManifest)) {
        Write-Fail "Template manifest.json not found at $TemplateManifest"
        return $false
    }
    $template = Get-Content $TemplateManifest -Raw

    # Check for placeholders
    $hasAppId = $template -match '\{\{TEAMS_APP_ID\}\}'
    $hasFqdn  = $template -match '\{\{BACKEND_FQDN\}\}'

    if ($hasAppId) { Write-Info "Replacing {{TEAMS_APP_ID}} -> $EntraAppId" }
    if ($hasFqdn)  { Write-Info "Replacing {{BACKEND_FQDN}} -> $BackendFqdn" }

    if (-not $hasAppId -and -not $hasFqdn) {
        Write-Warn "No placeholders found — manifest may already be resolved"
    }

    # Replace placeholders
    $resolved = $template -replace '\{\{TEAMS_APP_ID\}\}', $EntraAppId
    $resolved = $resolved -replace '\{\{BACKEND_FQDN\}\}', $BackendFqdn

    # Write resolved manifest to build dir
    Set-Content -Path $BuildManifest -Value $resolved -Encoding UTF8
    Write-Pass "Resolved manifest written to: $BuildManifest"

    # Copy icons to build dir
    Copy-Item $ColorIcon  $BuildColor  -Force
    Copy-Item $OutlineIcon $BuildOutline -Force
    Write-Pass "Icons copied to build directory"

    return $true
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — VALIDATE
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Validate {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PHASE 1 — VALIDATE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    $errors = 0

    # 1. Resolved manifest exists
    if (-not (Test-Path $BuildManifest)) {
        Write-Fail "Resolved manifest not found at $BuildManifest"
        return 1
    }

    # 2. Parse JSON
    try {
        $manifest = Get-Content $BuildManifest -Raw | ConvertFrom-Json
        Write-Pass "manifest.json is valid JSON"
    } catch {
        Write-Fail "manifest.json has invalid JSON: $_"
        return 1
    }

    # 3. No unresolved placeholders
    $raw = Get-Content $BuildManifest -Raw
    if ($raw -match '\{\{[A-Z_]+\}\}') {
        Write-Fail "Unresolved placeholders found in manifest: $($Matches[0])"
        $errors++
    } else {
        Write-Pass "No unresolved placeholders"
    }

    # 4. Required fields
    $checks = @(
        @{ Field = 'manifestVersion'; Expected = '' },
        @{ Field = 'id';              Expected = $EntraAppId }
    )
    # Validate manifest version is supported
    $mv = $manifest.manifestVersion
    if ($mv -and ([version]$mv -ge [version]'1.17')) {
        Write-Pass "manifestVersion = '$mv'"
    } elseif ($mv) {
        Write-Fail "manifestVersion = '$mv' (expected 1.17 or later)"; $errors++
    }
    foreach ($c in $checks) {
        $val = $manifest.PSObject.Properties[$c.Field]
        if ($null -eq $val) {
            Write-Fail "Missing field: $($c.Field)"; $errors++
        } elseif ($c.Expected -and $val.Value -ne $c.Expected) {
            Write-Fail "$($c.Field) = '$($val.Value)' (expected '$($c.Expected)')"; $errors++
        } else {
            Write-Pass "$($c.Field) = '$($val.Value)'"
        }
    }

    # 5. App name
    if ($manifest.name.short) {
        Write-Pass "App name: $($manifest.name.short)"
    } else { Write-Fail "Missing name.short"; $errors++ }

    # 6. Static tabs
    $tabCount = ($manifest.staticTabs | Measure-Object).Count
    if ($tabCount -ge 1) {
        Write-Pass "$tabCount static tab(s) configured"
        foreach ($tab in $manifest.staticTabs) {
            $path = $tab.contentUrl -replace 'https://[^/]+', ''
            Write-Info "  Tab: $($tab.name) -> $path"
        }
    } else { Write-Fail "No static tabs found"; $errors++ }

    # 7. webApplicationInfo
    if ($manifest.webApplicationInfo.id -eq $EntraAppId) {
        Write-Pass "webApplicationInfo.id matches Entra App ID"
    } else {
        Write-Fail "webApplicationInfo.id = '$($manifest.webApplicationInfo.id)' (expected '$EntraAppId')"
        $errors++
    }

    # 8. validDomains includes FQDN
    if ($manifest.validDomains -contains $BackendFqdn) {
        Write-Pass "validDomains includes $BackendFqdn"
    } else { Write-Warn "validDomains does not include $BackendFqdn" }

    # 9. Icons
    foreach ($icon in @(@{N="color.png";P=$BuildColor}, @{N="outline.png";P=$BuildOutline})) {
        if (Test-Path $icon.P) {
            $sz = (Get-Item $icon.P).Length
            Write-Pass "$($icon.N) found ($sz bytes)"
        } else { Write-Fail "$($icon.N) NOT found"; $errors++ }
    }

    # 10. Backend health
    Write-Info "Checking backend health: $HealthUrl"
    try {
        $resp = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 15
        if ($resp.StatusCode -eq 200) {
            Write-Pass "Backend is healthy (HTTP $($resp.StatusCode))"
        } else { Write-Warn "Backend returned HTTP $($resp.StatusCode)" }
    } catch {
        Write-Warn "Backend health check failed: $($_.Exception.Message)"
        Write-Warn "Package is still valid — backend may be temporarily unavailable"
    }

    Write-Host ""
    if ($errors -eq 0) {
        Write-Host "  Validation PASSED — 0 errors" -ForegroundColor Green
    } else {
        Write-Host "  Validation FAILED — $errors error(s)" -ForegroundColor Red
    }
    return $errors
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — BUILD
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Build {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PHASE 2 — BUILD PACKAGE" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

    if (Test-Path $ZipPath) {
        Remove-Item $ZipPath -Force
        Write-Info "Removed old PostureIQ.zip"
    }

    Compress-Archive -Path $BuildManifest, $BuildColor, $BuildOutline -DestinationPath $ZipPath -CompressionLevel Optimal
    $zipSize = (Get-Item $ZipPath).Length
    Write-Pass "PostureIQ.zip created ($zipSize bytes)"

    # Verify contents
    $zipEntries = [System.IO.Compression.ZipFile]::OpenRead($ZipPath).Entries.Name
    foreach ($expected in @("manifest.json", "color.png", "outline.png")) {
        if ($zipEntries -contains $expected) {
            Write-Pass "  Contains: $expected"
        } else { Write-Fail "  Missing: $expected" }
    }

    Write-Host ""
    Write-Host "  Package ready: $ZipPath" -ForegroundColor Green
    return $ZipPath
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3A — SIDELOAD
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Sideload {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PHASE 3A — SIDELOAD (Upload a Custom App)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

    $hasGraph = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph.Teams -ErrorAction SilentlyContinue)

    if ($hasGraph) {
        Write-Info "Microsoft.Graph.Teams module found"
        try {
            Import-Module Microsoft.Graph.Teams -ErrorAction Stop
            Connect-MgGraph -Scopes @("TeamsAppInstallation.ReadWriteForUser") -ErrorAction Stop
            $me = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/me"
            Write-Pass "Signed in as: $($me.displayName) ($($me.userPrincipalName))"

            # Check existing
            $installed = Invoke-MgGraphRequest -Method GET `
                -Uri "$GraphBase/users/$($me.id)/teamwork/installedApps?`$expand=teamsAppDefinition"
            $existing = $installed.value | Where-Object { $_.teamsAppDefinition.teamsAppId -eq $EntraAppId }
            if ($existing) {
                Write-Warn "PostureIQ already installed — removing old version"
                Invoke-MgGraphRequest -Method DELETE `
                    -Uri "$GraphBase/users/$($me.id)/teamwork/installedApps/$($existing.id)"
                Write-Pass "Old version removed"
            }

            # Upload to personal catalog then install
            $catalogUri = "$GraphBase/appCatalogs/teamsApps?requiresReview=false"
            $result = Invoke-MgGraphRequest -Method POST -Uri $catalogUri `
                -InputFilePath $ZipPath -ContentType "application/zip"
            Write-Pass "Uploaded to catalog (teamsAppId: $($result.id))"

            $body = @{ "teamsApp@odata.bind" = "$GraphBase/appCatalogs/teamsApps/$($result.id)" } | ConvertTo-Json
            Invoke-MgGraphRequest -Method POST `
                -Uri "$GraphBase/users/$($me.id)/teamwork/installedApps" `
                -Body $body -ContentType "application/json"
            Write-Pass "PostureIQ installed for $($me.displayName)!"
            return
        } catch {
            Write-Warn "Graph API sideload failed: $($_.Exception.Message)"
        }
    } else {
        Write-Info "Microsoft.Graph.Teams module not installed (optional)"
    }

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  MANUAL: Upload a Custom App                       │" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  1. Open Microsoft Teams                           │" -ForegroundColor White
    Write-Host "  │  2. Apps -> Manage your apps -> Upload an app      │" -ForegroundColor White
    Write-Host "  │  3. Select 'Upload a custom app'                   │" -ForegroundColor White
    Write-Host "  │  4. Browse to:                                     │" -ForegroundColor White
    Write-Host "  │     $ZipPath" -ForegroundColor Cyan
    Write-Host "  │  5. Click 'Add' to install                         │" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor Yellow
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3B — ORG PUBLISH
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-OrgPublish {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PHASE 3B — ORG PUBLISH (Submit to Org Catalog)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

    $hasGraph = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph.Teams -ErrorAction SilentlyContinue)

    if ($hasGraph) {
        Write-Info "Microsoft.Graph.Teams module found"
        try {
            Import-Module Microsoft.Graph.Teams -ErrorAction Stop
            Connect-MgGraph -Scopes @("AppCatalog.Submit") -ErrorAction Stop
            $me = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/me"
            Write-Pass "Signed in as: $($me.displayName) ($($me.userPrincipalName))"

            $catalogUri = "$GraphBase/appCatalogs/teamsApps?requiresReview=true"
            $result = Invoke-MgGraphRequest -Method POST -Uri $catalogUri `
                -InputFilePath $ZipPath -ContentType "application/zip"
            Write-Pass "Submitted to org catalog (teamsAppId: $($result.id))"
            Write-Info "Status: Pending admin approval"
            Write-Host ""
            Write-Host "  Admin must approve at: https://admin.teams.microsoft.com" -ForegroundColor Green
            return
        } catch {
            Write-Warn "Graph API org publish failed: $($_.Exception.Message)"
        }
    } else {
        Write-Info "Microsoft.Graph.Teams module not installed (optional)"
    }

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor Magenta
    Write-Host "  │  MANUAL: Submit an App to Your Org                 │" -ForegroundColor Magenta
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor Magenta
    Write-Host "  │  1. Open Microsoft Teams                           │" -ForegroundColor White
    Write-Host "  │  2. Apps -> Manage your apps -> Upload an app      │" -ForegroundColor White
    Write-Host "  │  3. Select 'Submit an app to your org'             │" -ForegroundColor White
    Write-Host "  │  4. Browse to:                                     │" -ForegroundColor White
    Write-Host "  │     $ZipPath" -ForegroundColor Cyan
    Write-Host "  │  5. App enters 'Pending approval' state            │" -ForegroundColor White
    Write-Host "  │  6. Admin approves at:                             │" -ForegroundColor White
    Write-Host "  │     https://admin.teams.microsoft.com              │" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor Magenta
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE E — ENTRA CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-EntraConfig {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  PHASE E — ENTRA APP CONFIGURATION" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

    # ── Verify az CLI is signed in ──────────────────────────────────────────
    Write-Info "Checking Azure CLI sign-in..."
    try {
        $acct = az account show --query "{name:name, user:user.name}" -o json 2>$null | ConvertFrom-Json
        if (-not $acct) { throw "not signed in" }
        Write-Pass "Signed in as: $($acct.user) ($($acct.name))"
    } catch {
        Write-Fail "Azure CLI not signed in. Run 'az login' first."
        return $false
    }

    # ── Fetch current app registration ──────────────────────────────────────
    Write-Info "Fetching app registration $EntraAppId..."
    $appJson = az ad app show --id $EntraAppId -o json 2>$null
    if (-not $appJson) {
        Write-Fail "App registration $EntraAppId not found"
        return $false
    }
    $app = $appJson | ConvertFrom-Json
    $appObjectId = $app.id
    Write-Pass "Found: $($app.displayName) (objectId: $appObjectId)"

    # ── Constants ───────────────────────────────────────────────────────────
    $ApplicationIdUri = "api://$BackendFqdn/$EntraAppId"
    $ScopeName        = "access_as_user"
    $ScopeDesc        = "Access PostureIQ as signed-in user"
    $BrkRedirect      = "brk-multihub://$BackendFqdn"
    $SpaRedirect      = "https://$BackendFqdn/Teams-SecurityComplianceAssessment.html"
    $AuthEndRedirect  = "https://$BackendFqdn/auth-end.html"

    # Pre-authorized Microsoft 365 client IDs (per MS docs)
    $PreAuthClients = @(
        @{ Name = "Teams desktop/mobile"; Id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264" },
        @{ Name = "Teams web";            Id = "5e3ce6c0-2b1f-4285-8d4b-75ee78787346" },
        @{ Name = "M365 web";             Id = "4765445b-32c6-49b0-83e6-1d93765276ca" },
        @{ Name = "M365 desktop";         Id = "0ec893e0-5785-4de6-99da-4ed124e5296c" },
        @{ Name = "M365 mobile/Outlook desktop"; Id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" },
        @{ Name = "Outlook web";          Id = "bc59ab01-8403-45c6-8796-ac3ef710b3e3" },
        @{ Name = "Outlook mobile";       Id = "27922004-5251-4030-b22d-91ecd9a37ea4" }
    )

    # ── Step 1: Application ID URI ─────────────────────────────────────────
    Write-Host ""
    Write-Info "Step 1: Application ID URI"
    $currentUri = $app.identifierUris
    if ($currentUri -contains $ApplicationIdUri) {
        Write-Pass "Application ID URI already set: $ApplicationIdUri"
    } else {
        Write-Info "Setting Application ID URI to: $ApplicationIdUri"
        az ad app update --id $EntraAppId --identifier-uris $ApplicationIdUri --output none
        if ($LASTEXITCODE -eq 0) {
            Write-Pass "Application ID URI set"
        } else {
            Write-Fail "Failed to set Application ID URI"
            return $false
        }
    }

    # ── Step 2: Expose access_as_user scope ────────────────────────────────
    Write-Host ""
    Write-Info "Step 2: API scope '$ScopeName'"
    $existingApi = $app.api
    $existingScope = $existingApi.oauth2PermissionScopes | Where-Object { $_.value -eq $ScopeName }

    if ($existingScope) {
        Write-Pass "Scope '$ScopeName' already exists (id: $($existingScope.id))"
        $scopeId = $existingScope.id
    } else {
        Write-Info "Creating scope '$ScopeName'..."
        $scopeId = [guid]::NewGuid().ToString()
        $scopePayload = @{
            api = @{
                oauth2PermissionScopes = @(
                    @{
                        id                      = $scopeId
                        adminConsentDescription = $ScopeDesc
                        adminConsentDisplayName = $ScopeDesc
                        userConsentDescription  = $ScopeDesc
                        userConsentDisplayName  = $ScopeDesc
                        isEnabled               = $true
                        type                    = "User"
                        value                   = $ScopeName
                    }
                )
            }
        }
        # Merge with any existing scopes
        if ($existingApi.oauth2PermissionScopes) {
            $scopePayload.api.oauth2PermissionScopes = @($existingApi.oauth2PermissionScopes) + $scopePayload.api.oauth2PermissionScopes
        }
        $tmpFile = [System.IO.Path]::GetTempFileName()
        $scopePayload | ConvertTo-Json -Depth 10 | Set-Content -Path $tmpFile -Encoding UTF8
        az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" --body "@$tmpFile" --headers "Content-Type=application/json" --output none
        $rc = $LASTEXITCODE
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
        if ($rc -eq 0) {
            Write-Pass "Scope '$ScopeName' created"
        } else {
            Write-Fail "Failed to create scope"
            return $false
        }
    }

    # ── Step 3: SPA redirect URIs ──────────────────────────────────────────
    Write-Host ""
    Write-Info "Step 3: SPA redirect URIs"
    $existingSpaRedirects = @()
    if ($app.spa -and $app.spa.redirectUris) {
        $existingSpaRedirects = @($app.spa.redirectUris)
    }

    $requiredRedirects = @($BrkRedirect, $SpaRedirect, $AuthEndRedirect)
    $missingRedirects = @()
    foreach ($uri in $requiredRedirects) {
        if ($existingSpaRedirects -contains $uri) {
            Write-Pass "SPA redirect exists: $uri"
        } else {
            Write-Info "Missing SPA redirect: $uri"
            $missingRedirects += $uri
        }
    }

    if ($missingRedirects.Count -gt 0) {
        $allRedirects = @($existingSpaRedirects) + $missingRedirects | Select-Object -Unique
        $spaPayload = @{ spa = @{ redirectUris = $allRedirects } }
        $tmpFile = [System.IO.Path]::GetTempFileName()
        $spaPayload | ConvertTo-Json -Depth 5 | Set-Content -Path $tmpFile -Encoding UTF8
        az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" --body "@$tmpFile" --headers "Content-Type=application/json" --output none
        $rc = $LASTEXITCODE
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
        if ($rc -eq 0) {
            Write-Pass "SPA redirect URIs updated ($($allRedirects.Count) total)"
        } else {
            Write-Fail "Failed to update SPA redirects"
            return $false
        }
    }

    # ── Step 4: Pre-authorized clients ─────────────────────────────────────
    Write-Host ""
    Write-Info "Step 4: Pre-authorized client applications"

    # Re-fetch app to get latest scope ID
    $appJson = az ad app show --id $EntraAppId -o json 2>$null | ConvertFrom-Json
    $scope = $appJson.api.oauth2PermissionScopes | Where-Object { $_.value -eq $ScopeName }
    if (-not $scope) {
        Write-Fail "Could not find scope '$ScopeName' after creation"
        return $false
    }
    $scopeId = $scope.id

    $existingPreAuth = @()
    if ($appJson.api.preAuthorizedApplications) {
        $existingPreAuth = @($appJson.api.preAuthorizedApplications)
    }
    $existingClientIds = $existingPreAuth | ForEach-Object { $_.appId }

    $newPreAuth = @($existingPreAuth)
    $addedCount = 0
    foreach ($client in $PreAuthClients) {
        if ($existingClientIds -contains $client.Id) {
            Write-Pass "Pre-authorized: $($client.Name) ($($client.Id))"
        } else {
            Write-Info "Adding: $($client.Name) ($($client.Id))"
            $newPreAuth += @{
                appId               = $client.Id
                delegatedPermissionIds = @($scopeId)
            }
            $addedCount++
        }
    }

    if ($addedCount -gt 0) {
        $preAuthPayload = @{
            api = @{
                preAuthorizedApplications = $newPreAuth
            }
        }
        $tmpFile = [System.IO.Path]::GetTempFileName()
        $preAuthPayload | ConvertTo-Json -Depth 10 | Set-Content -Path $tmpFile -Encoding UTF8
        az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" --body "@$tmpFile" --headers "Content-Type=application/json" --output none
        $rc = $LASTEXITCODE
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
        if ($rc -eq 0) {
            Write-Pass "Pre-authorized clients updated (+$addedCount new)"
        } else {
            Write-Fail "Failed to update pre-authorized clients"
            return $false
        }
    } else {
        Write-Pass "All 7 clients already pre-authorized"
    }

    # ── Summary ────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "  │  ENTRA CONFIGURATION COMPLETE                      │" -ForegroundColor Green
    Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor Green
    Write-Host "  │  App ID URI  : $ApplicationIdUri" -ForegroundColor White
    Write-Host "  │  Scope       : $ScopeName" -ForegroundColor White
    Write-Host "  │  SPA Redirects: $($requiredRedirects.Count) required" -ForegroundColor White
    Write-Host "  │  Pre-Auth    : $($PreAuthClients.Count) Microsoft clients" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor Green
    return $true
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         PostureIQ — Teams App Deployment                 ║" -ForegroundColor Cyan
Write-Host "║         Mode: $($Mode.PadRight(42))║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Entra App ID : $EntraAppId" -ForegroundColor White
Write-Host "  Backend FQDN : $BackendFqdn" -ForegroundColor White
Write-Host "  Output Dir   : $OutputDir" -ForegroundColor White

# Phase 0 — Resolve template
$resolved = Invoke-ResolveTemplate
if (-not $resolved) { exit 1 }

# EntraConfig mode — run Entra setup, then optionally continue to Build+Sideload
if ($Mode -eq "EntraConfig") {
    $ok = Invoke-EntraConfig
    if (-not $ok) { Write-Host "  Entra configuration failed" -ForegroundColor Red; exit 1 }
    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

if ($Mode -eq "Full") {
    # Step 1: Entra config
    $ok = Invoke-EntraConfig
    if (-not $ok) { Write-Host "  Entra configuration failed — aborting" -ForegroundColor Red; exit 1 }
}

# Phase 1 — Validate
Add-Type -AssemblyName System.IO.Compression.FileSystem
$validationErrors = Invoke-Validate

if ($Mode -eq "Validate") {
    if ($validationErrors -eq 0) { exit 0 } else { exit 1 }
}

if ($validationErrors -gt 0) {
    Write-Host ""
    Write-Host "  Aborting — fix validation errors first" -ForegroundColor Red
    exit 1
}

# Phase 2 — Build
Invoke-Build

# Phase 3 — Deploy
switch ($Mode) {
    "Build" {
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  NEXT STEPS — Choose a deployment path:" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Path A: Upload a custom app (personal / testing)" -ForegroundColor Yellow
        Write-Host "    .\Deploy-TeamsApp.ps1 -EntraAppId $EntraAppId -BackendFqdn $BackendFqdn -Mode Sideload" -ForegroundColor White
        Write-Host ""
        Write-Host "  Path B: Submit to your org (all users)" -ForegroundColor Magenta
        Write-Host "    .\Deploy-TeamsApp.ps1 -EntraAppId $EntraAppId -BackendFqdn $BackendFqdn -Mode OrgPublish" -ForegroundColor White
        Write-Host ""
        Write-Host "  Path C: Full deployment (Entra + Build + Sideload)" -ForegroundColor Green
        Write-Host "    .\Deploy-TeamsApp.ps1 -EntraAppId $EntraAppId -BackendFqdn $BackendFqdn -Mode Full" -ForegroundColor White
        Write-Host ""
        Write-Host "  Or upload $ZipPath manually in Teams." -ForegroundColor Gray
    }
    "Sideload"    { Invoke-Sideload }
    "OrgPublish"  { Invoke-OrgPublish }
    "Full"        { Invoke-Sideload }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
