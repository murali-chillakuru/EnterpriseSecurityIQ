# helpers.psm1 — shared functions for automation scripts

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
