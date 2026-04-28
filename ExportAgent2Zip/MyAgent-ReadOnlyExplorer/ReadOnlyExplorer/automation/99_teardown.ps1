<#
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
