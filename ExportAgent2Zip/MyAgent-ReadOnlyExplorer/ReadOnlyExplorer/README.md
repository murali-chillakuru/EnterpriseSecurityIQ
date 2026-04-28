# ReadOnlyExplorerIQ — ReadOnlyExplorer

Isolated, deployable copy of the **ReadOnlyExplorer** agent generated from the
EnterpriseSecurityIQ source repository.

## One-command setup

Prerequisites:
- PowerShell 7+
- Azure CLI logged in (`az login`)
- Subscription Contributor + Entra **Application Administrator** (or Owner)
- Python 3.12+ (only for local backend testing)

```powershell
.\setup.ps1 -BrandName "ReadOnlyExplorerIQ" -Location "northeurope" -SubscriptionId "<your-sub-id>"
```

This will automatically:

1. Create an Entra app registration (SPA + Web redirect URIs, Graph + ARM scopes, admin consent)
2. Provision Foundry + ACR + Container Apps environment + Container App + Storage
3. Inject the generated clientId / tenantId / FQDN into:
   - `webapp/*.html` (MSAL_CONFIG)
   - `teams/appPackage/manifest.json` (id, validDomains, webApplicationInfo)
   - `Infra-Foundary-New/deploy.ps1` (resource names)
4. Build the container image in ACR and deploy it to the Container App
5. Package and validate the Teams app zip (under `teams/appPackage/build/`)

After setup completes, the deployed URL and Teams app zip path are printed.

## Tools included

- `search_tenant`
- `check_permissions`

## Pages included

- `CloudExplorer.html`

## Manual customization (optional)

Edit `automation/.config.json` after `setup.ps1` runs to change names/regions
before re-running individual scripts under `automation/`.

## Teardown

```powershell
.\automation\99_teardown.ps1
```

Deletes the resource group created by setup.
