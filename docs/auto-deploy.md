# Auto-Deploy

> One-command end-to-end deployment of the EnterpriseSecurityIQ repo to a fresh
> Azure environment under any brand name — without modifying a single tracked
> file in the repository.

The [`auto-deploy/`](../auto-deploy/) folder ships a thin orchestration layer on
top of the existing [`Infra-Foundary-New/deploy.ps1`](../Infra-Foundary-New/deploy.ps1)
template. It adds the missing pieces required to make a fresh tenant operational
end-to-end (Entra app registration, brand token injection, image build, Teams
package zip) without touching any source file.

> Note: this complements the existing manual flow described in
> [Deployment](deployment.md) — both flows continue to coexist.

## When to use

| Scenario | Recommended flow |
|---|---|
| New brand or tenant | `auto-deploy/setup.ps1` (this page) |
| Update existing `esiqnew-agent` deployment | Manual flow described in [Deployment](deployment.md) |
| Isolated single-tool zip for a customer | Packager under [`ExportAgent2Zip/`](../ExportAgent2Zip/) |

## Prerequisites

- PowerShell 7+
- Azure CLI logged in (`az login`)
- Subscription **Contributor** + Entra **Application Administrator** (or Owner)
- Python only required for the packager — not for `auto-deploy`

## Quick start

```powershell
.\auto-deploy\setup.ps1 -BrandName "MyBrand" -SubscriptionId "AI"
```

Optional parameters:

| Parameter | Default | Purpose |
|---|---|---|
| `-Location` | `swedencentral` | Region for Foundry |
| `-ContainerAppsLocation` | `northeurope` | Region for Container App + ACR |
| `-SkipEntra` | – | Skip phase 1 |
| `-SkipInfra` | – | Skip phase 2 |
| `-SkipBuild` | – | Skip phase 4 |
| `-SkipTeams` | – | Skip phase 5 |
| `-DryRun` | – | Print actions without changing anything |

## Phases

| # | Script | Action |
|---|---|---|
| 1 | `01_provision_entra.ps1` | Creates `<BrandName>-Agent` app registration with SPA + Web redirects, Microsoft Graph `User.Read` + ARM `user_impersonation` scopes, admin consent, service principal |
| 2 | `02_provision_infra.ps1` | Invokes existing `Infra-Foundary-New/deploy.ps1` with `-BaseName <BrandName>` and captures the resulting Container App FQDN |
| 3 | `03_inject_config.ps1` | Copies `webapp/` + `teams/appPackage/` into `auto-deploy/staged/` and replaces the hardcoded clientId + token placeholders. **Source files are never modified.** Adds the SPA redirect URIs to the Entra app |
| 4 | `04_build_and_deploy.ps1` | Temp-context ACR build using `AIAgent/Dockerfile` and the staged webapp, deploys the new tag to Container App |
| 5 | `05_publish_teams_app.ps1` | Zips manifest + icons into `auto-deploy/.generated/teams/<Brand>-teams-app.zip` |

State is persisted to `auto-deploy/.generated/runtime.json` so re-runs are
idempotent. Re-running `setup.ps1` after a partial failure resumes from the
first incomplete phase.

## Resource naming

`auto-deploy` follows the same convention as `Infra-Foundary-New/deploy.ps1`:

| Resource | Name pattern (BrandName = `MyBrand`) |
|---|---|
| Resource group | `MyBrand-RG` |
| AI / Foundry | `MyBrand-AI` |
| Foundry project | `MyBrand-project` |
| Storage | `mybrandstorage` |
| Key Vault | `MyBrand-kv` |
| App Insights | `MyBrand-appinsights` |
| Log Analytics | `MyBrand-law` |
| Container Registry | `mybrandacr` |
| Managed Identity | `MyBrand-identity` |
| Container Apps Env | `MyBrand-env` |
| Container App | `mybrand-agent` |

## Token injection

`03_inject_config.ps1` rewrites the staged copy of every `webapp/*.html` file
plus `teams/appPackage/manifest.json`. Replacements:

| Token / source value | Replaced with |
|---|---|
| `ffb6f10d-6991-430e-b3d6-23a0101a92b1` (hardcoded MSAL clientId) | Generated Entra `EntraClientId` |
| `{{ENTRA_CLIENT_ID}}` | Generated Entra `EntraClientId` |
| `{{TEAMS_APP_ID}}` | Newly minted GUID |
| `{{BACKEND_FQDN}}` | Container App FQDN |
| `{{TENANT_ID}}` | Current `az account` tenant |

The repo source remains byte-identical — only the staged copy is mutated.

## Layout

```
auto-deploy/
├── setup.ps1                       ← entrypoint
├── README.md
├── scripts/
│   ├── helpers.psm1
│   ├── 01_provision_entra.ps1
│   ├── 02_provision_infra.ps1
│   ├── 03_inject_config.ps1
│   ├── 04_build_and_deploy.ps1
│   ├── 05_publish_teams_app.ps1
│   └── 99_teardown.ps1
├── .generated/                     ← runtime state + Teams zip (gitignored)
│   ├── runtime.json
│   └── teams/<Brand>-teams-app.zip
└── staged/                         ← temp build copy of webapp/ + teams/ (gitignored)
```

## Re-using and resuming

- `auto-deploy/.generated/runtime.json` records every generated value
  (`EntraClientId`, `BackendFqdn`, `ResourceGroup`, `AcrName`,
  `ContainerAppName`, `TeamsAppId`, `ImageTag`, `StagePath`, `TeamsAppZip`).
- Each phase script short-circuits when its state is already present — safe to
  re-run `setup.ps1` after fixing a transient error.
- To force a fresh provisioning, delete `auto-deploy/.generated/runtime.json`
  and `auto-deploy/staged/` before re-running.

## Teardown

```powershell
.\auto-deploy\scripts\99_teardown.ps1
```

Deletes the resource group (`az group delete --no-wait`) and the Entra app.
Local files in `auto-deploy/` (state + Teams zip) remain on disk so you can
re-deploy quickly if needed.

## Relationship to other deployment paths

| Path | Modifies repo? | Best for |
|---|---|---|
| `auto-deploy/setup.ps1` | No | Fresh brand/tenant, end-to-end |
| `Infra-Foundary-New/deploy.ps1` (manual) | No | Infra-only provisioning |
| `ExportAgent2Zip/MyAgent-*/<Name>.zip` + `setup.ps1` | No | Single-tool isolated package, deployable on a different repo or by an external customer |

All three flows respect the same naming conventions and share the same
`Infra-Foundary-New/` template under the hood, so resources provisioned by one
path are recognised by the others.

## See also

- [Deployment](deployment.md) — manual ACR build + Container App revision
- [Architecture](architecture.md) — runtime topology
- [Configuration](configuration.md) — environment variables and secrets
- [`auto-deploy/README.md`](../auto-deploy/README.md) — script-level reference
