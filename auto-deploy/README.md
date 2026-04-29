# auto-deploy — Repo-level one-command deployment

Deploy this entire EnterpriseSecurityIQ repo to a fresh Azure environment under
**any brand name** without modifying a single tracked file in the repo.

## Prerequisites

- PowerShell 7+
- Azure CLI logged in (`az login`)
- Azure Subscription **Contributor** + Entra **Application Administrator** (or Owner)

## Usage

```powershell
.\auto-deploy\setup.ps1 -BrandName "MyBrand" -SubscriptionId "AI"
```

Optional parameters:
- `-Location` (default `swedencentral`)
- `-ContainerAppsLocation` (default `northeurope`)
- `-SkipEntra` / `-SkipInfra` / `-SkipBuild` / `-SkipTeams`
- `-DryRun`

## What it does

1. **Entra app** — creates `<BrandName>-Agent` registration with SPA + Web redirects, Graph + ARM scopes, admin consent
2. **Azure infra** — invokes the existing `Infra-Foundary-New/deploy.ps1` (read-only) to provision Foundry + ACR + Container App + Storage as `<BrandName>-RG`
3. **Stage + inject** — copies `webapp/` + `teams/appPackage/` into `auto-deploy/staged/` and replaces the hardcoded clientId + token placeholders. **Source files are NEVER modified.**
4. **Build + deploy** — temp-context ACR build using `AIAgent/Dockerfile` and the staged webapp, deploys to Container App
5. **Teams package** — zips `manifest.json` + icons into `auto-deploy/.generated/teams/<BrandName>-teams-app.zip`

State is stored in `auto-deploy/.generated/runtime.json` so re-runs are idempotent.

## Layout

```
auto-deploy/
├── setup.ps1                       ← entrypoint
├── README.md                       ← this file
├── scripts/
│   ├── helpers.psm1
│   ├── 01_provision_entra.ps1
│   ├── 02_provision_infra.ps1
│   ├── 03_inject_config.ps1
│   ├── 04_build_and_deploy.ps1
│   ├── 05_publish_teams_app.ps1
│   └── 99_teardown.ps1
├── .generated/                     ← runtime state + Teams zip (created at first run)
│   ├── runtime.json
│   └── teams/<Brand>-teams-app.zip
└── staged/                         ← temp build copy of webapp/ + teams/ (created at first run)
```

## Teardown

```powershell
.\auto-deploy\scripts\99_teardown.ps1
```

Deletes the resource group + Entra app. Local files in `auto-deploy/` remain.

## Existing deployment still works

This folder is purely additive. The existing flow (`Infra-Foundary-New/deploy.ps1` + manual `az acr build`) for the `esiqnew-agent` / `ESIQNew-RG` deployment continues to work unchanged.
