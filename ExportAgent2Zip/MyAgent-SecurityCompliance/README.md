# MyAgent-SecurityCompliance — Tool Isolation Packager

Manifest-driven packager that produces standalone, deployable zips of any
agent/tool subset from the EnterpriseSecurityIQ source repo.

**The packager NEVER modifies anything in the source repo.** All staged copies
and zips are written under this folder.

## Usage

```powershell
# Default: package SecurityComplianceAssessment using the bundled manifest
python MyAgent-SecurityCompliance/package_agent.py `
  --manifest MyAgent-SecurityCompliance/manifests/securitycompliance.json

# Preview without writing
python MyAgent-SecurityCompliance/package_agent.py `
  --manifest MyAgent-SecurityCompliance/manifests/securitycompliance.json --dry-run
```

Output:
- Staged folder: `MyAgent-SecurityCompliance/<name>/`
- Zip:           `MyAgent-SecurityCompliance/<name>.zip` (auto-incremented to `01_<name>.zip`, `02_…` if exists)

## Adding a new tool

1. Add an entry to [`dependency_map.py`](./dependency_map.py) under `TOOL_MODULES`:
   ```python
   "run_my_new_tool": [
       "AIAgent/app/my_engine.py",
       "AIAgent/app/my_evaluators/",
   ],
   ```
2. Create a manifest in `manifests/` (copy `_template.json`) listing the tools and pages.
3. Run the packager.

## Manifest schema

```json
{
  "name": "OutputZipBasename",
  "brand_name": "DisplayBrand",
  "tools": ["tool_function_name_1", ...],
  "pages": ["Page1.html", "Teams-Page1.html"],
  "include_teams_package": true,
  "include_infra": true,
  "include_automation": true
}
```

## What the generated zip contains

- `AIAgent/` — full Python backend (byte-identical copy of source)
- `webapp/` — only the pages listed in the manifest + shared assets
- `Infra-Foundary-New/` — Bicep + deploy.ps1 (if `include_infra`)
- `teams/appPackage/` — Teams manifest + icons (if `include_teams_package`)
- `setup.ps1` — one-command end-to-end provisioner
- `automation/` — orchestrated PowerShell scripts (Entra, infra, inject, build, deploy, teams, teardown)
- `README.md`, `SETUP.md` — quick-start docs

## What the new repo owner does after unzipping

```powershell
Expand-Archive SecurityComplianceAssessment.zip -DestinationPath C:\Repos\MyBrand
cd C:\Repos\MyBrand
.\setup.ps1 -BrandName "MyBrand" -SubscriptionId "<sub-id>"
```

Setup automatically registers the Entra app, provisions infra, injects all
config tokens, builds the image, deploys the Container App, and packages the
Teams app zip.
