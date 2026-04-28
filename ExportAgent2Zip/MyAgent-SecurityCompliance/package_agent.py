"""
package_agent.py — Tool-isolation packager for EnterpriseSecurityIQ.

Reads a manifest JSON, copies only the required modules + pages from the source
repo into a staged folder under MyAgent-SecurityCompliance/<name>/, injects
auto-deploy automation, and produces a zip.

USAGE:
  python MyAgent-SecurityCompliance/package_agent.py --manifest MyAgent-SecurityCompliance/manifests/securitycompliance.json
  python MyAgent-SecurityCompliance/package_agent.py --manifest manifests/myothertool.json --dry-run

DESIGN:
  - NEVER modifies anything in the source repo (read-only).
  - All transformations (placeholder injection, brand replace) happen on copies
    inside MyAgent-SecurityCompliance/<name>/.
  - Auto-increments zip filename: name.zip -> 01_name.zip -> 02_name.zip.
  - Re-runnable: removes prior staged folder for the same name before re-staging.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

# Resolve paths relative to this script.
# Layout: <REPO_ROOT>/ExportAgent2Zip/MyAgent-SecurityCompliance/package_agent.py
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent

sys.path.insert(0, str(SCRIPT_DIR))
from dependency_map import (  # noqa: E402
    ALWAYS_ON_BACKEND,
    ALWAYS_ON_ROOT,
    ALWAYS_ON_WEBAPP,
    EXCLUDE_PATTERNS,
    TOOL_MODULES,
)
from automation_templates import AUTOMATION_FILES  # noqa: E402


# ─────────────────────────────────────────────────────────────────
# File copy helpers
# ─────────────────────────────────────────────────────────────────
def _excluded(path: Path) -> bool:
    name = path.name
    parts = path.parts
    for pat in EXCLUDE_PATTERNS:
        if pat.startswith("*"):
            if fnmatch.fnmatch(name, pat):
                return True
        elif pat in parts or name == pat:
            return True
    return False


def copy_path(src: Path, dst: Path, stats: dict) -> None:
    """Copy a file or directory from src to dst, applying exclusions."""
    if not src.exists():
        print(f"  ! missing: {src.relative_to(REPO_ROOT)}")
        stats["missing"].append(str(src.relative_to(REPO_ROOT)))
        return
    if src.is_file():
        if _excluded(src):
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        stats["files"] += 1
        stats["bytes"] += src.stat().st_size
        return
    # directory: walk and copy
    for sp in src.rglob("*"):
        if _excluded(sp):
            continue
        if sp.is_file():
            rel = sp.relative_to(src)
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sp, target)
            stats["files"] += 1
            stats["bytes"] += sp.stat().st_size


# ─────────────────────────────────────────────────────────────────
# Token injection (replaces hardcoded values with deploy-time placeholders
# in STAGED COPIES ONLY — the source repo is never touched).
# ─────────────────────────────────────────────────────────────────
# Tokens used by automation/03_inject_config.ps1 to substitute generated values
TOKEN_REPLACEMENTS = [
    # MSAL clientId in HTML files (preserves the YOUR-CLIENT-ID-HERE demo-mode check)
    (re.compile(r'clientId:\s*"ffb6f10d-6991-430e-b3d6-23a0101a92b1"'),
     'clientId: "{{ENTRA_CLIENT_ID}}"'),
]


def inject_placeholders(staged_root: Path, brand: str) -> int:
    """Walk staged copy and inject deploy-time placeholders. Returns file count modified."""
    count = 0
    for path in staged_root.rglob("*.html"):
        if _excluded(path):
            continue
        text = path.read_text(encoding="utf-8")
        original = text
        for pattern, replacement in TOKEN_REPLACEMENTS:
            text = pattern.sub(replacement, text)
        if text != original:
            path.write_text(text, encoding="utf-8")
            count += 1
    return count


# ─────────────────────────────────────────────────────────────────
# Manifest resolution
# ─────────────────────────────────────────────────────────────────
def resolve_files(manifest: dict) -> tuple[list[str], list[str]]:
    """Return (paths_to_copy_from_repo, webapp_pages_to_include)."""
    paths: set[str] = set(ALWAYS_ON_BACKEND)
    paths.update(ALWAYS_ON_WEBAPP)

    # Add tool-specific modules
    for tool in manifest.get("tools", []):
        if tool not in TOOL_MODULES:
            print(f"  ! unknown tool '{tool}' in manifest — skipped (add to dependency_map.py)")
            continue
        paths.update(TOOL_MODULES[tool])

    # Add manifest-flagged root scaffolding
    if manifest.get("include_infra", True):
        paths.update(ALWAYS_ON_ROOT)

    pages = manifest.get("pages", [])
    return sorted(paths), pages


# ─────────────────────────────────────────────────────────────────
# Zip creation with auto-increment
# ─────────────────────────────────────────────────────────────────
def find_unique_zip_path(out_dir: Path, base: str) -> Path:
    candidate = out_dir / f"{base}.zip"
    if not candidate.exists():
        return candidate
    for i in range(1, 100):
        candidate = out_dir / f"{i:02d}_{base}.zip"
        if not candidate.exists():
            return candidate
    raise RuntimeError("Too many existing zips — clean up MyAgent-SecurityCompliance/ first")


def create_zip(staged_root: Path, zip_path: Path) -> int:
    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in staged_root.rglob("*"):
            if path.is_file():
                arcname = path.relative_to(staged_root.parent)
                zf.write(path, arcname)
                count += 1
    return count


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description="Package an isolated agent zip")
    ap.add_argument("--manifest", required=True, help="Path to manifest JSON")
    ap.add_argument("--name", help="Output basename (overrides manifest 'name')")
    ap.add_argument("--output-dir", help="Directory for staged folder + zip (default: packager folder)")
    ap.add_argument("--dry-run", action="store_true", help="Preview only, no files written")
    ap.add_argument("--keep-staged", action="store_true", default=True,
                    help="Keep staged folder after zipping (default true)")
    args = ap.parse_args()

    output_dir = Path(args.output_dir).resolve() if args.output_dir else SCRIPT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = (Path.cwd() / manifest_path).resolve()
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    name = args.name or manifest.get("name", "Agent")
    brand = manifest.get("brand_name", "PostureIQ")
    pages = manifest.get("pages", [])

    print("═" * 64)
    print(f"  Packager — {name}")
    print(f"  Brand:    {brand}")
    print(f"  Tools:    {', '.join(manifest.get('tools', []))}")
    print(f"  Pages:    {', '.join(pages)}")
    print("═" * 64)

    paths_to_copy, _ = resolve_files(manifest)

    if args.dry_run:
        print("\n[DRY RUN] Files/dirs that would be copied:")
        for p in paths_to_copy:
            print(f"  - {p}")
        print(f"\n[DRY RUN] Webapp pages: {pages}")
        return 0

    # Stage folder
    staged_root = output_dir / name
    if staged_root.exists():
        print(f"\n[clean] Removing existing staged folder: {staged_root}")
        shutil.rmtree(staged_root)
    staged_root.mkdir(parents=True)

    stats = {"files": 0, "bytes": 0, "missing": []}

    print(f"\n[copy] Source = {REPO_ROOT}")
    print(f"[copy] Target = {staged_root}\n")

    # Copy generic paths
    for rel in paths_to_copy:
        src = REPO_ROOT / rel.rstrip("/")
        dst = staged_root / rel.rstrip("/")
        copy_path(src, dst, stats)

    # Copy selected webapp pages
    for page in pages:
        src = REPO_ROOT / "webapp" / page
        dst = staged_root / "webapp" / page
        copy_path(src, dst, stats)

    # Copy teams package if requested
    if manifest.get("include_teams_package", False):
        copy_path(REPO_ROOT / "teams" / "appPackage", staged_root / "teams" / "appPackage", stats)

    # Copy a minimal index.html (regenerated to link only included pages)
    write_minimal_index(staged_root / "webapp" / "index.html", pages, brand)

    # Inject deploy-time placeholders into staged copies
    if manifest.get("include_automation", True):
        modified = inject_placeholders(staged_root, brand)
        print(f"[inject] {modified} HTML file(s) updated with placeholders")

        # Write automation scripts
        write_automation(staged_root, brand, name, manifest)

    # Top-level README + SETUP guide for the staged copy
    write_top_level_readme(staged_root, brand, name, manifest)

    # Zip
    out_dir = output_dir
    zip_path = find_unique_zip_path(out_dir, name)
    file_count = create_zip(staged_root, zip_path)

    # Summary
    print("\n" + "═" * 64)
    print(f"  Files copied:  {stats['files']:,}")
    print(f"  Total size:    {stats['bytes'] / (1024*1024):.2f} MB")
    print(f"  Staged folder: {staged_root}")
    print(f"  Zip file:      {zip_path}")
    print(f"  Zip entries:   {file_count:,}")
    if stats["missing"]:
        print(f"  ! missing:     {len(stats['missing'])} (see warnings above)")
    print("═" * 64)
    return 0


# ─────────────────────────────────────────────────────────────────
# Auxiliary writers
# ─────────────────────────────────────────────────────────────────
def write_minimal_index(target: Path, pages: list[str], brand: str) -> None:
    cards = ""
    for p in pages:
        if p.startswith("Teams"):
            continue  # Teams pages aren't entry points for the web SPA
        title = p.replace(".html", "").replace("-", " ")
        cards += f'    <a class="card" href="/{p}"><h3>{title}</h3></a>\n'
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{brand} - Portal</title>
<style>body{{font-family:Segoe UI,sans-serif;max-width:800px;margin:3rem auto;padding:0 1rem}}
.card{{display:block;padding:1.2rem;margin:.5rem 0;border:1px solid #ddd;border-radius:8px;text-decoration:none;color:#0078d4}}
.card:hover{{background:#f5f5f5}}</style></head>
<body>
  <h1 style="color:#0078d4">{brand}</h1>
  <p>Select an assessment:</p>
{cards}</body></html>
"""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")


def write_top_level_readme(staged_root: Path, brand: str, name: str, manifest: dict) -> None:
    readme = f"""# {brand} — {name}

Isolated, deployable copy of the **{name}** agent generated from the
EnterpriseSecurityIQ source repository.

## One-command setup

Prerequisites:
- PowerShell 7+
- Azure CLI logged in (`az login`)
- Subscription Contributor + Entra **Application Administrator** (or Owner)
- Python 3.12+ (only for local backend testing)

```powershell
.\\setup.ps1 -BrandName "{brand}" -Location "northeurope" -SubscriptionId "<your-sub-id>"
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

{chr(10).join(f'- `{t}`' for t in manifest.get('tools', []))}

## Pages included

{chr(10).join(f'- `{p}`' for p in manifest.get('pages', []))}

## Manual customization (optional)

Edit `automation/.config.json` after `setup.ps1` runs to change names/regions
before re-running individual scripts under `automation/`.

## Teardown

```powershell
.\\automation\\99_teardown.ps1
```

Deletes the resource group created by setup.
"""
    (staged_root / "README.md").write_text(readme, encoding="utf-8")
    (staged_root / "SETUP.md").write_text(readme, encoding="utf-8")


def write_automation(staged_root: Path, brand: str, name: str, manifest: dict) -> None:
    """Write all PowerShell automation scripts into the staged copy."""
    auto_dir = staged_root / "automation"
    auto_dir.mkdir(parents=True, exist_ok=True)

    for fname, content in AUTOMATION_FILES.items():
        # Substitute brand/name into the templates
        text = content.replace("{{DEFAULT_BRAND}}", brand).replace("{{AGENT_NAME}}", name)
        target = staged_root / fname if fname == "setup.ps1" else auto_dir / fname
        target.write_text(text, encoding="utf-8")
        print(f"[automation] wrote {target.relative_to(staged_root)}")


if __name__ == "__main__":
    sys.exit(main())
