#!/usr/bin/env python3
"""IQForge — Scaffold a complete IQ-platform repo from a domain definition YAML.

Usage:
    python iqforge.py create   --config <yaml> --output <dir>
    python iqforge.py validate --config <yaml>

Patterns are extracted from EnterpriseSecurityIQ and templatised so any
domain (FinOps, DevSecOps, Supply-Chain, …) gets the identical architecture,
UX, infra, and operational model.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the package is importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from iqforge.generator import generate_project
from iqforge.validators import load_and_validate


def cmd_create(args: argparse.Namespace) -> int:
    cfg = load_and_validate(Path(args.config))
    if cfg is None:
        return 1
    out = Path(args.output)
    if out.exists() and any(out.iterdir()) and not args.force:
        print(f"ERROR: Output directory {out} is not empty. Use --force to overwrite.")
        return 1
    generate_project(cfg, out)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = load_and_validate(Path(args.config))
    if cfg is None:
        return 1
    print(f"  Valid domain definition: {cfg['project_name']}")
    print(f"  Data sources : {sum(len(v) for v in cfg.get('data_sources', {}).values())}")
    print(f"  Frameworks   : {len(cfg.get('frameworks', []))}")
    print(f"  Domains      : {sorted({d for fw in cfg.get('frameworks', []) for d in fw.get('domains', [])})}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="iqforge", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command")

    p_create = sub.add_parser("create", help="Generate a complete IQ-platform repo")
    p_create.add_argument("--config", "-c", required=True, help="Path to domain-definition YAML")
    p_create.add_argument("--output", "-o", required=True, help="Output directory for the new repo")
    p_create.add_argument("--force", "-f", action="store_true", help="Overwrite existing output dir")

    p_validate = sub.add_parser("validate", help="Validate a domain-definition YAML")
    p_validate.add_argument("--config", "-c", required=True, help="Path to domain-definition YAML")

    args = ap.parse_args()
    if args.command == "create":
        return cmd_create(args)
    elif args.command == "validate":
        return cmd_validate(args)
    else:
        ap.print_help()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
