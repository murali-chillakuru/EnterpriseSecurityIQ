"""Collector auto-discovery registry.

Discovers all collector modules under the collectors/ package tree
using pkgutil.iter_modules. Each module must register itself via
the @register_collector decorator.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Any, Callable, Coroutine

log = logging.getLogger(__name__)

# Global registry: name → collector coroutine
_COLLECTORS: dict[str, dict[str, Any]] = {}


def register_collector(
    name: str,
    plane: str = "data",
    source: str = "azure",
    priority: int = 100,
):
    """Decorator to register a collector function.

    Usage:
        @register_collector("network_security_groups", plane="data", source="azure")
        async def collect_nsgs(creds, subscriptions):
            ...
    """
    def decorator(fn: Callable[..., Coroutine]):
        _COLLECTORS[name] = {
            "fn": fn,
            "plane": plane,
            "source": source,
            "priority": priority,
            "name": name,
        }
        return fn
    return decorator


def get_collectors(source: str | None = None) -> list[dict[str, Any]]:
    """Return registered collectors, optionally filtered by source."""
    items = list(_COLLECTORS.values())
    if source:
        items = [c for c in items if c["source"] == source]
    return sorted(items, key=lambda c: c["priority"])


def discover_collectors() -> None:
    """Auto-discover collector modules by walking the package tree."""
    pkg_dir = Path(__file__).parent
    for finder, module_name, is_pkg in pkgutil.walk_packages(
        [str(pkg_dir)], prefix=f"{__name__}."
    ):
        try:
            importlib.import_module(module_name)
        except Exception:
            log.warning("Failed to import collector: %s", module_name, exc_info=True)

    log.info("Discovered %d collectors", len(_COLLECTORS))
