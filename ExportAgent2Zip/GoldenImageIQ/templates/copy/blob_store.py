"""Blob Storage helper — upload / download / list files.

Uses DefaultAzureCredential for managed-identity auth.
Falls back to local file system when AZURE_STORAGE_ACCOUNT is not set.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import BinaryIO

log = logging.getLogger(__name__)

_container_client = None


def _get_container():
    """Lazy-init blob container client (cached)."""
    global _container_client
    if _container_client is not None:
        return _container_client

    account = os.getenv("AZURE_STORAGE_ACCOUNT")
    container = os.getenv("AZURE_STORAGE_CONTAINER", "reports")
    if not account:
        log.warning("AZURE_STORAGE_ACCOUNT not set — blob ops will be local-only")
        return None

    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import ContainerClient

    url = f"https://{account}.blob.core.windows.net/{container}"
    _container_client = ContainerClient.from_container_url(url, credential=DefaultAzureCredential())
    return _container_client


def upload_file(local_path: str | Path, blob_name: str) -> str | None:
    """Upload a single file. Returns blob URL or None."""
    client = _get_container()
    if client is None:
        return None
    try:
        with open(local_path, "rb") as f:
            client.upload_blob(name=blob_name, data=f, overwrite=True)
        return f"{client.url}/{blob_name}"
    except Exception:
        log.exception("Blob upload failed: %s", blob_name)
        return None


def upload_directory(local_dir: str | Path, prefix: str = "") -> list[str]:
    """Upload all files in a directory. Returns list of blob URLs."""
    results = []
    base = Path(local_dir)
    for f in sorted(base.rglob("*")):
        if f.is_file():
            blob_name = f"{prefix}/{f.relative_to(base)}" if prefix else str(f.relative_to(base))
            blob_name = blob_name.replace("\\", "/")
            url = upload_file(f, blob_name)
            if url:
                results.append(url)
    return results


def download_file(blob_name: str, local_path: str | Path) -> bool:
    """Download a blob to a local file."""
    client = _get_container()
    if client is None:
        return False
    try:
        blob = client.get_blob_client(blob_name)
        p = Path(local_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            stream = blob.download_blob()
            stream.readinto(f)
        return True
    except Exception:
        log.exception("Blob download failed: %s", blob_name)
        return False


def list_blobs(prefix: str = "") -> list[str]:
    """List blob names under a prefix."""
    client = _get_container()
    if client is None:
        return []
    return [b.name for b in client.list_blobs(name_starts_with=prefix or None)]
