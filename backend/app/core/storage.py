"""
NETRA — MinIO (S3-compatible) storage helpers.

Handles uploading raw event payloads and downloading them
for the extraction pipeline and the UI snapshot viewer.
"""

from __future__ import annotations

import io
import logging
from typing import Any

from minio import Minio

from backend.app.config import get_settings

logger = logging.getLogger(__name__)

_client: Minio | None = None


def get_minio_client() -> Minio:
    """Get or create the MinIO client singleton."""
    global _client
    if _client is None:
        settings = get_settings()
        _client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key.get_secret_value(),
            secure=settings.minio_secure,
        )
        # Ensure bucket exists
        if not _client.bucket_exists(settings.minio_bucket):
            _client.make_bucket(settings.minio_bucket)
            logger.info("Created MinIO bucket: %s", settings.minio_bucket)
    return _client


def upload_payload(
    content: bytes,
    object_key: str,
    content_type: str = "text/plain",
    metadata: dict[str, str] | None = None,
) -> str:
    """
    Upload raw event payload to MinIO.

    Returns the s3:// reference URI.
    """
    settings = get_settings()
    client = get_minio_client()

    client.put_object(
        settings.minio_bucket,
        object_key,
        io.BytesIO(content),
        length=len(content),
        content_type=content_type,
        metadata=metadata or {},
    )

    ref = f"s3://{settings.minio_bucket}/{object_key}"
    logger.debug("Uploaded %d bytes to %s", len(content), ref)
    return ref


def download_payload(object_key: str) -> bytes:
    """Download a payload from MinIO by its object key."""
    settings = get_settings()
    client = get_minio_client()

    response = client.get_object(settings.minio_bucket, object_key)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def generate_object_key(event_id: str, suffix: str = "txt") -> str:
    """Generate a deterministic object key for an event payload."""
    # Group by first 2 chars of event_id for bucket partitioning
    prefix = event_id[:2]
    return f"events/{prefix}/{event_id}.{suffix}"
