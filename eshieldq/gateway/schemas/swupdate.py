#!/usr/bin/python3

"""SWUpdate delivery metadata.

`metadata.json` is the small manifest the device fetches (before the large
`image.bin`) to decide whether and how to update. It supersedes the older bare
`version.json`. It is forward-compatible: unknown fields are ignored so a newer
publisher can add fields without breaking an older device.

Note: `sha256` is only an early-corruption hint -- update integrity is enforced
independently by the CMS signature + AES encryption on the `.swu` itself.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

SWUPDATE_METADATA_FILE = "metadata.json"
SWUPDATE_IMAGE_FILE = "image.bin"


class SwUpdateMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")  # forward-compatible

    version: str = Field(description="Image version, e.g. 3.1.1782515705")
    channel: str | None = Field(default=None, description="debug | release | prod")
    description: str | None = Field(default=None, description="Human-readable summary of changes")
    security_critical: bool = Field(
        default=False, description="True if this update addresses an urgent security issue"
    )
    released_at: datetime | None = Field(default=None, description="Release timestamp (UTC)")
    min_version: str | None = Field(
        default=None, description="Minimum currently-installed version required to apply this update"
    )
    size_bytes: int | None = Field(default=None, description="Size of image.bin in bytes")
    sha256: str | None = Field(
        default=None, description="Hex SHA-256 of image.bin (early-corruption hint only)"
    )
