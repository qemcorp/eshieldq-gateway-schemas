#!/usr/bin/python3

"""SWUpdate delivery metadata.

`metadata.json` is the small manifest the device fetches (before the large
`image.bin`) to decide whether and how to update. It supersedes the older bare
`version.json`. It is forward-compatible: unknown fields are ignored so a newer
publisher can add fields without breaking an older device.

`sha256` is NOT merely an early-corruption hint, whatever this docstring said
before. metadata.json decides whether an update exists, whether it is
security-critical, whether `min_version` blocks it, and how many bytes the device
will accept -- and every one of those decisions is made BEFORE the CMS signature
is ever evaluated. CMS protects installation; it cannot protect against
SUPPRESSION, because nothing is installed. So the blob is untrusted input, the
fields are validated here rather than by whoever consumes them, and the digest is
checked against the Broker's authenticated artifact claims
(`SwUpdateArtifactClaims`) before the image is handed to the installer.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

SWUPDATE_METADATA_FILE = "metadata.json"
SWUPDATE_IMAGE_FILE = "image.bin"

# The channel + version contract, canonical HERE because it is part of the on-the-wire
# manifest rather than of credential minting. Re-exported where it is also needed, so
# there is one definition: keeping two copies is how the device and the update service
# came to disagree about what a version is.
CHANNELS = ("debug", "release", "prod")
# Dotted-numeric, 1-4 segments, each 1-10 digits. Tightened from v1's [0-9A-Za-z.-]:
# letters/dashes made the KV bundle-key suffix (dot->dash) non-injective and made
# version comparison ill-defined.
VERSION_RE = re.compile(r"^\d{1,10}(\.\d{1,10}){0,3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# The device's own hard cap is 512 MiB; a manifest claiming more than that describes an
# artifact no device would ever accept, so the bound belongs on the field rather than
# only in the client that reads it.
MAX_IMAGE_BYTES = 512 * 1024 * 1024

# Module-level so both models below share ONE definition of each rule. The manifest and
# the Broker's claims are cross-checked field by field, so a rule that held on only one
# side would make a disagreement the device is meant to refuse look like a bad blob.
def _check_dotted_numeric(value: str | None) -> str | None:
    """`version` / `min_version` are compared numerically by the device and by the
    Broker's version floor, so a non-dotted-numeric value is not cosmetic: it makes both
    comparisons raise, and both sides then fail closed on a manifest that could have been
    rejected at the edge."""
    if value is not None and not VERSION_RE.fullmatch(value):
        raise ValueError(f"not a dotted-numeric version: {value!r}")
    return value


def _check_known_channel(value: str | None) -> str | None:
    """Optional but never arbitrary. None is "this manifest does not say"; a WRONG channel
    would otherwise pass through to a caller comparing it against its own."""
    if value is not None and value not in CHANNELS:
        raise ValueError(f"unknown channel {value!r} (expected one of {CHANNELS})")
    return value


def _check_bounded_size(value: int | None) -> int | None:
    if value is not None and not 0 < value <= MAX_IMAGE_BYTES:
        raise ValueError(f"size_bytes {value} outside 1..{MAX_IMAGE_BYTES}")
    return value


def _check_hex_digest(value: str | None) -> str | None:
    """Lower-case hex only, and exactly 64 of it. An upper-case or truncated digest
    compares unequal to a correctly computed one, turning a publisher's formatting slip
    into "the image is corrupt" on every device in the fleet."""
    if value is not None and not SHA256_RE.fullmatch(value):
        raise ValueError("sha256 must be 64 lower-case hex characters")
    return value


class SwUpdateMetadata(BaseModel):
    """The published `metadata.json`. Untrusted input: every field is validated."""

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
    sha256: str | None = Field(default=None, description="Hex SHA-256 of image.bin")

    _v_version = field_validator("version", "min_version")(_check_dotted_numeric)
    _v_channel = field_validator("channel")(_check_known_channel)
    _v_size = field_validator("size_bytes")(_check_bounded_size)
    _v_sha256 = field_validator("sha256")(_check_hex_digest)


class SwUpdateArtifactClaims(BaseModel):
    """The Broker's AUTHENTICATED statement about the artifact it just granted.

    Returned inside the token response, which the device obtains only after a
    proof-of-possession exchange over TLS -- so unlike `metadata.json`, which is fetched
    from blob storage with a read SAS and signed by nothing, these claims cannot be
    substituted, staled or stripped by anyone who cannot also break the Broker exchange.

    The Broker reads `metadata.json` itself, over its own authenticated storage identity,
    and echoes it here. The device cross-checks the blob it fetched against these claims
    and refuses on any disagreement, then verifies the downloaded bytes against
    `sha256`/`size_bytes` from HERE -- never from the blob.

    Every field is REQUIRED, unlike the manifest's: the Broker either read a usable
    manifest or it did not, and a claims object with holes in it is the unauthenticated
    case wearing an authenticated label.
    """

    model_config = ConfigDict(extra="ignore")

    version: str
    channel: str
    size_bytes: int
    sha256: str
    security_critical: bool = False
    min_version: str | None = None
    # Optional because a manifest may legitimately omit them -- but they ARE echoed and
    # cross-checked, because the device writes the parsed manifest to
    # /run/sk/swupdate-metadata.json and the REST API/UI reads it from there. A field
    # that reaches an operator's screen without being authenticated is one a substituted
    # manifest can rewrite while passing every other check.
    description: str | None = None
    released_at: datetime | None = None

    _v_version = field_validator("version", "min_version")(_check_dotted_numeric)
    _v_channel = field_validator("channel")(_check_known_channel)
    _v_size = field_validator("size_bytes")(_check_bounded_size)
    _v_sha256 = field_validator("sha256")(_check_hex_digest)
