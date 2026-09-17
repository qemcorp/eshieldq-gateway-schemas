#!/usr/bin/python3


from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import List, Union

from pydantic import BaseModel, Field

# from pydantic.networks import IPv4Address
from eshieldq.gateway.schemas.intf import HostnameModel
from eshieldq.gateway.schemas.stats import StatusModel
from eshieldq.gateway.schemas.swupdate import SwUpdateMetadata

API_SYS = "/sys"
API_SYS_V1 = API_SYS + "/v1"


class VarIntegrityModel(BaseModel):
    """/var (LUKS) mount + device-identity self-report. Device identity lives on
    /var, so var_mounted=False with a non-'healthy' last_heal_result means the
    volume could not be unlocked -- a storage fault, not an enrollment fault.
    Read-only, no key material."""

    var_mounted: bool = Field(description="Is the /var LUKS volume currently mounted")
    identity_present: bool = Field(
        description="birth_cert.pem AND license.jwt both present under /var/sk/device_id"
    )
    last_heal_result: Union[str, None] = Field(
        default=None,
        description="Last SK_VAR_HEAL verdict from the var-recover log (healthy/drift_healed/nv_absent/reenroll_failed/no_tpm)",
    )
    last_heal_pcr7: Union[str, None] = Field(
        default=None, description="PCR-7 value recorded with the last heal verdict"
    )


# Reported so that "the audit log is quiet" and "the audit log is not being
# written" are distinguishable to a caller, which they are not from the log
# contents alone. The REST app only reads this state; it never changes it.
class AuditLoggingEnum(str, Enum):
    """Whether the audit trail is recording. Anything other than `active` means audit
    records are being lost; `suspended_space` clears itself once log space is
    reclaimed, `suspended_error` and `not_running` need an operator."""

    ACTIVE = "active"
    # crossed admin_space_left / disk_full: recoverable, and sk_log_reaper.sh
    # resumes it once /var/log is back inside its budget
    SUSPENDED_SPACE = "suspended_space"
    # disk_error_action: a write/IO fault. No amount of free space repairs it and
    # the reaper deliberately will not resume it (it would re-suspend on the next
    # write) -- this one needs attention.
    SUSPENDED_ERROR = "suspended_error"
    # the unit is not active: no trail at all, and no unit failure to notice it by
    # if it was stopped rather than crashed
    NOT_RUNNING = "not_running"
    # auditd is up but configured not to write logs (write_logs = no)
    DISABLED = "disabled"
    # no current dump to read (off-target, auditd has never dumped, or the dump was
    # being rewritten). Deliberately not "active": a state we cannot prove must not
    # read as a healthy audit trail.
    UNKNOWN = "unknown"


class SystemHealth(BaseModel):
    """Boot/runtime health the management UI surfaces. Distinct from the
    per-component liveness in GET /sys/v1/status: this also captures systemd-level
    boot integrity (a *skipped* unit from an ordering cycle, or a *failed* unit)
    that the component list cannot express."""

    healthy: bool = Field(
        description="Overall: booted cleanly (no ordering cycles, no failed units, settled) and all key services up"
    )
    system_running: str = Field(
        description="systemctl is-system-running state (running/degraded/starting/...)"
    )
    failed_units: List[str] = Field(
        default_factory=list, description="systemd units currently in the failed state"
    )
    ordering_cycles: bool = Field(
        default=False,
        description="True if systemd detected a unit ordering cycle at boot (causes units to be silently skipped)",
    )
    services: List[StatusModel] = Field(
        default_factory=list,
        description="Per-component liveness rollup (same data as GET /sys/v1/status)",
    )
    var_integrity: Union[VarIntegrityModel, None] = Field(
        default=None,
        description="/var LUKS mount + device-identity self-report; None when unavailable",
    )
    audit_logging: AuditLoggingEnum = Field(
        default=AuditLoggingEnum.UNKNOWN,
        description=(
            "Whether the audit trail is recording. Read this field rather than "
            "inferring from log timestamps, and read it in addition to `healthy` "
            "rather than instead of it -- the two report different things."
        ),
    )


class SwupdateStatusEnum(str, Enum):
    IDLE = "IDLE"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED_SERVER_CHECK = "FAILED_SERVER"
    FAILED_DOWNLOAD = "FAILED_DOWNLOAD"
    FAILED_INSTALL = "FAILED_INSTALL"
    # The bundle was refused at signature verification, before SWUpdate hands
    # anything to a handler -- so no bank was written and the appliance stays
    # configurable. Distinct from FAILED_INSTALL, which may have written one
    # and is therefore frozen until a reboot (staged_update_guard).
    FAILED_VERIFY = "FAILED_VERIFY"
    DOWNLOADING = "IMAGE_DOWNLOADING"
    DOWNLOAD_COMPLETE = "IMAGE_DOWNLOAD_COMPLETE"
    INSTALLING = "INSTALLING"
    SUCCESS_NO_UPDATE_AVAILABLE = "SUCCESS_NO_UPDATE"
    REBOOT_REQUIRED = "REBOOT_REQUIRED"


class JobStatusEnum(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class SwupdateStatus(BaseModel):
    status: SwupdateStatusEnum = Field(description="Software Update Status")
    available: SwUpdateMetadata | None = Field(
        default=None,
        description="Metadata of the latest available update from the last check (if any)",
    )


class SwupdateCheckRequest(BaseModel):
    """Optional version-targeted SWUpdate check. Absent body = today's implicit latest."""

    target_version: str | None = Field(
        default=None,
        description=(
            "Request this specific version instead of implicit latest. "
            "Dotted-numeric only: 1-4 segments, each 1-10 digits (e.g. '3.1.1782515705')"
        ),
    )
    source_url: str | None = Field(
        default=None,
        description="Direct URL to fetch metadata.json/image.bin from instead of a broker-minted SAS",
    )


class SwupdateEndpointsModel(BaseModel):
    """The overlayable SWUpdate/registration endpoints. PUT replaces the persisted
    overlay with exactly the non-null keys given, and may be refused depending on
    how the device was built and licensed.

    Only the endpoint locations are settable. Cryptographic trust anchors are
    fixed at build time and cannot be changed through this API. `authority_ca` is
    the TLS transport CA used when contacting these endpoints; it is not an
    identity or image trust anchor."""

    authority_url: str | None = Field(
        default=None, description="License Authority base URL (enrollment)"
    )
    broker_url: str | None = Field(
        default=None, description="License Broker base URL (licensed SWUpdate)"
    )
    swupdate_channel: str | None = Field(
        default=None, description="SWUpdate channel (debug|release|prod)"
    )
    authority_ca: str | None = Field(
        default=None,
        description="Path to a TLS CA bundle ON /var for a private-TLS backend",
    )


class SwupdateEndpointsStatus(BaseModel):
    """Effective endpoints + whether an overlay is active and honored. Returned by
    GET /sys/v1/swupdate-endpoints."""

    build_type: str = Field(description="Baked build type: debug|release|production")
    overlay_present: bool = Field(
        description="A whitelisted /var endpoint overlay exists on disk"
    )
    overlay_effective: dict[str, str] = Field(
        default_factory=dict,
        description="Overlay keys actually honored, which may be a subset of "
        "those present depending on how the device was built and licensed",
    )
    authority_url: str | None = Field(default=None, description="Effective Authority URL")
    broker_url: str | None = Field(default=None, description="Effective Broker URL")
    swupdate_channel: str | None = Field(default=None, description="Effective channel")
    authority_ca: str | None = Field(default=None, description="Effective TLS CA path")


class JobNumber(BaseModel):
    id: int = Field(
        description=f"Job Number ID - check {API_SYS_V1}/job-status/<id> for status"
    )
    descritpion: str = Field(description="Description of the Job", default="")


class JobStatus(BaseModel):
    status: JobStatusEnum = Field(description="Job Status")


class SyslogConfigModel(BaseModel):
    enable_remote_syslog: bool = Field(
        description="True if remote syslog server is enabled", default=False
    )
    server_address: IPv4Address | None = Field(
        description="Server IP address", default=None
    )
    server_port: int | None = Field(description="Port", ge=0, le=65535, default=514)
    enable_authentication: bool = Field(
        description="True if authentication is enabled", default=False
    )


class DNSServer(BaseModel):
    ip: Union[IPv4Address, IPv6Address] = Field(description="DNS IP address")
    port: int = Field(description="Port", ge=0, le=65535, default=53)
    domain: HostnameModel | None = Field(description="DNS Domains", default=None)


DEFAULT_DNS_SERVERS: List[DNSServer] = [
    DNSServer(ip=IPv4Address("1.1.1.1")),
    DNSServer(ip=IPv4Address("1.0.0.1")),
    DNSServer(ip=IPv4Address("8.8.8.8")),
    DNSServer(ip=IPv4Address("8.8.4.4")),
    DNSServer(ip=IPv6Address("2606:4700:4700::1111")),
    DNSServer(ip=IPv6Address("2606:4700:4700::1001")),
    DNSServer(ip=IPv6Address("2001:4860:4860::8888")),
    DNSServer(ip=IPv6Address("2001:4860:4860::8844")),
]


class DNSConfigModel(BaseModel):

    servers: List[DNSServer] = Field(
        description="DNS IP address", default=DEFAULT_DNS_SERVERS
    )
    # port: int = Field(description="Port", ge=0, le=65535, default=53)
    # domains: List[HostnameModel] = Field(description="DNS Domains", default=None)
    dnssec: bool = Field(description="True if DNSSEC is enabled", default=False)
    fallback_servers: List[DNSServer] = Field(
        description="Fallback DNS IP address - Default to Goole and Cloudflare",
        default=DEFAULT_DNS_SERVERS,
    )
