#!/usr/bin/python3


from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

API_EAAS = "/eaas"
API_EAAS_V1 = API_EAAS + "/v1"


class EaaSAction(Enum):
    EAAS_ACTION_RESTART = 1
    EAAS_ACTION_STOP = 2
    EAAS_ACTION_START = 3


class EaasServiceControlModel(BaseModel):
    action: EaaSAction = Field(description="Action for Entropy Service Control")


class EaasHealthState(str, Enum):
    """Public QEaaS state; healthy requires recent entropy delivery."""

    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"
    STOPPED = "stopped"
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class EaasErrorCode(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    TLS = "tls"
    SERVER = "server"
    INVALID_RESPONSE = "invalid_response"
    INTERNAL = "internal"


class EaasStatusModel(BaseModel):
    # Retained only for wire compatibility. Raw systemctl output is not an API
    # contract and may expose implementation detail, so this is always empty.
    status: str = Field(default="", description="Deprecated; always empty")
    state: EaasHealthState = Field(
        default=EaasHealthState.UNKNOWN,
        description="QEaaS configuration, service, and functional health state",
    )
    healthy: bool = Field(
        default=False,
        description="True only when rngd recently delivered QEaaS entropy",
    )
    credential_configured: bool = Field(
        default=False,
        description="Whether a QEaaS credential exists; its value is never returned",
    )
    service_active_state: str | None = Field(
        default=None, description="systemd ActiveState for rngd.service"
    )
    service_sub_state: str | None = Field(
        default=None, description="systemd SubState for rngd.service"
    )
    unit_enabled: bool | None = Field(
        default=None, description="Whether systemd reports the service unit enabled"
    )
    active_since: datetime | None = Field(
        default=None, description="When the current rngd service instance became active"
    )
    last_entropy_at: datetime | None = Field(
        default=None, description="Most recent successful QEaaS delivery"
    )
    last_entropy_bytes: int | None = Field(
        default=None, description="Bytes delivered by the most recent successful request"
    )
    consecutive_failures: int = Field(
        default=0, description="Observed QEaaS failures after the most recent success"
    )
    last_error_code: EaasErrorCode | None = Field(
        default=None, description="Sanitized QEaaS source failure category"
    )
    observed_at: datetime | None = Field(
        default=None, description="When the status was evaluated"
    )


class EaasBaseModel(BaseModel):
    id: str | None = Field(
        description="Identifier for the Entropy Service Secrets",
        examples=["qem_eaas_secret"],
        default=None,
    )
    type: str | None = Field(
        description="Type of Entropy Service Secret", examples=["QEM"], default="QEM"
    )


class EaasSecretDataModel(EaasBaseModel):
    secret: str = Field(
        description="Data String for Entropy Service Secret",
    )
