"""Schemas for the device identity + birth certificate + license status surface
that the management UI renders. Read-only/display-oriented."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

API_IDENTITY = "/identity"
API_IDENTITY_V1 = API_IDENTITY + "/v1"


class TpmDaModel(BaseModel):
    """The TPM's dictionary-attack accounting.

    A non-zero counter is the early warning this appliance never had: the device key
    is unusable once the TPM locks out, and `failedTries` is in NV so no reboot clears
    it. Fields are None when the TPM could not be asked -- reporting an unreadable
    counter as 0 is how a locked-out device would keep looking healthy.
    """

    lockout_counter: int | None = Field(
        default=None, description="failedTries: authorization failures counted so far"
    )
    max_auth_fail: int | None = Field(
        default=None, description="Failures tolerated before the TPM enters lockout"
    )
    lockout_interval: int | None = Field(
        default=None, description="Seconds before the counter decays by one (powered on)"
    )
    in_lockout: bool | None = Field(
        default=None, description="True when the TPM is refusing DA-protected objects"
    )


class DeviceIdentityModel(BaseModel):
    machine_id: str = Field(description="Persistent device ID (/etc/machine-id)")
    instance_id: str | None = Field(default=None, description="Cloud-init instance-id")
    key_backing: str = Field(description="Device key custody: 'tpm', 'software', or 'none'")
    public_key_thumbprint: str | None = Field(
        default=None,
        description=(
            "Thumbprint of the device public key. The birth certificate's while one "
            "exists (the two agree -- see birth_cert_bound_to_present_key); otherwise "
            "the key the device currently holds, as published by the identity service. "
            "An operator reads this to fill in --successor-thumbprint for an "
            "administrative enrollment reset, which is needed exactly when there is no "
            "certificate"
        ),
    )
    enrolled: bool = Field(description="True once a birth certificate is present")
    key_backing_recorded: bool = Field(
        default=False,
        description="True when key_backing comes from the custody record written at key creation rather than being inferred from which key files exist",
    )
    pop_signing_ok: bool | None = Field(
        default=None,
        description="True when the device key just produced a verifiable signature. This is the only field that proves the licensed-update proof-of-possession still works; None when not checked",
    )
    pop_signing_error: str | None = Field(
        default=None, description="Why the proof-of-possession self-test failed, when it did"
    )
    birth_cert_bound_to_present_key: bool | None = Field(
        default=None,
        description="True when the birth certificate is bound to the key the device would actually present. False is the broker's bad_device_cert state: the device looks enrolled and healthy but can never obtain an update",
    )
    key_status_age_seconds: float | None = Field(
        default=None,
        description="Age of the published device-key measurement, or null when none has ever been published. Distinguishes 'the publisher stopped' (a large age) from 'it never ran' (null) -- both report pop_signing_ok as null",
    )
    key_status_current: bool = Field(
        default=False,
        description="True when the published device-key measurement is still within the freshness the publisher claimed for it. False means the reported pop_signing_ok/binding fields are stale or absent, not that the key is bad",
    )
    tpm_da: TpmDaModel | None = Field(
        default=None, description="TPM dictionary-attack counters, when a TPM key is in use"
    )


class BirthCertModel(BaseModel):
    present: bool
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = Field(default_factory=list, description="Subject Alternative Names")
    thumbprint: str | None = None
    valid: bool | None = Field(
        default=None,
        description="True if the device verified this cert chains to the trusted Device CA root; None if not checked (anchor absent)",
    )
    error: str | None = Field(
        default=None, description="Verification error detail when valid is False"
    )
    pem: str | None = Field(
        default=None,
        description="The birth certificate PEM (public) so a client can independently re-verify",
    )


class LicenseEntitlementModel(BaseModel):
    feature: str
    granted: bool | None = None
    channels: list[str] | None = None
    swupdate_min_version: str | None = Field(
        default=None,
        description=(
            "Anti-downgrade floor on a swupdate entitlement. The broker denies every "
            "explicit-version request on a non-debug channel when this is absent, and "
            "the floor is minted ONCE at enrollment -- so a device that enrolled "
            "before the Authority issued one shows null here and can only ever ask "
            "for -latest. Surfaced so an operator can confirm a re-enrollment "
            "repaired it, rather than discovering it from a failed update."
        ),
    )


class LicenseModel(BaseModel):
    present: bool
    lic_id: str | None = None
    issuer: str | None = None
    device_id: str | None = None
    instance_id: str | None = None
    issued_at: datetime | None = None
    not_after: datetime | None = None
    entitlements: list[LicenseEntitlementModel] = Field(default_factory=list)
    valid: bool | None = Field(
        default=None,
        description="True if the device verified this license's signature under the trusted Authority signer; None if not checked (anchor absent)",
    )
    error: str | None = Field(
        default=None, description="Verification error detail when valid is False"
    )
    token: str | None = Field(
        default=None,
        description="The compact-JWS license token (public, signed) so a client can independently re-verify",
    )


class DeviceLicenseStatusModel(BaseModel):
    """The full device identity / license picture for the UI."""

    identity: DeviceIdentityModel
    birth_cert: BirthCertModel
    license: LicenseModel
    healthy: bool = Field(
        default=False,
        description="Operational HEALTH REPORT: birth cert and license verify against the trust anchors AND a CURRENT device-key measurement says the key still signs. Goes false when the measurement stops being refreshed, because a publisher that stopped is a real fault worth surfacing. Do not gate updates on this -- see update_ready",
    )
    update_ready: bool = Field(
        default=False,
        description="Device-side UPDATE PRE-CHECK: enrolled, birth cert and license verify against the trust anchors, and the device key is not KNOWN to be bad. Deliberately tolerates an unknown or stale key measurement, because the authoritative test is the live proof-of-possession the device signs at update time. NOT an authorization decision: device binding, update entitlement and revocation are enforced by the broker, so never use this in place of asking it",
    )
