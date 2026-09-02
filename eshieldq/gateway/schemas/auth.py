#!/usr/bin/python3


from pydantic import BaseModel, Field

API_AUTH = "/auth"
API_AUTH_V1 = API_AUTH + "/v1"
API_AUTH_V2 = API_AUTH + "/v2"

API_AUTH_V1_TOKEN = API_AUTH_V1 + "/token"
API_AUTH_V2_TOKEN = API_AUTH_V2 + "/token"


class LoginResultModel(BaseModel):
    """Result of a successful token request.

    ``enrollment_required`` is the only way a cookie client can tell an
    enrollment-scoped session from a full one: the cookie is opaque and
    HttpOnly, and an unenrolled account looks identical to an enrolled one on
    every other field.
    """

    detail: str = Field(default="ok")
    enrollment_required: bool = Field(
        default=False,
        description="The session is scoped to enrollment only. Every route "
        "outside the enrollment allow-list refuses it until a factor is "
        "confirmed.",
    )


class OtpEnrollModel(BaseModel):
    """The one and only response that ever carries a TOTP seed.

    The seed is inside ``uri``. It is minted here, held as an unconfirmed
    pending enrollment, and never readable again by any endpoint -- losing it
    means enrolling again, which mints a new one.
    """

    enrollment_id: str = Field(
        description="Identifies this enrollment attempt. Must be echoed back "
        "when confirming, so a superseded attempt cannot be confirmed."
    )
    uri: str = Field(description="otpauth:// provisioning URI")
    qrcode_b64: str = Field(description="Base64 PNG QR code of the same URI")


class OtpEnrollRequest(BaseModel):
    password: str = Field(description="The caller's current password")
    otp_value: str | None = Field(
        default=None,
        description="The current one-time password. Required when the account "
        "already has a factor enrolled.",
    )
    activation_code: str | None = Field(
        default=None,
        description="Single-use code issued by an administrator. Required when "
        "otp_enrollment_requires_admin_token is set and the caller is enrolling "
        "from an enrollment-scoped session.",
    )


class OtpEnableRequest(OtpEnrollRequest):
    enrollment_id: str = Field(description="From the enroll response")
    otp_code: str = Field(
        description="A code generated from the pending seed, proving the "
        "authenticator was provisioned."
    )


class OtpDisableRequest(BaseModel):
    password: str = Field(description="The caller's current password")
    otp_value: str = Field(
        description="The current one-time password. Removing a factor always "
        "requires proving possession of it."
    )


class OtpActivationCodeModel(BaseModel):
    """Shown once, when an administrator issues it."""

    activation_code: str = Field(description="Single-use enrollment code")
    expires_at: str = Field(description="ISO timestamp after which it is refused")


class SysSecuritySettings(BaseModel):
    otp_enforce: bool = Field(
        description="OTP Enforcement setting for all users. When set all users must provide OTP for login.",
        default=False,
    )
    otp_enrollment_requires_admin_token: bool = Field(
        default=True,
        description="Require an administrator-issued single-use activation "
        "code before a user enrolling from an enrollment-scoped session can "
        "claim a second factor. Defaults on so a stolen password alone cannot "
        "register an attacker's authenticator; clear it only for a supervised "
        "fleet rollout.",
    )
    token_timeout_sec: int = Field(
        default=30 * 60,
        ge=60,
        le=86400,
        description="Longest an issued API/UI session token stays valid "
        "(default: 30 minutes). Range 60 to 86400 seconds (1 minute to 1 day). "
        "A logout, a password change or a role change signs the session out "
        "sooner; this is the cap when none of those happen, so keep it short.",
    )
    password_timeout_sec: int = Field(
        description="Password Timeout in seconds (default: 90 days)", default=86400 * 90
    )
    login_lockout_threshold: int = Field(
        default=5,
        ge=0,
        le=100,
        description="Failed logins from one client address for one account "
        "before this appliance refuses further attempts for that pair, without "
        "checking the credential. Counts wrong passwords and wrong one-time "
        "passwords. Set 0 to disable the limiter and allow unlimited guessing.",
    )
    login_lockout_window_sec: int = Field(
        default=900,
        ge=60,
        le=3600,
        description="How long a failed login is remembered. Failures older "
        "than this stop counting toward the threshold, so occasional mistakes "
        "spread over a working day never accumulate into a lockout.",
    )
    login_lockout_duration_sec: int = Field(
        default=300,
        ge=60,
        le=3600,
        description="How long a lockout lasts. Attempts made during a lockout "
        "do not extend it. There is deliberately no indefinite value: an "
        "administrator locked out of the only management interface has to be "
        "able to wait it out, or log in from another address.",
    )
