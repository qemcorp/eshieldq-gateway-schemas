#!/usr/bin/python3


from pydantic import BaseModel, Field, field_validator

API_AUTH = "/auth"
API_AUTH_V1 = API_AUTH + "/v1"
API_AUTH_V2 = API_AUTH + "/v2"

API_AUTH_V1_TOKEN = API_AUTH_V1 + "/token"
API_AUTH_V2_TOKEN = API_AUTH_V2 + "/token"

# How long a request that hashes a password may take: the appliance ENFORCES
# each route's deadline below (a request that cannot finish inside it fails
# before it changes anything), and sk_client waits the deadline plus a network
# margin. One source for both, so neither can drift from the other.

#: A caller that has logged in recently waits up to this long for a login slot.
AUTH_KNOWN_GOOD_WAIT_SECONDS = 2
#: Delay served after a rejected credential, before the answer.
AUTH_RETRY_AFTER_SECONDS = 1
#: A password write (set or create) waits up to this long for a hash permit.
AUTH_HASH_WRITE_WAIT_SECONDS = 15
#: One sha512_crypt hash or verification at 656 000 rounds, child start included.
PASSWORD_HASH_ALLOWANCE_SECONDS = 5
#: Hashes that may be ahead of this one in the hash pool, as allowed for.
HASH_QUEUE_ALLOWANCE = 2
#: The bootstrap route's `cloud-init query instance-id` is cut off after this.
INSTANCE_ID_QUERY_SECONDS = 10
#: Left for the commit: SQLite's 5 s busy wait plus the write. A change does
#: not start committing with less than this to go.
CREDENTIAL_COMMIT_RESERVE_SECONDS = 6
#: The client's wait beyond a route's deadline: the response and the network.
CREDENTIAL_NETWORK_MARGIN_SECONDS = 5


def credential_route_deadline_seconds(
    *, verifies: int = 0, writes: int = 0, admission: bool = False, extra_wait: int = 0
) -> int:
    """The enforced deadline of a route that verifies ``verifies`` passwords
    and hashes ``writes`` new ones. ``admission`` is a login slot plus the
    rejection delay; ``extra_wait`` is any other wait the route bounds."""
    wait = extra_wait + writes * AUTH_HASH_WRITE_WAIT_SECONDS
    if admission:
        wait += AUTH_KNOWN_GOOD_WAIT_SECONDS + AUTH_RETRY_AFTER_SECONDS
    hashes = (verifies + writes + HASH_QUEUE_ALLOWANCE) * PASSWORD_HASH_ALLOWANCE_SECONDS
    return wait + hashes + CREDENTIAL_COMMIT_RESERVE_SECONDS


#: POST /auth/v2/token, and the OTP step-up routes that re-verify a password.
LOGIN_DEADLINE_SECONDS = credential_route_deadline_seconds(verifies=1, admission=True)
#: POST /auth/v1/change-password: verify the old password, hash the new one.
CHANGE_PASSWORD_DEADLINE_SECONDS = credential_route_deadline_seconds(
    verifies=1, writes=1, admission=True
)
#: POST /users/v1/register, and PATCH /users/v1/{user} with a password.
PASSWORD_WRITE_DEADLINE_SECONDS = credential_route_deadline_seconds(writes=1)
#: POST /users/v2/initial: a login slot, the instance-id query, one hash.
INITIAL_USER_DEADLINE_SECONDS = credential_route_deadline_seconds(
    writes=1, admission=True, extra_wait=INSTANCE_ID_QUERY_SECONDS
)

#: sk_client's read timeout for each of those routes.
LOGIN_TIMEOUT_SECONDS = LOGIN_DEADLINE_SECONDS + CREDENTIAL_NETWORK_MARGIN_SECONDS
CHANGE_PASSWORD_TIMEOUT_SECONDS = (
    CHANGE_PASSWORD_DEADLINE_SECONDS + CREDENTIAL_NETWORK_MARGIN_SECONDS
)
PASSWORD_WRITE_TIMEOUT_SECONDS = (
    PASSWORD_WRITE_DEADLINE_SECONDS + CREDENTIAL_NETWORK_MARGIN_SECONDS
)
INITIAL_USER_TIMEOUT_SECONDS = (
    INITIAL_USER_DEADLINE_SECONDS + CREDENTIAL_NETWORK_MARGIN_SECONDS
)


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


#: password_timeout_sec value meaning passwords never expire.
PASSWORD_TIMEOUT_NEVER = 0
#: Shortest password lifetime a release image accepts (1 day).
PASSWORD_TIMEOUT_MIN_SEC = 86400
#: Longest password lifetime accepted on every image (365 days).
PASSWORD_TIMEOUT_MAX_SEC = 365 * 86400
#: Shortest password lifetime accepted where short lifetimes are enabled.
PASSWORD_TIMEOUT_DEBUG_MIN_SEC = 30
PASSWORD_TIMEOUT_DEFAULT_SEC = 90 * 86400
PASSWORD_TIMEOUT_RANGE = (
    "password_timeout_sec must be 0 (passwords never expire) or "
    f"{PASSWORD_TIMEOUT_MIN_SEC} to {PASSWORD_TIMEOUT_MAX_SEC} seconds (1 to 365 days)"
)


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
        default=PASSWORD_TIMEOUT_DEFAULT_SEC,
        description="How long a password stays valid before it must be changed, "
        "in seconds (default: 90 days). 0 means passwords never expire; "
        "otherwise 86400 to 31536000 seconds (1 to 365 days).",
        json_schema_extra={"minimum": 0, "maximum": PASSWORD_TIMEOUT_MAX_SEC},
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

    @field_validator("password_timeout_sec")
    @classmethod
    def _password_timeout_in_range(cls, value: int) -> int:
        # The release floor depends on the image, so the appliance enforces it.
        if value < PASSWORD_TIMEOUT_NEVER or value > PASSWORD_TIMEOUT_MAX_SEC:
            raise ValueError(PASSWORD_TIMEOUT_RANGE)
        return value
