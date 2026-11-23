#!/usr/bin/python3


from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from eshieldq.gateway.schemas.certs import SSHPubKeyModel

API_USERS = "/users"
API_USERS_V1 = API_USERS + "/v1"
API_USERS_V2 = API_USERS + "/v2"


class Role(str, Enum):
    """Built-in RBAC roles. The set of roles is extensible; the permissions
    attached to each role are decided by the server, not by this enum."""

    ADMIN = "admin"
    OPERATOR = "operator"


class UserName(BaseModel):
    username: str

    @field_validator("username")
    @classmethod
    def check_username(cls, username: str) -> str:
        if len(username) > 32:
            raise ValueError("Username must be at most 32 characters long")

        # check for valid characters
        special_chars = "@-_."
        if not all(c.isalnum() or c in special_chars for c in username):
            valid_chars = f"(only A-Z, a-z, 0-9, {special_chars})"
            raise ValueError("Invalid username must be alphanumeric, " + valid_chars)

        return username


class UserBase(UserName):
    is_admin: bool = Field(default=False)
    is_active: bool = Field(default=True)
    role: Role | None = Field(
        default=None,
        description="RBAC role. Authoritative over is_admin; when omitted it is "
        "derived from is_admin for backward compatibility.",
    )

    @model_validator(mode="after")
    def _reconcile_role_and_is_admin(self) -> "UserBase":
        # role is the source of truth; is_admin is kept in sync for backward
        # compatibility. Older clients that only send is_admin still work.
        if self.role is None:
            self.role = Role.ADMIN if self.is_admin else Role.OPERATOR
        else:
            self.is_admin = self.role == Role.ADMIN
        return self


class UserInfo(UserBase):
    is_otp_enabled: bool = Field(default=False)
    is_otp_enrolled: bool = Field(
        default=False,
        description="A confirmed second factor exists for this account. "
        "Metadata only -- the seed itself is never returned.",
    )
    enrollment_required: bool = Field(
        default=False,
        description="The acting session is scoped to enrollment only.",
    )


class SSHUserInfo(UserName):
    public_key: SSHPubKeyModel = Field(description="SSH Public Key")
    pass


class UserPassword(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def password_verify(cls, password: str) -> str:
        if len(password) < 14:
            raise ValueError("Password must be at least 14 characters long")
        # spaces are not allowed
        if " " in password:
            raise ValueError("Password cannot contain spaces")
        # check for number, letter and special character
        special_chars = "!@#$%^&*()-+?_=,<>/."
        if (
            not any(char.isdigit() for char in password)
            or not any(char.isalpha() for char in password)
            or not any(char in special_chars for char in password)
        ):
            raise ValueError(
                f"Password must contain at least one number, one letter and one special character ({special_chars})"
            )
        return password


class UserLogin(UserName, UserPassword):
    scope: str = Field(default="")
    client_id: str | None = Field(description="Oauth2 Client ID", default=None)
    client_secret: str | None = Field(
        description="Oauth2 Client Secret (when OTP is enabled this is the OTP)",
        default=None,
    )


class UserChangePassword(UserLogin):
    new_password: UserPassword


class UserCreate(UserBase, UserPassword):
    # OTP state is set by enrollment, not here; refuse any undeclared field.
    model_config = ConfigDict(extra="forbid")


class InitialUser(UserCreate):
    instance_id: str | None = Field(
        description="Instance ID - must match Instance ID assigned in order to add initial user",
        default=None,
    )


def _validate_password_strength(password: str) -> str:
    if len(password) < 14:
        raise ValueError("Password must be at least 14 characters long")
    if " " in password:
        raise ValueError("Password cannot contain spaces")
    special_chars = "!@#$%^&*()-+?_=,<>/."
    if (
        not any(char.isdigit() for char in password)
        or not any(char.isalpha() for char in password)
        or not any(char in special_chars for char in password)
    ):
        raise ValueError(
            "Password must contain at least one number, one letter and one "
            f"special character ({special_chars})"
        )
    return password


class UserUpdate(BaseModel):
    """Partial update for an existing user. Only the supplied fields change.

    ``username`` is taken from the request path, not the body.
    """

    # A misspelled password field would otherwise be dropped and nothing reset.
    model_config = ConfigDict(extra="forbid")

    role: Role | None = Field(default=None, description="New RBAC role")
    is_active: bool | None = Field(
        default=None, description="Enable (true) or deactivate (false) the account"
    )
    password: str | None = Field(
        default=None,
        description="Reset another user's password. Your own password is "
        "changed with change-password, which asks for the current one.",
    )

    @field_validator("password")
    @classmethod
    def password_verify(cls, password: str | None) -> str | None:
        if password is None:
            return None
        return _validate_password_strength(password)


class RoleInfo(BaseModel):
    """A role and the access level it grants in each feature area."""

    role: Role
    description: str = Field(default="")
    builtin: bool = Field(
        default=True, description="Built-in roles cannot be edited or deleted"
    )
    # area name -> access level name ("none" | "read" | "read_write")
    permissions: dict[str, str] = Field(default_factory=dict)
