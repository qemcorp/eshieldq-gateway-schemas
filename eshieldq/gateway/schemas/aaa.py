#!/usr/bin/python3

"""Named AAA profiles: one authentication backend, selected per connection.

Before this module a gateway had exactly one remote-access AAA backend --
directory (LDAP) or external RADIUS, never both -- because charon's eap-radius
plugin has a single global server set and both wrote it.

A profile is a NAME plus one backend body. A remote-access connection names the
profile it authenticates against, and the broker routes by the IKE connection
name charon puts in ``NAS-Port-Id``. There is deliberately no ordered fallback
sequence: a RADIUS ``Access-Reject`` does not distinguish an unknown user from a
wrong password, so "fall through on user unknown" can only be inferred from
``Reply-Message`` -- which turns a bad password into a weaker backend's accept.
Every reject and every infrastructure failure is terminal, and local users stay
a connection of their own (``remote_auth_method=eap-mschapv2``). That is the
Cisco/PAN "connection profile chooses the backend" model.

Secrets are write-only everywhere here: the read and list models carry only a
``*_configured`` flag, exactly as the single-backend models did.
"""

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from eshieldq.gateway.schemas.ipsec import (
    RadiusServerConfigModel,
    RadiusServerModel,
    RadiusSourceInterfaceEnum,
)
from eshieldq.gateway.schemas.ldap import LdapConfigModel, LdapSetConfigModel

API_AAA = "/aaa"


class AaaProfileTypeEnum(str, Enum):
    """Which backend a profile is. The body field of the same name carries it."""

    RADIUS = "radius"
    LDAP = "ldap"


#: Reserved names holding the configuration a single-backend appliance had
#: before profiles existed. The migration copies the legacy rows into these,
#: ciphertext unchanged, so no secret is ever re-entered; the API adapters at
#: /ipsec/v1/radius and /ipsec/v1/ldap read and write them.
LEGACY_RADIUS_PROFILE = "legacy-radius"
LEGACY_LDAP_PROFILE = "legacy-ldap"
RESERVED_PROFILE_NAMES = frozenset({LEGACY_RADIUS_PROFILE, LEGACY_LDAP_PROFILE})

#: A profile name is rendered into FreeRADIUS identifiers (a realm, a home
#: server pool) and compared against ``NAS-Port-Id`` in an exact allowlist, so
#: it is restricted to what is safe in both places rather than escaped later.
MAX_PROFILE_NAME_LEN = 48
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")

#: How many profiles one gateway may hold. Each brokered RADIUS profile is a
#: home-server pool and a realm in the broker's configuration, and each is a
#: switch arm in the dial-up ``authorize`` section.
MAX_PROFILES = 16

#: At most one DIRECTORY profile per gateway, this cycle.
#:
#: Not a policy choice -- a broker limitation stated rather than discovered. The
#: inner EAP-TTLS tunnel dispatches EAP-GTC to a single ``Auth-Type LDAP``
#: (``rlm_eap_gtc``'s ``auth_type`` is a module-level setting), so serving a
#: second directory would mean branching the authentication block that
#: implements it. That cannot be validated without a live broker per
#: permutation, so a second directory profile is refused with an actionable
#: error rather than rendered unproven. External RADIUS has no such limit:
#: proxying is per realm and needs no branch in that block at all.
MAX_LDAP_PROFILES = 1


def profile_realm(name: str) -> str:
    """The FreeRADIUS realm a brokered RADIUS profile proxies through.

    Prefixed so it cannot collide with a realm an operator's own configuration
    might mean, and stable, because ``Proxy-To-Realm`` names it from the
    rendered switch.
    """
    return f"sk-aaa-{name}"


def profile_pool(name: str) -> str:
    """The home-server pool holding one profile's servers, in order."""
    return f"sk-pool-{name}"


def validate_profile_name(value: str) -> str:
    text = value.strip()
    if not _PROFILE_NAME_RE.match(text):
        raise ValueError(
            "A profile name must start with a letter or digit and contain only "
            "letters, digits, '.', '_' or '-', at most "
            f"{MAX_PROFILE_NAME_LEN} characters"
        )
    return text


class AaaProfileBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        description="Profile name. Referenced by a remote-access connection's "
        "'aaa_profile', and rendered into the broker's realm and home-server "
        "pool names.",
        examples=["corp-radius"],
    )
    type: AaaProfileTypeEnum = Field(
        description="Which backend this profile authenticates against. The "
        "body field of the same name carries its configuration."
    )
    description: str | None = Field(
        default=None,
        description="Free-text note shown to the operator.",
        max_length=255,
    )

    @field_validator("name", mode="after")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return validate_profile_name(value)

    @field_validator("description", mode="after")
    @classmethod
    def _validate_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
            raise ValueError("description must not contain control characters")
        return text


class AaaProfileModel(AaaProfileBase):
    """READ model. Carries no secret -- see the ``*_configured`` flags on the
    bodies, which is how the single-backend models already report one."""

    radius: RadiusServerModel | None = Field(
        default=None,
        description="RADIUS body, present when type is 'radius'. Shared "
        "secrets are never included.",
    )
    ldap: LdapConfigModel | None = Field(
        default=None,
        description="Directory body, present when type is 'ldap'. The bind "
        "password is never included.",
    )
    reserved: bool = Field(
        default=False,
        description="A profile created by the upgrade from a single-backend "
        "configuration. It may be edited but not renamed or deleted, because "
        "the /ipsec/v1/radius and /ipsec/v1/ldap endpoints are adapters over "
        "it.",
    )
    brokered: bool = Field(
        default=True,
        description="Whether this profile is served through the on-box broker. "
        "False only for a RADIUS profile sourced from the WAN interface, which "
        "charon addresses directly.",
    )

    @model_validator(mode="after")
    def _body_matches_type(self):
        # The READ model allows NO body, unlike the write model. That is how a
        # reserved profile reports itself once emptied: the row survives so the
        # /ipsec/v1/{ldap,radius} adapters keep answering and the stored
        # ciphertext outlives a delete, but there is no configuration to return.
        # A body of the WRONG type is still refused.
        _assert_one_body(self.type, self.radius, self.ldap, required=False)
        return self


class AaaProfileSetModel(AaaProfileBase):
    """WRITE model. Exactly one body, matching ``type``, carrying its own
    write-only secrets (encrypted at rest, never returned)."""

    radius: RadiusServerConfigModel | None = Field(
        default=None,
        description="RADIUS body, required when type is 'radius'. Each server "
        "carries its own write-only shared secret; omit a server's secret to "
        "keep the stored one.",
    )
    ldap: LdapSetConfigModel | None = Field(
        default=None,
        description="Directory body, required when type is 'ldap'. The bind "
        "password is write-only; omit it to keep the stored one.",
    )

    @model_validator(mode="after")
    def _body_matches_type(self):
        _assert_one_body(self.type, self.radius, self.ldap)
        return self


def _assert_one_body(profile_type, radius, ldap, *, required: bool = True) -> None:
    """Exactly the body named by ``type``, and nothing else.

    The wrong body is refused rather than resolved by precedence: a profile
    carrying a RADIUS body while typed 'ldap' would render whichever the
    renderer happened to look at first, and the operator would be told it was
    the other one.

    ``required`` is False for the read model, where no body at all is the
    emptied-reserved-profile state.
    """
    bodies = {
        AaaProfileTypeEnum.RADIUS: radius,
        AaaProfileTypeEnum.LDAP: ldap,
    }
    if required and bodies[profile_type] is None:
        raise ValueError(f"a '{profile_type.value}' profile requires a {profile_type.value} body")
    for other, body in bodies.items():
        if other != profile_type and body is not None:
            raise ValueError(
                f"a '{profile_type.value}' profile must not carry a "
                f"{other.value} body"
            )


def profile_is_brokered(profile: AaaProfileSetModel | AaaProfileModel) -> bool:
    """Whether the broker serves this profile, or charon addresses it directly.

    Only one shape is not brokered: a RADIUS profile sourced from the WAN
    interface. radiusd runs in the root network namespace and the WAN address
    belongs to the VPP dataplane, so the broker cannot bind it as a proxy
    source. Such a profile keeps today's charon-direct path and is accepted
    only as the sole remote profile.
    """
    if profile.type != AaaProfileTypeEnum.RADIUS or profile.radius is None:
        return True
    return profile.radius.source_interface != RadiusSourceInterfaceEnum.WAN
