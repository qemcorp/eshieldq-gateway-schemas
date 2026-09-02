#!/usr/bin/python3

"""Schemas for LDAP / Active Directory authentication of remote-access users.

The gateway authenticates dial-up users against a customer directory the same
way FortiGate (``config user ldap``) and Cisco ASA/FTD (``aaa-server ... protocol
ldap``) do: it binds to the directory as the user. That requires the user's
cleartext password, so the IKEv2 EAP method is EAP-GTC (the credential travels
inside the encrypted IKE_AUTH exchange). EAP-MSCHAPv2 cannot be used against a
directory — it never yields a cleartext password — which is the same limitation
both competitors have.

Values here are rendered into the configuration of the on-appliance FreeRADIUS
broker (see ``raddb_render``), whose renderer escapes every user-supplied value
per RFC 4515 (filters) and RFC 4514 (DNs) before it reaches the directory. The
validators in this module are defence in depth on top of that, not a substitute
for it.
"""

import ipaddress
import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

API_LDAP = "/ldap"


class AaaBackendEnum(str, Enum):
    """Which backend owns charon's eap-radius server set.

    charon has one global server set for the whole daemon, so directory auth and
    external RADIUS cannot both hold it. This is the discriminator that decides,
    rather than two independent config rows racing to write the same file.
    """

    NONE = "none"
    LDAP = "ldap"
    RADIUS = "radius"

# xauth_pam.c authenticates through fixed user[128]/pass[128] buffers, so a
# longer identity or password can never reach the directory intact. Reject it at
# the edge instead of silently truncating.
PAM_CREDENTIAL_MAX = 128

# Bounds on how much work one authentication can create, and on how much
# operator input the broker has to parse. Not arbitrary tidiness: rlm_ldap tries
# each server in turn, so N servers at timeout_secs each is how long a single
# attacker-driven request can occupy one of the broker's eight workers.
MAX_SERVERS = 4
MAX_ALLOWED_GROUPS = 64
MAX_CA_PEM_BYTES = 64 * 1024
# A ceiling on servers x per-request timeout: the whole failover chain, i.e. the
# longest a worker can be held by one authentication.
MAX_TOTAL_FAILOVER_SECS = 60

# Attempt-limiter defaults, chosen to match what the incumbents ship rather than
# invented: FortiGate auth-lockout-threshold is 3, Cisco ASA max-failed-attempts
# is 3. The ceiling keeps a lockout well inside one support call.
#
# The floor is a duration, not a formality: too short a lockout is never
# observed by the client at all. This module is published, so the reasoning
# behind the specific values lives in the commit history rather than here.
DEFAULT_LOCKOUT_THRESHOLD = 3
DEFAULT_LOCKOUT_DURATION_SECS = 180
MIN_LOCKOUT_DURATION_SECS = 180
MAX_LOCKOUT_DURATION_SECS = 3600

# RFC 4512 attribute descriptor: letter, then letters/digits/hyphen. Attribute
# names are spliced into search filters, so an allowlist here removes that
# injection avenue entirely rather than relying on escaping alone.
_ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")

_HOSTNAME_PART_RE = re.compile(r"(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")


def _reject_over_byte_limit(value: str, field: str, limit: int = PAM_CREDENTIAL_MAX) -> None:
    """Enforce the limit in UTF-8 BYTES, which is what the wire and the C
    buffers underneath actually count.

    Pydantic's max_length counts characters, so "128 characters" of multibyte
    UTF-8 is up to 512 bytes: it passes the schema and then overruns the RADIUS
    User-Password field (capped at 128 encoded bytes) or xauth_pam.c's fixed
    user[128]/pass[128]. Rejected here rather than truncated -- silently
    shortening a credential turns a typo into a different password.
    """
    encoded = len(value.encode("utf-8"))
    if encoded > limit:
        raise ValueError(
            f"{field} must be at most {limit} bytes when UTF-8 encoded "
            f"(this value is {encoded})"
        )


def _reject_ldap_control_chars(value: str, field: str) -> None:
    """Reject control characters and NUL in a value bound for the directory.

    A NUL truncates the value in the C client library underneath, and control
    characters have no legitimate place in a DN, filter or attribute name.
    """
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError(f"{field} must not contain control characters")


def _validate_dn(value: str, field: str, *, max_length: int = 512) -> str:
    text = value.strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    if len(text) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    _reject_ldap_control_chars(text, field)
    return text


def _validate_filter(value: str, field: str, *, max_length: int = 512) -> str:
    """Validate an operator-supplied LDAP filter fragment.

    Parentheses are legitimate here (this is a filter), so they cannot be
    rejected the way they are in a DN. Check the parentheses balance instead —
    an unbalanced fragment is always a mistake and would otherwise produce a
    confusing directory-side error at authentication time.
    """
    text = value.strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    if len(text) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    _reject_ldap_control_chars(text, field)
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError(f"{field} has unbalanced parentheses")
    if depth != 0:
        raise ValueError(f"{field} has unbalanced parentheses")
    return text


def _validate_attribute(value: str, field: str) -> str:
    text = value.strip()
    if not _ATTRIBUTE_RE.match(text):
        raise ValueError(
            f"{field} must be an LDAP attribute name (letter, then letters, "
            f"digits or hyphens)"
        )
    return text


class LdapSecurityEnum(str, Enum):
    """Transport security for the directory connection. Always TLS.

    There is deliberately no plaintext option. We authenticate by binding as the
    user, so an unencrypted connection would put the service-account password
    AND every VPN user's corporate password on the wire in cleartext, and would
    leave the directory's identity unverified -- meaning anything that can answer
    on port 389 can harvest passwords or accept any password outright. That is
    not a warning-worthy option on a security appliance; FortiGate and Cisco both
    permit it and we deliberately do not.

    StartTLS is the low-friction choice: it upgrades on port 389, so no new
    firewall rule is needed to stop sending credentials in the clear.
    """

    STARTTLS = "starttls"
    LDAPS = "ldaps"


class LdapBindTypeEnum(str, Enum):
    """How the gateway locates the user entry before binding as the user.

    Mirrors FortiGate's ``type``, minus ``simple``. FortiGate's ``simple`` builds
    the user DN from a template and skips the search; we do not offer it for two
    independent reasons. The broker (rlm_ldap) always searches and has no
    DN-template mode, and against Active Directory there is no correct template
    anyway -- AD's RDN is the DISPLAY name, so alice is
    ``CN=Alice Anderson,...``, not ``CN=alice,...``. That bites asymmetrically:
    a service account created without a given/surname does have a login-shaped
    RDN, so templating appears to work right up until a real user tries it.
    """

    ANONYMOUS = "anonymous"
    REGULAR = "regular"


class LdapScopeEnum(str, Enum):
    BASE = "base"
    ONE = "one"
    SUBTREE = "subtree"


class LdapGroupCheckEnum(str, Enum):
    """How group membership is determined (FortiGate ``group-member-check``).

    ``user_attr`` reads an attribute on the user entry (``memberOf``);
    ``group_object`` searches group entries for the user's DN (``member``);
    ``posix_group`` searches posixGroup entries for the bare username
    (``memberUid``).
    """

    USER_ATTR = "user_attr"
    GROUP_OBJECT = "group_object"
    POSIX_GROUP = "posix_group"


# Group-membership modes the appliance does NOT yet qualify.
#
# ``group_object`` and ``posix_group`` are rendered correctly and FreeRADIUS
# accepts them, but no test has ever authenticated a real user through either
# one on an appliance, against either OpenLDAP or Active Directory. Exposing a
# mode nobody has authenticated through is a support commitment we cannot
# honour, and the alternative to testing them is not shipping them.
#
# Gated on the WRITE model only. The read/stored model stays open on purpose:
# configuration is re-validated on boot rehydration, so rejecting these
# everywhere would strand a device that already has one configured -- it would
# fail to load its directory configuration on the update that shipped the gate,
# which is a worse outcome than the untested mode. Same reasoning as the
# remote-access reauth bound in eshieldq.gateway.schemas.ipsec.
UNQUALIFIED_GROUP_CHECKS = frozenset(
    {LdapGroupCheckEnum.GROUP_OBJECT, LdapGroupCheckEnum.POSIX_GROUP}
)


QUALIFIED_GROUP_CHECKS = tuple(
    check.value
    for check in LdapGroupCheckEnum
    if check not in UNQUALIFIED_GROUP_CHECKS
)


# NOTE: there is deliberately no LdapSourceInterfaceEnum. The RADIUS model has
# a source_interface because charon binds the socket itself; the directory
# connection is made by libldap inside the broker, which has no source-address
# option. Offering the field would have meant shipping a control that silently
# does nothing. If WAN-sourced directory traffic is ever actually required it
# comes back as an additive change -- the non-breaking direction.


class LdapServerEntryModel(BaseModel):
    """A single directory server. Servers are tried in order for failover."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(
        description="Directory server hostname. Must be the DNS name the "
        "server's certificate is issued to: certificate identity is always "
        "verified and is matched against DNS names, so a bare IP cannot be "
        "validated.",
        examples=["ldap.example.com"],
    )
    port: int = Field(
        description="Directory server TCP port (389 for ldap/starttls, 636 for "
        "ldaps)",
        ge=1,
        le=65535,
        default=389,
    )

    @field_validator("address", mode="after")
    @classmethod
    def validate_address(cls, value: str) -> str:
        text = value.strip()
        try:
            ipaddress.ip_address(text)
            return text
        except ValueError:
            pass
        if not text or len(text) > 255:
            raise ValueError(f"Invalid LDAP server address: {value}")
        if not all(
            _HOSTNAME_PART_RE.match(part) for part in text.rstrip(".").split(".")
        ):
            raise ValueError(f"Invalid LDAP server address: {value}")
        return text


class LdapConfigBase(BaseModel):
    """Fields common to the read and write models (everything but the secret)."""

    model_config = ConfigDict(extra="forbid")

    servers: list[LdapServerEntryModel] = Field(
        default_factory=list,
        max_length=MAX_SERVERS,
        description="Directory servers, tried in order for failover. At most "
        f"{MAX_SERVERS}: every extra server is another timeout one "
        "authentication can make a broker worker wait through.",
    )
    security: LdapSecurityEnum = Field(
        default=LdapSecurityEnum.LDAPS,
        description="Transport security. Always TLS: LDAPS (implicit, port 636) "
        "or StartTLS (upgrade on port 389). There is no plaintext option -- we "
        "bind as the user, so that would put the user's own corporate password "
        "on the wire.",
    )
    ca_cert_pem: str | None = Field(
        default=None,
        max_length=MAX_CA_PEM_BYTES,
        description="PEM CA certificate used to validate the directory "
        "server's certificate. Always required. There is deliberately no option "
        "to skip certificate validation.",
    )
    # NOTE: there is deliberately no server_identity_check toggle. FortiGate has
    # one; we always verify. The client library validates the certificate name
    # whenever it validates the chain at all, so a toggle could not be honoured
    # -- and shipping a security switch that silently does nothing is worse than
    # not offering it. Certificate identity is always checked under TLS.
    base_dn: str = Field(
        description="Base DN under which user entries are searched",
        examples=["ou=people,dc=example,dc=com"],
    )
    username_attribute: str = Field(
        default="uid",
        description="Attribute holding the login name (FortiGate 'cnid', "
        "Cisco 'ldap-naming-attribute'). Typically 'uid' for OpenLDAP or "
        "'sAMAccountName' for Active Directory.",
        examples=["uid", "sAMAccountName"],
    )
    bind_type: LdapBindTypeEnum = Field(
        default=LdapBindTypeEnum.REGULAR,
        description="How the user entry is located before binding as the user.",
    )
    bind_dn: str | None = Field(
        default=None,
        description="Service-account DN used to search for user entries. "
        "Required when bind_type is 'regular'.",
        examples=["cn=svc-vpn,ou=service,dc=example,dc=com"],
    )
    search_scope: LdapScopeEnum = Field(
        default=LdapScopeEnum.SUBTREE,
        description="Scope of the user search below base_dn",
    )
    user_filter: str | None = Field(
        default=None,
        description="Additional filter ANDed with the username match, e.g. to "
        "restrict to enabled accounts.",
        examples=["(objectClass=person)"],
    )
    group_check: LdapGroupCheckEnum = Field(
        default=LdapGroupCheckEnum.USER_ATTR,
        description="How group membership is determined.",
    )
    group_base_dn: str | None = Field(
        default=None,
        description="Base DN for group searches. Required when group_check is "
        "'group_object' or 'posix_group'.",
        examples=["ou=groups,dc=example,dc=com"],
    )
    member_attribute: str = Field(
        default="memberOf",
        description="Membership attribute: 'memberOf' on the user entry for "
        "user_attr, 'member' on the group entry for group_object, or "
        "'memberUid' for posix_group.",
        examples=["memberOf", "member", "memberUid"],
    )
    group_filter: str | None = Field(
        default=None,
        description="Additional filter ANDed with the group-object search.",
        examples=["(objectClass=groupOfNames)"],
    )
    nested_groups: bool = Field(
        default=False,
        description="Resolve nested group membership (Active Directory only). "
        "AD's memberOf lists only DIRECT membership, so a user who reaches an "
        "allowed group through an intermediate group is otherwise denied -- "
        "silently, since it looks like a legitimate authorization failure. "
        "Enabling this uses AD's LDAP_MATCHING_RULE_IN_CHAIN "
        "(1.2.840.113556.1.4.1941), which OpenLDAP does not implement; leave "
        "it off for non-AD directories.",
    )
    allowed_groups: list[str] = Field(
        default_factory=list,
        description="Only members of these groups may connect (FortiGate "
        "'authusrgrp'). DNs for user_attr/group_object, bare group names for "
        "posix_group. Empty means any successfully authenticated user.",
    )
    timeout_secs: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Per-request directory timeout. Kept short so an "
        "unreachable directory fails fast instead of stalling IKE.",
    )
    lockout_threshold: int = Field(
        default=DEFAULT_LOCKOUT_THRESHOLD,
        ge=0,
        le=100,
        description="Consecutive rejected credential checks, per client address "
        "and username, before the broker stops asking the directory and refuses "
        "the attempt itself (FortiGate 'auth-lockout-threshold', Cisco ASA "
        "'max-failed-attempts'). MUST be lower than the directory's own account "
        "lockout threshold, or a password spray locks the real account out in "
        "the directory before this limiter ever trips. 0 disables the limiter "
        "and sends every attempt to the directory.",
    )
    lockout_duration_secs: int = Field(
        default=DEFAULT_LOCKOUT_DURATION_SECS,
        ge=MIN_LOCKOUT_DURATION_SECS,
        le=MAX_LOCKOUT_DURATION_SECS,
        description="How long a refused client stays refused. This is NOT the "
        "window that failures are counted in, which is set independently. There "
        "is deliberately no 'until an administrator clears it' value: the "
        "counter is held in memory on the gateway, so an indefinite lockout "
        "would be a self-inflicted denial of service with no on-box way to "
        "undo it.",
    )
    eap_cert_fingerprint: str | None = Field(
        default=None,
        description="SHA-256 fingerprint of the certificate the broker presents "
        "inside the EAP-TTLS tunnel. This is the AAA/EAP server identity, "
        "separate from the IKE gateway certificate: clients must be provisioned "
        "to expect it (strongSwan 'aaa_id', Windows 'ServerNames'), which the "
        "exported client profile does. Must have a private key on this "
        "appliance and an extendedKeyUsage of serverAuth.",
    )
    eap_cert_reuse_ike: bool = Field(
        default=False,
        description="Compatibility fallback: present the remote-access "
        "connection's own IKE certificate inside the tunnel instead of a "
        "dedicated EAP certificate. This lets clients that cannot be given an "
        "AAA identity connect without a profile change, at the cost of placing "
        "a copy of the gateway's IKE private key in the broker -- so a "
        "compromise of the broker becomes gateway impersonation. Off by "
        "default; only set it deliberately.",
    )

    @field_validator("eap_cert_fingerprint", mode="after")
    @classmethod
    def validate_eap_cert_fingerprint(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        text = value.strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", text):
            raise ValueError(
                "eap_cert_fingerprint must be a SHA-256 fingerprint "
                "(64 hex characters)"
            )
        return text

    @field_validator("base_dn", mode="after")
    @classmethod
    def validate_base_dn(cls, value: str) -> str:
        return _validate_dn(value, "base_dn")

    @field_validator("bind_dn", "group_base_dn", mode="after")
    @classmethod
    def validate_optional_dn(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return _validate_dn(value, "DN")

    @field_validator("username_attribute", "member_attribute", mode="after")
    @classmethod
    def validate_attribute_name(cls, value: str) -> str:
        return _validate_attribute(value, "attribute")

    @field_validator("user_filter", "group_filter", mode="after")
    @classmethod
    def validate_optional_filter(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return _validate_filter(value, "filter")

    @field_validator("allowed_groups", mode="after")
    @classmethod
    def validate_allowed_groups(cls, value: list[str]) -> list[str]:
        groups = []
        for entry in value:
            text = entry.strip()
            if not text:
                continue
            if len(text) > 512:
                raise ValueError("allowed_groups entries must be at most 512 chars")
            _reject_ldap_control_chars(text, "allowed_groups")
            groups.append(text)
        if len(groups) > MAX_ALLOWED_GROUPS:
            # Each one is a comparison the broker does per authentication, and
            # they are rendered into unlang, so the list is bounded.
            raise ValueError(
                f"at most {MAX_ALLOWED_GROUPS} allowed_groups may be configured"
            )
        return groups

    @field_validator("ca_cert_pem", mode="after")
    @classmethod
    def validate_ca_cert(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        text = value.strip()
        if "-----BEGIN CERTIFICATE-----" not in text:
            raise ValueError("ca_cert_pem must be a PEM-encoded certificate")
        return text

    @model_validator(mode="after")
    def validate_combination(self) -> "LdapConfigBase":
        if self.bind_type == LdapBindTypeEnum.REGULAR and not self.bind_dn:
            raise ValueError("bind_dn is required when bind_type is 'regular'")
        # Anonymous carries no bind identity. NORMALISED here rather than
        # rejected, because this validator also runs when the stored row is
        # rehydrated at boot: an appliance configured before this rule existed
        # can hold anonymous + a leftover DN, and rejecting it here would turn a
        # working directory configuration into a boot-time failure to load. The
        # operator-facing refusal belongs on the write model, where there is
        # someone to tell -- see LdapSetConfigModel.
        if self.bind_type == LdapBindTypeEnum.ANONYMOUS:
            self.bind_dn = None
        # Unconditional: every transport is TLS, so a CA is always needed and
        # certificate validation can never be skipped.
        if not self.ca_cert_pem:
            raise ValueError(
                "ca_cert_pem is required: the directory connection is always "
                "TLS and its certificate is always verified"
            )
        # Certificate identity is matched against DNS names only -- an
        # IP-address SAN is not usable for verification. Configuring a bare
        # IP would fail at connect time with an opaque handshake error, so
        # reject it here with something actionable instead.
        for server in self.servers:
            try:
                ipaddress.ip_address(server.address)
            except ValueError:
                continue
            raise ValueError(
                f"server '{server.address}' is an IP address; TLS requires the "
                f"DNS hostname the directory certificate is issued to"
            )
        if self.group_check in (
            LdapGroupCheckEnum.GROUP_OBJECT,
            LdapGroupCheckEnum.POSIX_GROUP,
        ) and not self.group_base_dn:
            raise ValueError(
                f"group_base_dn is required when group_check is "
                f"'{self.group_check.value}'"
            )
        # The whole failover chain, not just one hop. rlm_ldap tries each server
        # in turn, so this is the longest a single authentication -- which an
        # unauthenticated peer can initiate -- can hold one of the broker's
        # workers. Bounding the product is what keeps the pool from being
        # exhausted by a handful of requests aimed at slow servers.
        total = len(self.servers) * self.timeout_secs
        if total > MAX_TOTAL_FAILOVER_SECS:
            raise ValueError(
                f"servers x timeout_secs is {total}s, more than the "
                f"{MAX_TOTAL_FAILOVER_SECS}s failover budget; reduce the timeout "
                f"or the number of servers"
            )
        if self.eap_cert_fingerprint and self.eap_cert_reuse_ike:
            raise ValueError(
                "eap_cert_fingerprint and eap_cert_reuse_ike are alternatives: "
                "set a dedicated EAP certificate, or opt in to reusing the IKE "
                "certificate, not both"
            )
        return self


class LdapConfigModel(LdapConfigBase):
    """READ model for the directory configuration. Never carries the bind
    password — it is write-only and encrypted at rest."""

    bind_password_configured: bool = Field(
        default=False,
        description="Whether a bind password is stored (the password itself is "
        "write-only and never returned by the API).",
    )


class LdapSetConfigModel(LdapConfigBase):
    """WRITE model for the directory configuration.

    Carries the write-only bind password. Omit ``bind_password`` on an update to
    keep the stored one.
    """

    servers: list[LdapServerEntryModel] = Field(
        min_length=1,
        max_length=MAX_SERVERS,
        description="Directory servers, tried in order for failover. At most "
        f"{MAX_SERVERS}.",
    )
    bind_password: str | None = Field(
        default=None,
        description="Password for bind_dn. Write-only: never returned by the "
        "API; stored encrypted at rest. Omit to keep the existing password.",
        examples=["s3cr3t"],
        min_length=1,
        max_length=PAM_CREDENTIAL_MAX,
    )

    @field_validator("bind_password", mode="after")
    @classmethod
    def validate_bind_password(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _reject_ldap_control_chars(value, "bind_password")
        _reject_over_byte_limit(value, "bind_password")
        return value

    @model_validator(mode="before")
    @classmethod
    def reject_anonymous_with_bind_credentials(cls, values):
        """Anonymous plus a bind identity is a contradiction, not a preference.

        Refused on the WRITE model only. The base model quietly normalises the
        same combination so an older stored row still loads, but silently
        dropping fields an operator just sent is how a request that says
        "anonymous" and a directory connection that authenticates end up
        disagreeing. mode="before" so it sees what was actually submitted,
        ahead of the base model's normalisation.
        """
        if not isinstance(values, dict):
            return values
        bind_type = values.get("bind_type")
        bind_type = getattr(bind_type, "value", bind_type)
        if bind_type != LdapBindTypeEnum.ANONYMOUS.value:
            return values
        for field in ("bind_dn", "bind_password"):
            if values.get(field):
                raise ValueError(
                    f"{field} must be empty when bind_type is 'anonymous'. "
                    "Clear it to bind anonymously, or set bind_type to "
                    "'regular'."
                )
        return values

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        """Advertise only the qualified group-check modes on the WRITE schema.

        The validator below refuses the others, but a validator does not change
        JSON Schema -- so the generated client and the WebUI picker would keep
        offering group_object and posix_group, and the operator would find out
        they are refused only when Save returned 422. Options you cannot choose
        do not belong in the picker.

        Done here rather than by declaring a narrower enum on the field: the
        base model types it LdapGroupCheckEnum, and a subclass that narrows a
        mutable attribute violates substitutability -- mypy rejects it, and it
        would be a real inconsistency rather than a lint complaint. Same Python
        type, pruned schema.

        The READ model is deliberately untouched and keeps the full enum: a
        stored configuration using one of these must still load and still be
        reportable.
        """
        schema = handler(core_schema)
        prop = schema.get("properties", {}).get("group_check")
        if prop is not None:
            prop.pop("allOf", None)
            prop.pop("$ref", None)
            prop["enum"] = list(QUALIFIED_GROUP_CHECKS)
            prop["type"] = "string"
            prop["description"] = (
                "How group membership is determined. Only 'user_attr' (an "
                "attribute on the user entry, e.g. memberOf -- what Active "
                "Directory populates by default) is qualified on this release."
            )
        return schema

    @model_validator(mode="after")
    def reject_unqualified_group_check(self):
        """Refuse a group-membership mode the appliance has not qualified.

        Belt and braces beside the narrowed field type above: the type keeps the
        mode out of the schema, and this keeps a direct model construction --
        the internal callers that do not go through FastAPI's parsing -- from
        bypassing it. Same WRITE-model-only placement as the validator above,
        and for the same reason: a stored configuration must still load.
        """
        if self.group_check in UNQUALIFIED_GROUP_CHECKS:
            qualified = sorted(
                c.value for c in LdapGroupCheckEnum if c not in UNQUALIFIED_GROUP_CHECKS
            )
            raise ValueError(
                f"group_check '{self.group_check.value}' is not qualified on this "
                f"release and cannot be configured. Use one of: {', '.join(qualified)}. "
                "Group membership read from an attribute on the user entry "
                "(user_attr/memberOf) is the supported mode, and is what Active "
                "Directory populates by default."
            )
        return self


class LdapTestUserModel(BaseModel):
    """Probe a single user's credentials through the live authentication path."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        description="Login name to test",
        min_length=1,
        max_length=PAM_CREDENTIAL_MAX,
        examples=["alice"],
    )
    password: str = Field(
        description="Password to test. Write-only: never stored or logged.",
        min_length=1,
        max_length=PAM_CREDENTIAL_MAX,
    )

    @field_validator("username", "password", mode="after")
    @classmethod
    def validate_credential(cls, value: str) -> str:
        _reject_ldap_control_chars(value, "credential")
        # The probe travels as a RADIUS User-Password, which is capped at 128
        # ENCODED bytes -- so the limit has to be counted in bytes, not
        # characters, or a multibyte password passes here and is mangled on the
        # wire.
        _reject_over_byte_limit(value, "credential")
        return value


class LdapTestResultModel(BaseModel):
    """Outcome of a connectivity or credential probe."""

    # Deliberately just these two. The probe goes over RADIUS, where the only
    # channel back is Reply-Message, so a resolved user DN, a group list or the
    # server that answered could not be reported without inventing a second,
    # parallel path to the directory that proves nothing about the one dial-up
    # uses. Earlier versions modelled all three and populated none of them.
    success: bool = Field(description="Whether the probe succeeded")
    detail: str = Field(
        description="Human-readable outcome, safe to show an administrator. "
        "Never contains the tested password.",
    )


class LdapStatusModel(BaseModel):
    """Broker health, surfaced in the UI.

    Deliberately has no per-server reachability list. The broker (rlm_ldap)
    performs its own failover across the configured servers and does not report
    which one answered, so a per-server field could only ever have been
    populated by a second, parallel set of connections that prove nothing about
    the path authentication actually takes. A field that looks authoritative and
    is not is worse than no field.
    """

    configured: bool = Field(description="Whether a directory config is loaded")
    broker_running: bool = Field(
        description="Whether the authentication broker is answering on the "
        "local bus (a Status-Server probe, not an authentication)"
    )
    directory_reachable: bool | None = Field(
        default=None,
        description="Result of the last directory probe: true if the broker "
        "could bind, false if it could not, null if it has not been asked "
        "since the configuration was applied.",
    )
    backend: AaaBackendEnum = Field(
        default=AaaBackendEnum.NONE,
        description="Which AAA backend currently owns charon's eap-radius "
        "server set. 'radius' means an external RADIUS server was configured "
        "and directory authentication is not in service even if a directory "
        "configuration is stored.",
    )
    active_generation: int | None = Field(
        default=None,
        description="Configuration generation the running broker is serving, "
        "or null if none has been activated.",
    )
    saved_but_inactive: bool = Field(
        default=False,
        description="True when a stored configuration could not be put into "
        "service (the broker or charon did not accept it). The saved settings "
        "are not the ones authenticating users; re-apply to retry.",
    )
    eap_credential: str | None = Field(
        default=None,
        description="SHA-256 fingerprint of the certificate the broker presents "
        "inside the EAP-TTLS tunnel, or null when the self-signed fallback is in "
        "use. Clients must be provisioned to trust this credential's identity "
        "(strongSwan 'aaa_id', Windows 'ServerNames') -- see the client profile.",
    )
    eap_credential_is_fallback: bool = Field(
        default=False,
        description="Whether the broker is presenting the generated self-signed "
        "fallback certificate. EAP-TTLS is the only outer method the broker "
        "offers and every client rejects this certificate, so no one can "
        "connect: configure a dedicated EAP server certificate and re-apply.",
    )
    dialup_ready: bool = Field(
        default=False,
        description="Whether a VPN client can actually authenticate against "
        "the directory right now. False whenever any prerequisite is missing, "
        "with the first missing one named in dialup_blocker.",
    )
    dialup_blocker: str | None = Field(
        default=None,
        description="What stops directory dial-up from working, or null when "
        "nothing does. Reported because every other field in this model can "
        "read healthy while dial-up is impossible -- most often because no EAP "
        "server certificate has been configured, which is not a failure of the "
        "apply and so has no error to surface anywhere else.",
    )
