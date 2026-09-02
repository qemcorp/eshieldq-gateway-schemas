#!/usr/bin/python3


import ipaddress
import re
from enum import Enum, IntEnum
from typing import List

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from eshieldq.gateway.schemas.inet import IPorDNSNameModel, IpSubnetModel

API_IPSEC = "/ipsec"
API_IPSEC_V1 = API_IPSEC + "/v1"

DEFAULT_DH_GROUP = 20

# Remote-access reauthentication bounds.
#
# Credentials and group membership are evaluated once, at IKE_AUTH. With
# reauth_time=0 the peer is never made to authenticate again, so disabling a
# directory user has NO effect on an established tunnel -- it keeps forwarding
# until the client disconnects, which may be never. Revocation with no bound on
# when it takes effect is not revocation.
#
# The bound is enforced rather than merely defaulted: a default can be
# configured back to 0, and "unbounded" must not be reachable on a
# remote-access connection. Site-to-site is deliberately untouched -- both ends
# are appliances under the operator's control, there is no user account to
# disable, and forcing reauth there churns tunnels for no security gain.
REMOTE_ACCESS_REAUTH_DEFAULT_SECS = 8 * 60 * 60
# A ceiling as well as a floor: 0 is coerced up, but a caller must not be able
# to set a nominally-bounded 30 days and call it revocation.
REMOTE_ACCESS_REAUTH_MAX_SECS = 24 * 60 * 60


def _reject_config_injection(value: str, field: str) -> None:
    """Guard values that are rendered verbatim into charon's plugin config
    files (e.g. eap-radius.conf) against config injection.

    strongSwan settings are line-oriented (``key = value`` to end-of-line),
    ``#`` starts a comment, and ``{``/``}`` open/close sections. A value
    containing any of those — or a newline — could inject arbitrary directives.
    Reject control characters (incl. CR/LF/TAB), DEL, and the structural
    characters ``{ } #``.
    """
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError(f"{field} must not contain control characters")
    if any(c in "{}#" for c in value):
        raise ValueError(f"{field} must not contain any of: {{ }} #")


class ProposalEncryptionEnum(str, Enum):
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"
    AES128GCM = "AES128GCM"
    AES192GCM = "AES192GCM"
    AES256GCM = "AES256GCM"


class ProposalAuthenticationEnum(str, Enum):
    NONE = "NONE"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"


class DhGroupEnum(IntEnum):
    MODP_2048 = 14
    MODP_3072 = 15
    MODP_4096 = 16
    ECP_256 = 19
    ECP_384 = 20
    ECP_521 = 21
    CURVE25519 = 31


class AdditionalKemGroupEnum(str, Enum):
    MLKEM768 = "MLKEM768"
    MLKEM1024 = "MLKEM1024"


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def _is_aead_encryption(value: str) -> bool:
    return value.endswith("GCM")


def normalize_authentication(value: str | ProposalAuthenticationEnum | None) -> str:
    if value is None:
        return ProposalAuthenticationEnum.NONE.value
    if isinstance(value, ProposalAuthenticationEnum):
        return value.value

    aliases = {
        "": ProposalAuthenticationEnum.NONE.value,
        "none": ProposalAuthenticationEnum.NONE.value,
        "sha256": ProposalAuthenticationEnum.SHA256.value,
        "sha384": ProposalAuthenticationEnum.SHA384.value,
        "sha512": ProposalAuthenticationEnum.SHA512.value,
        "authhmacsha2256128": ProposalAuthenticationEnum.SHA256.value,
        "authhmacsha2384192": ProposalAuthenticationEnum.SHA384.value,
        "authhmacsha2512256": ProposalAuthenticationEnum.SHA512.value,
    }
    compact = _compact(str(value))
    if compact in aliases:
        return aliases[compact]
    raise ValueError(f"Unsupported authentication algorithm: {value}")


def normalize_encryption(value: str | ProposalEncryptionEnum) -> str:
    if isinstance(value, ProposalEncryptionEnum):
        return value.value

    aliases = {
        "aes128": ProposalEncryptionEnum.AES128.value,
        "aes192": ProposalEncryptionEnum.AES192.value,
        "aes256": ProposalEncryptionEnum.AES256.value,
        "aes128gcm": ProposalEncryptionEnum.AES128GCM.value,
        "aes192gcm": ProposalEncryptionEnum.AES192GCM.value,
        "aes256gcm": ProposalEncryptionEnum.AES256GCM.value,
    }
    compact = _compact(str(value))
    if compact in aliases:
        return aliases[compact]
    raise ValueError(f"Unsupported encryption algorithm: {value}")


def normalize_dh_group(value: int | str | DhGroupEnum) -> int:
    if isinstance(value, DhGroupEnum):
        return int(value)
    if isinstance(value, int):
        if value in [int(group) for group in DhGroupEnum]:
            return value
        raise ValueError(f"Unsupported DH/PFS group: {value}")

    aliases = {
        "14": int(DhGroupEnum.MODP_2048),
        "modp2048": int(DhGroupEnum.MODP_2048),
        "15": int(DhGroupEnum.MODP_3072),
        "modp3072": int(DhGroupEnum.MODP_3072),
        "16": int(DhGroupEnum.MODP_4096),
        "modp4096": int(DhGroupEnum.MODP_4096),
        "19": int(DhGroupEnum.ECP_256),
        "ecp256": int(DhGroupEnum.ECP_256),
        "20": int(DhGroupEnum.ECP_384),
        "ecp384": int(DhGroupEnum.ECP_384),
        "21": int(DhGroupEnum.ECP_521),
        "ecp521": int(DhGroupEnum.ECP_521),
        "31": int(DhGroupEnum.CURVE25519),
        "curve25519": int(DhGroupEnum.CURVE25519),
        "x25519": int(DhGroupEnum.CURVE25519),
    }
    compact = _compact(str(value))
    if compact in aliases:
        return aliases[compact]
    raise ValueError(f"Unsupported DH/PFS group: {value}")


def normalize_kem_group(value: str | AdditionalKemGroupEnum) -> str:
    if isinstance(value, AdditionalKemGroupEnum):
        return value.value

    aliases = {
        "mlkem768": AdditionalKemGroupEnum.MLKEM768.value,
        "mlkem786": AdditionalKemGroupEnum.MLKEM768.value,
        "mlkem1024": AdditionalKemGroupEnum.MLKEM1024.value,
    }
    compact = _compact(str(value))
    if compact in aliases:
        return aliases[compact]
    raise ValueError(f"Unsupported KEM group: {value}")


def normalize_prf(value: str) -> str:
    aliases = {
        "prfhmacsha2256": "PRF_HMAC_SHA2_256",
        "sha2256": "PRF_HMAC_SHA2_256",
        "prfsha256": "PRF_HMAC_SHA2_256",
        "prfhmacsha2384": "PRF_HMAC_SHA2_384",
        "sha2384": "PRF_HMAC_SHA2_384",
        "prfsha384": "PRF_HMAC_SHA2_384",
        "prfhmacsha2512": "PRF_HMAC_SHA2_512",
        "sha2512": "PRF_HMAC_SHA2_512",
        "prfsha512": "PRF_HMAC_SHA2_512",
    }
    compact = _compact(str(value))
    if compact in aliases:
        return aliases[compact]
    raise ValueError(f"Unsupported PRF algorithm: {value}")


def build_legacy_proposal(
    encr_alg: str | None,
    encr_keysize: int | None,
) -> dict[str, str]:
    size = int(encr_keysize or 256)
    compact = _compact(encr_alg or "AES_GCM_16")

    if size not in [128, 192, 256]:
        raise ValueError(f"Unsupported encryption key size: {size}")

    if "gcm" in compact:
        return {
            "encryption": f"AES{size}GCM",
            "authentication": ProposalAuthenticationEnum.NONE.value,
        }

    return {
        "encryption": f"AES{size}",
        "authentication": ProposalAuthenticationEnum.SHA384.value,
    }


def dedupe_preserve_order(values: list):
    seen = set()
    ordered = []
    for value in values:
        key = value if not isinstance(value, dict) else tuple(sorted(value.items()))
        if key in seen:
            raise ValueError("Duplicate values are not allowed")
        seen.add(key)
        ordered.append(value)
    return ordered


def normalize_legacy_group_list_or_default(
    raw_value,
    default_value,
):
    if raw_value in [None, "", []]:
        return [normalize_dh_group(default_value)]
    return [normalize_dh_group(raw_value)]


def normalize_legacy_kem_groups(raw_value):
    if raw_value in [None, "", []]:
        return []
    return raw_value


class NameModel(BaseModel):
    name: str = Field(
        description="Name Field ",
        examples=["string_name-123"],
        pattern="^[-_()0-9a-zA-Z]+$",
    )


class ConnectionSaModel(BaseModel):
    connection_name: NameModel
    sa_name: NameModel


class ModeEnum(str, Enum):
    transport = "transport"
    tunnel = "tunnel"


class StartActionEnum(str, Enum):
    start = "start"
    none = "none"
    trap = "trap"
    trap_start = "trap-start"


class AuthMethodEnum(str, Enum):
    """IKE authentication method for an auth round.

    Values are the strongSwan ``auth`` keywords used in the VICI/swanctl
    config. ``pubkey`` is classic X.509 mutual auth (site-to-site default);
    ``eap-tls`` drives remote-access (dial-up) clients with a client
    certificate and is IKEv2-only, reusing the existing X.509 certificate
    lifecycle. ``eap-radius`` forwards client EAP (typically username/password)
    to a configured RADIUS server (see RadiusServerModel).

    Password EAP without RADIUS (eap-mschapv2 against a local user DB) and
    negotiated EAP (eap-dynamic) are not exposed yet.
    """

    pubkey = "pubkey"
    eap_tls = "eap-tls"
    eap_radius = "eap-radius"
    eap_mschapv2 = "eap-mschapv2"
    # NOTE: there is deliberately no eap-gtc. Directory (LDAP/AD) authentication
    # is selected with eap-radius: charon relays the EAP method the on-box broker
    # chooses (EAP-TTLS, with inner PAP for Windows or inner GTC for strongSwan),
    # so the gateway needs no per-method setting. An eap-gtc value here would be worse
    # than redundant -- it would make charon terminate GTC itself against its own
    # local secrets, bypassing the broker and the directory entirely.


EAP_AUTH_METHODS = {
    AuthMethodEnum.eap_tls,
    AuthMethodEnum.eap_radius,
    AuthMethodEnum.eap_mschapv2,
}


class RadiusSourceInterfaceEnum(str, Enum):
    MGMT = "mgmt"
    WAN = "wan"


class RadiusServerEntryModel(BaseModel):
    """A single RADIUS server. READ model: never carries the shared secret.

    Multiple servers may be configured; charon's eap-radius plugin tries them
    in order for failover/redundancy (the industry norm — cf. Palo Alto RADIUS
    server profiles, Cisco AAA server groups)."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(
        description="RADIUS server IP address or hostname",
        examples=["10.0.0.53"],
    )
    auth_port: int = Field(
        description="RADIUS authentication (access) UDP port",
        ge=1,
        le=65535,
        default=1812,
    )
    acct_port: int = Field(
        description="RADIUS accounting UDP port",
        ge=1,
        le=65535,
        default=1813,
    )
    secret_configured: bool = Field(
        description="Whether a shared secret is stored for this server (the "
        "secret itself is write-only and never returned by the API)",
        default=False,
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
        # allow a DNS hostname
        if not text or len(text) > 255:
            raise ValueError(f"Invalid RADIUS server address: {value}")
        allowed = re.compile(r"(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")
        if not all(allowed.match(part) for part in text.rstrip(".").split(".")):
            raise ValueError(f"Invalid RADIUS server address: {value}")
        return text

class RadiusServerEntryConfigModel(RadiusServerEntryModel):
    """WRITE model for one RADIUS server: carries the write-only shared secret."""

    secret: str | None = Field(
        description="Shared secret between the gateway (NAS) and this RADIUS "
        "server. Write-only: never returned by the API. Omit to keep the "
        "existing secret for the server with this address.",
        examples=["s3cr3t"],
        default=None,
        min_length=1,
        max_length=128,
    )

    @field_validator("secret", mode="after")
    @classmethod
    def validate_secret(cls, value: str | None) -> str | None:
        # The secret is rendered verbatim into charon's root-only eap-radius.conf;
        # reject characters that could inject config directives.
        if value is None:
            return None
        _reject_config_injection(value, "RADIUS secret")
        return value


class RadiusServerModel(BaseModel):
    """RADIUS configuration used by the eap-radius plugin to authenticate
    remote-access clients.

    This is the READ model returned by the API: it never carries shared secrets
    (secrets are write-only and encrypted at rest — see
    RadiusServerConfigModel). strongSwan reads the server config from a charon
    plugin config file (not VICI), so the gateway renders it and reloads
    settings.
    """

    servers: list[RadiusServerEntryModel] = Field(
        default_factory=list,
        description="RADIUS servers, tried in order for failover / redundancy.",
    )
    source_interface: RadiusSourceInterfaceEnum = Field(
        description=(
            "Local appliance interface used to reach RADIUS servers. 'mgmt' "
            "uses the management namespace service path; 'wan' binds charon's "
            "RADIUS socket to the dataplane WAN IP."
        ),
        default=RadiusSourceInterfaceEnum.MGMT,
    )
    nas_identifier: str | None = Field(
        description="NAS-Identifier the gateway presents to the RADIUS server(s)",
        default=None,
    )
    accounting: bool = Field(
        description="Send RADIUS accounting (Start/Stop) for remote-access "
        "sessions to the server's accounting port, for AAA session logging.",
        default=False,
    )

    @field_validator("nas_identifier", mode="after")
    @classmethod
    def validate_nas_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        if len(text) > 253:
            raise ValueError("nas_identifier must be at most 253 characters")
        _reject_config_injection(text, "nas_identifier")
        return text


class RadiusServerConfigModel(BaseModel):
    """WRITE model for setting the RADIUS configuration. Each server carries its
    own write-only shared secret (encrypted at rest, never returned; omit a
    server's ``secret`` to keep its existing one)."""

    servers: list[RadiusServerEntryConfigModel] = Field(
        min_length=1,
        description="RADIUS servers, tried in order for failover / redundancy.",
    )
    source_interface: RadiusSourceInterfaceEnum = Field(
        description=(
            "Local appliance interface used to reach RADIUS servers. 'mgmt' "
            "uses the management namespace service path; 'wan' binds charon's "
            "RADIUS socket to the dataplane WAN IP."
        ),
        default=RadiusSourceInterfaceEnum.MGMT,
    )
    nas_identifier: str | None = Field(
        description="NAS-Identifier the gateway presents to the RADIUS server(s)",
        default=None,
    )
    accounting: bool = Field(
        description="Send RADIUS accounting (Start/Stop) for remote-access "
        "sessions to the server's accounting port, for AAA session logging.",
        default=False,
    )

    @field_validator("nas_identifier", mode="after")
    @classmethod
    def validate_nas_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        if len(text) > 253:
            raise ValueError("nas_identifier must be at most 253 characters")
        _reject_config_injection(text, "nas_identifier")
        return text


class VpnUserModel(BaseModel):
    """A local remote-access (dial-up) user for EAP-MSCHAPv2 auth without a
    RADIUS server. READ model: never carries the password."""

    username: str = Field(
        description="EAP username / identity",
        examples=["alice"],
        pattern=r"^[A-Za-z0-9._@-]{1,64}$",
    )
    framed_ip: str | None = Field(
        default=None,
        description="Optional static virtual IP always assigned to this user "
        "(a 'framed IP'). Must fall inside a virtual-IP pool referenced by the "
        "remote-access connection; the client requests it on connect. For "
        "server-enforced static IPs, use a RADIUS server returning "
        "Framed-IP-Address instead.",
        examples=["10.66.0.200"],
    )

    @field_validator("framed_ip", mode="after")
    @classmethod
    def validate_framed_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        try:
            ipaddress.ip_address(text)
        except ValueError:
            raise ValueError(f"Invalid framed IP address: {value}")
        return text


class VpnUserConfigModel(VpnUserModel):
    """WRITE model for creating/updating a local VPN user. Carries the password,
    which is encrypted at rest and NEVER returned by any API endpoint."""

    password: str = Field(
        description="User password. Write-only: never returned by the API; "
        "stored encrypted and loaded into charon as an EAP secret.",
        examples=["s3cr3t"],
        min_length=1,
    )


class EspEncapEnum(str, Enum):
    espintcp = "espintcp"
    espinudp = "espinudp"
    none = "none"


class IpsecLifetimeEnum(str, Enum):
    terminate_clear = "terminate_clear"
    terminate_hold = "terminate_hold"
    replace_val = "replace"


class IpsecTrafficDirEnum(str, Enum):
    inbound = "inbound"
    outbound = "outbound"


class IpsecSpdActionEnum(str, Enum):
    protect = "protect"
    bypass = "bypass"
    discard = "discard"


class LifetimeTimeModel(BaseModel):
    time: int = Field(
        description="""Time in seconds since the IPsec SA was added.
            For example, if this value is 180 seconds, it
            means the IPsec SA expires in 180 seconds since
            it was added.  The value 0 implies infinite.""",
        ge=0,
        le=4294967295,
        default=0,
    )


class LifetimeBytesModel(BaseModel):
    bytes: int = Field(
        description="""If the IPsec SA processes the number of bytes
            expressed in this leaf, the IPsec SA expires and
            SHOULD be rekeyed.  The value 0 implies
            infinite.""",
        ge=0,
        le=9223372036854775807,
        default=0,
    )


class LifetimePacketsModel(BaseModel):
    packets: int = Field(
        description="""If the IPsec SA processes the number of packets
            expressed in this leaf, the IPsec SA expires and
            SHOULD be rekeyed.  The value 0 implies
            infinite.""",
        ge=0,
        le=4294967295,
        default=0,
    )


class LifetimeIdleModel(BaseModel):
    idle: int = Field(
        description="""When an NSF stores an IPsec SA, it
            consumes system resources.  For an idle IPsec SA, this
            is a waste of resources.  If the IPsec SA is idle
            during this number of seconds, the IPsec SA
            SHOULD be removed.  The value 0 implies
            infinite.""",
        ge=0,
        le=4294967295,
        default=0,
    )


class SACertModel(BaseModel):
    id: str = Field(description="Identifier", examples=["CN=user.strongswan.org"])
    class_: str = Field(description="Class Name for the SA", examples=["public key"])
    groups: List[str] = Field(description="Groups", default=[""])
    cert_policy: List[str] = Field(description="Certificate Policy", default=[""])
    certs: List[str] = Field(description="Certificates List", default=[""])
    cacerts: List[str] = Field(description="CA Certificates List", default=[""])


class IpsecProposalModel(BaseModel):
    encryption: ProposalEncryptionEnum = Field(
        default=ProposalEncryptionEnum.AES256GCM,
        examples=[ProposalEncryptionEnum.AES256GCM.value],
    )
    authentication: ProposalAuthenticationEnum = Field(
        default=ProposalAuthenticationEnum.NONE,
        examples=[ProposalAuthenticationEnum.SHA384.value],
    )

    @field_validator("encryption", mode="before")
    @classmethod
    def normalize_encryption_value(cls, value):
        return normalize_encryption(value)

    @field_validator("authentication", mode="before")
    @classmethod
    def normalize_authentication_value(cls, value):
        return normalize_authentication(value)

    @model_validator(mode="after")
    def validate_combination(self):
        if _is_aead_encryption(self.encryption.value):
            if self.authentication != ProposalAuthenticationEnum.NONE:
                raise ValueError(
                    f"{self.encryption.value} must use authentication NONE"
                )
        elif self.authentication == ProposalAuthenticationEnum.NONE:
            raise ValueError(
                f"{self.encryption.value} requires an authentication algorithm"
            )
        return self


class ChildConnModel(BaseModel, extra="allow"):
    name: str = Field(description="Child SA Name", examples=["net1-net2"])
    mode: str = Field(description="IPsec mode: TUNNEL (encapsulate the whole packet; site-to-site / remote-access) or TRANSPORT (protect payload only; host-to-host).", examples=["TUNNEL"])
    rekey_time: int = Field(description="Re-Key Seconds")
    rekey_bytes: int = Field(description="Re-Key Bytes")
    rekey_packets: int = Field(description="Re-Key Packets")
    dpd_action: str = Field(description="DPD Action")
    close_action: str = Field(description="Close Action")
    local_ts: List[IpSubnetModel] = Field(description="Local Phase 2 traffic selectors — the subnets/hosts behind this gateway reachable through the tunnel. For remote access these are the protected/split-tunnel networks pushed to the client.")
    remote_ts: List[IpSubnetModel] = Field(description="Remote Phase 2 traffic selectors — the peer-side subnets reachable through the tunnel. For a remote-access responder this is the client's dynamically assigned virtual IP.")


class ConnectionModel(BaseModel, extra="allow"):
    name: str = Field(description="IPsec Connection Name", examples=["Connection-1"])
    local_addrs: List[IPorDNSNameModel] = Field(description="Local Addressess")
    remote_addrs: List[IPorDNSNameModel] = Field(description="Remote Addressess")
    version: str = Field(description="IKEv1/2 Version")
    mobike: bool | None = Field(
        description=(
            "MOBIKE status as reported by strongSwan runtime state. "
            "This is null when the loaded-connection view does not expose it."
        ),
        default=None,
    )
    reauth_time: int = Field(description="Re-Authentication Time in Seconds", default=0)
    rekey_time: int = Field(description="Re-Key Time in Seconds")
    unique: str = Field(description="Unique name for this Connection")
    ppk_id: str | None = Field(
        description="Postquantum Preshared Key Identifier (PPK)", default=None
    )
    ppk_required: str | None = Field(description="Is PPK required", default=None)
    local_1: List[SACertModel] = Field(description="List of Local SAs")
    remote_1: List[SACertModel] = Field(description="List of Remote SAs")
    children: List[ChildConnModel] = Field(description="List of Children SAs")


class ChildConnCreateModel(NameModel):
    esp_proposals: List[IpsecProposalModel] = Field(
        description="Ordered ESP (Phase 2) cipher proposals protecting tunneled traffic (e.g. AES-GCM), most-preferred first. The first mutually supported proposal is used for the IPsec SA.",
        default_factory=lambda: [
            IpsecProposalModel(encryption=ProposalEncryptionEnum.AES256GCM)
        ],
        json_schema_extra={"key": "esp-proposals"},
    )
    pfs_groups: List[DhGroupEnum] = Field(
        description="Diffie-Hellman groups for Perfect Forward Secrecy on this Phase 2 SA. When set, a fresh key exchange runs at each rekey so past traffic stays protected if the IKE key is later compromised.",
        default_factory=lambda: [DhGroupEnum.ECP_384],
        json_schema_extra={"key": "pfs-groups"},
    )
    kem_groups: List[AdditionalKemGroupEnum] = Field(
        description="Additional post-quantum key-exchange methods (RFC 9370, e.g. ML-KEM) for the Phase 2 SA, layered with the PFS group for hybrid quantum-resistant rekeying.",
        default_factory=list,
        max_length=7,
    )
    mode: str = Field(
        description="IPsec mode: TUNNEL (encapsulate the whole packet; site-to-site / remote-access) or TRANSPORT (protect payload only; host-to-host).", examples=["TUNNEL"], default="TUNNEL"
    )
    protocol: str = Field(description="Protocol Name", examples=["ESP"], default="ESP")
    rekey_time: int = Field(
        description="Time before this Phase 2 (CHILD_SA) is re-keyed, in seconds.",
        examples=[6000],
        default=3600,
        json_schema_extra={"key": "rekey-time"},
    )
    life_time: int = Field(
        description="Hard lifetime after which this Phase 2 SA is closed if not already re-keyed, in seconds.",
        examples=[6000],
        default=6000,
        json_schema_extra={"key": " life-time"},
    )
    esn: bool = Field(description="Enable Extended (64-bit) Sequence Numbers for the IPsec SA, supporting higher packet volumes before rekeying.", default=False)
    start_action: StartActionEnum = Field(
        description="Start Action",
        default=StartActionEnum.none,
        json_schema_extra={"key": "start-action"},
    )
    local_ts: List[IpSubnetModel] = Field(
        description="Local Phase 2 traffic selectors — the subnets/hosts behind this gateway reachable through the tunnel. For remote access these are the protected/split-tunnel networks pushed to the client.", json_schema_extra={"key": " local-ts"}
    )
    remote_ts: List[IpSubnetModel] = Field(
        description="Remote Phase 2 traffic selectors — the peer-side subnets reachable through the tunnel. For a remote-access responder this is the client's dynamically assigned virtual IP.", json_schema_extra={"key": " remote-ts"}
    )

    @model_validator(mode="before")
    @classmethod
    def translate_legacy_fields(cls, data):
        if not isinstance(data, dict):
            return data

        translated = dict(data)
        if not translated.get("esp_proposals"):
            translated["esp_proposals"] = [
                build_legacy_proposal(
                    translated.pop("encr_alg", None),
                    translated.pop("encr_keysize", None),
                )
            ]
        else:
            translated.pop("encr_alg", None)
            translated.pop("encr_keysize", None)

        if not translated.get("pfs_groups"):
            translated["pfs_groups"] = normalize_legacy_group_list_or_default(
                translated.pop("dh_group", DEFAULT_DH_GROUP),
                DEFAULT_DH_GROUP,
            )
        else:
            translated.pop("dh_group", None)

        translated["kem_groups"] = normalize_legacy_kem_groups(
            translated.get("kem_groups")
        )

        return translated

    @field_validator("pfs_groups", mode="before")
    @classmethod
    def normalize_pfs_groups(cls, value):
        values = value if isinstance(value, list) else [value]
        return dedupe_preserve_order([normalize_dh_group(item) for item in values])

    @field_validator("kem_groups", mode="before")
    @classmethod
    def normalize_child_kem_groups(cls, value):
        values = [] if value is None else (value if isinstance(value, list) else [value])
        return dedupe_preserve_order([normalize_kem_group(item) for item in values])

    @model_validator(mode="after")
    def validate_lists(self):
        if len(self.esp_proposals) == 0:
            raise ValueError("At least one ESP proposal is required")
        if len(self.pfs_groups) == 0:
            raise ValueError("At least one PFS group is required")
        if len(self.kem_groups) > 7:
            raise ValueError("No more than 7 additional KEM groups are allowed")
        return self


class ChildSAModel(ChildConnCreateModel, extra="allow"):
    uniqueid: str = Field(description="Unique ID for this SA")
    reqid: str = Field(description="Req ID for this SA")
    state: str = Field(description="State of this SA", examples=["ESTABLISHED"])
    spi_in: str = Field(
        description="Input SPI Value hex string",
        examples=["17c06cc2fc722e8a"],
        json_schema_extra={"key": " spi-in"},
    )
    spi_out: str = Field(
        description="Output SPI Value hex string",
        examples=["17c06cc2fc722e8a"],
        json_schema_extra={"key": " spi-out"},
    )
    bytes_in: int = Field(
        description="Bytes Input",
        examples=[1000],
        json_schema_extra={"key": " bytes-in"},
    )
    packets_in: int = Field(
        description="Packets Input",
        examples=[1000],
        json_schema_extra={"key": " packets-in"},
    )
    bytes_out: int = Field(
        description="Bytes Output",
        examples=[1000],
        json_schema_extra={"key": " bytes-out"},
    )
    packets_out: int = Field(
        description="Packets Output",
        examples=[1000],
        json_schema_extra={"key": " packets-out"},
    )
    install_time: int = Field(
        description="Install Time Seconds",
        examples=[6000],
        json_schema_extra={"key": " install-time"},
    )
    encap: bool = Field(
        description="True if UDP Encapslation (NAT Traversal) is enabled", default=False
    )


class BaseIKEConnModel(BaseModel):
    ike_proposals: List[IpsecProposalModel] = Field(
        description="Ordered IKE (Phase 1) cipher proposals — encryption + integrity/PRF offered to the peer, most-preferred first. The first proposal both sides support is used to protect the IKE SA.",
        default_factory=lambda: [
            IpsecProposalModel(encryption=ProposalEncryptionEnum.AES256GCM)
        ],
        json_schema_extra={"key": "ike-proposals"},
    )
    ike_dh_groups: List[DhGroupEnum] = Field(
        description="Ordered Diffie-Hellman / key-exchange groups for the IKE (Phase 1) SA, most-preferred first (e.g. ECP_384, MODP_4096). Sets the strength of the key exchange protecting the IKE control channel.",
        default_factory=lambda: [DhGroupEnum.ECP_384],
        json_schema_extra={"key": "ike-dh-groups"},
    )
    ike_kem_groups: List[AdditionalKemGroupEnum] = Field(
        description="Additional post-quantum key-exchange methods layered onto the IKE SA per RFC 9370 (e.g. ML-KEM-768/1024), combined with the classical DH group for hybrid quantum-resistant key exchange. Up to 7 may be listed; IKEv2 only.",
        default_factory=list,
        max_length=7,
        json_schema_extra={"key": "ike-kem-groups"},
    )
    version: int = Field(
        description="IKE protocol version: 2 (recommended) or 1. IKEv2 is required for EAP/remote-access auth and post-quantum (RFC 9370) key exchange.", examples=[1, 2], default=2
    )
    local_host: IPorDNSNameModel = Field(
        description="Local gateway address this end binds to — an IP, FQDN, or %any to accept on any local address.", json_schema_extra={"key": " local-host"}
    )
    local_port: int = Field(
        description="Local UDP port for IKE: 500 for native IKE, 4500 when NAT traversal (UDP encapsulation) is in use.",
        ge=0,
        le=65535,
        examples=[4500],
        default=4500,
        json_schema_extra={"key": " local-port"},
    )
    local_id: str = Field(
        description="Local IKE identity (IKEv2 IDi) sent to the peer — typically the subject DN of the gateway certificate, e.g. CN=gw.example.com.",
        examples=["CN=user1.strongswan.org"],
        json_schema_extra={"key": " local-id"},
    )
    local_cert_fingerprint: str | None = Field(
        description="Fingerprint selecting the local gateway certificate/key used for the local authentication round.",
        default=None,
    )
    local_cacerts: List[str] = Field(
        description="CA certificate IDs anchoring the local end's own certificate chain.",
        examples=["CN=CA1.strongswan.org"],
        json_schema_extra={"key": "local-cacert"},
        default=[],
    )
    remote_host: IPorDNSNameModel = Field(
        description="Remote peer gateway address to reach (IP or FQDN), or %any to accept connections from any address (dial-up / remote-access responders).", json_schema_extra={"key": " remote-host"}
    )
    remote_port: int = Field(
        description="Remote UDP port for IKE — typically 500, or 4500 with NAT traversal.",
        ge=0,
        le=65535,
        examples=[4500],
        default=4500,
        json_schema_extra={"key": " remote-port"},
    )
    remote_id: str = Field(
        description="Expected IKE identity of the remote peer (IKEv2 IDr), e.g. the subject DN in its certificate. Use %any to accept any identity (common for dial-up clients matched by CA).",
        examples=["CN=user2.strongswan.org"],
        json_schema_extra={"key": " remote-id"},
    )
    remote_cacerts: List[str] = Field(
        description="Trusted CA certificate IDs used to validate the remote peer's certificate; the peer's cert must chain to one of these.",
        examples=["CN=CA2.strongswan.org"],
        json_schema_extra={"key": "cacert"},
        default=[],
    )
    prf_alg: str = Field(
        description="Pseudo-Random Function used for IKE key derivation (e.g. PRF_HMAC_SHA2_384), usually matched to the IKE integrity algorithm.",
        examples=["PRF_HMAC_SHA2_384"],
        default="PRF_HMAC_SHA2_384",
        json_schema_extra={"key": " prf-alg"},
    )
    rekey_time: int = Field(
        description="Time before the IKE (Phase 1) SA is re-keyed — fresh keys on the same authenticated session — in seconds. Default 4 hours; 0 disables IKE rekeying.",
        examples=[6000],
        default=60 * 60 * 4,
        json_schema_extra={"key": " rekey-time"},
    )
    reauth_time: int = Field(
        description=(
            "Time before the peer must fully re-authenticate the IKE SA (re-run "
            "authentication, not just rekey), in seconds. 0 disables "
            "reauthentication. On a remote-access connection it cannot be "
            f"disabled: 0 is raised to {REMOTE_ACCESS_REAUTH_DEFAULT_SECS}s "
            f"({REMOTE_ACCESS_REAUTH_DEFAULT_SECS // 3600}h) and values above "
            f"{REMOTE_ACCESS_REAUTH_MAX_SECS}s "
            f"({REMOTE_ACCESS_REAUTH_MAX_SECS // 3600}h) are rejected, because "
            "directory credentials and group membership are only re-checked at "
            "reauthentication -- this is the bound on how long a disabled user "
            "keeps an established tunnel."
        ),
        examples=[3600],
        default=0,
        json_schema_extra={"key": " reauth-time"},
    )
    mobike: bool = Field(
        description="Enable MOBIKE (RFC 4555) so an established IKEv2 SA survives the client's IP address changing (roaming between networks) without renegotiating.",
        default=True,
        json_schema_extra={"key": " mobike"},
    )
    fragmentation: bool = Field(
        description="Enable IKEv2 fragmentation (RFC 7383). Recommended (default on): Windows/macOS/iOS native clients require it to exchange the large EAP/certificate payloads used by remote-access auth.",
        default=True,
        json_schema_extra={"key": " fragmentation"},
    )
    dpd_delay: int = Field(
        description="Dead Peer Detection interval in seconds — how often to check that a peer is still responsive (reclaims resources from dropped dial-up clients). 0 disables DPD.",
        ge=0,
        le=3600,
        examples=[30],
        default=30,
        json_schema_extra={"key": " dpd_delay"},
    )
    ppk_id: str | None = Field(
        description="Identifier of a Post-quantum Preshared Key (PPK, RFC 8784) mixed into key derivation for quantum resistance. Optional; references a stored shared secret.",
        default=None,
        json_schema_extra={"key": " ppk_id"},
    )
    remote_access: bool = Field(
        description=(
            "Remote-access (dial-up) connection: the gateway acts as an IKEv2 responder, assigns virtual IPs from the configured pools, and pushes configuration (DNS/routes) to connecting clients. When true the gateway acts as "
            "an IKEv2 responder assigning virtual IPs from 'pools' and pushing "
            "configuration payloads (DNS/routes) to dial-up clients."
        ),
        default=False,
    )
    local_auth_method: AuthMethodEnum = Field(
        description="How this gateway proves its own identity to the peer (local IKE auth round) — typically 'pubkey' (X.509 certificate).",
        default=AuthMethodEnum.pubkey,
    )
    remote_auth_method: AuthMethodEnum = Field(
        description="Authentication required of the remote peer/client. 'pubkey' = X.509 certificate (site-to-site); 'eap-tls' = client certificate for remote-access (dial-up); 'eap-radius' = username/password forwarded to a RADIUS server; 'eap-mschapv2' = username/password against the gateway's local user database. EAP methods require IKEv2.",
        default=AuthMethodEnum.pubkey,
    )
    pools: List[str] = Field(
        description=(
            "Named virtual-IP address pools to assign to remote-access clients "
            "(gateway/responder side). Referenced by name; see PoolModel."
        ),
        default=[],
        json_schema_extra={"key": " pools"},
    )
    vips: List[str] = Field(
        description=(
            "Virtual IPs to request as an initiator/client. Use '0.0.0.0'/'::' "
            "to request any address from the responder's pool."
        ),
        default=[],
        json_schema_extra={"key": " vips"},
    )
    eap_id: str | None = Field(
        description="EAP identity to use/expect for EAP authentication rounds",
        default=None,
        json_schema_extra={"key": " eap_id"},
    )

    #: The reauth_time as SUBMITTED, when _bound_remote_access_reauth() had to
    #: change it; None when the value was already within bounds. Private so it
    #: stays out of the schema and the wire format: it describes what happened
    #: to this request, not a property of a connection.
    _reauth_requested: int | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def translate_legacy_fields(cls, data):
        if not isinstance(data, dict):
            return data

        translated = dict(data)
        if not translated.get("ike_proposals"):
            translated["ike_proposals"] = [
                build_legacy_proposal(
                    translated.pop("encr_alg", None),
                    translated.pop("encr_keysize", None),
                )
            ]
        else:
            translated.pop("encr_alg", None)
            translated.pop("encr_keysize", None)

        if not translated.get("ike_dh_groups"):
            translated["ike_dh_groups"] = normalize_legacy_group_list_or_default(
                translated.pop("dh_group", DEFAULT_DH_GROUP),
                DEFAULT_DH_GROUP,
            )
        else:
            translated.pop("dh_group", None)

        if "ike_kem_groups" not in translated:
            translated["ike_kem_groups"] = normalize_legacy_kem_groups(
                translated.pop("kem_groups", [])
            )
        else:
            translated.pop("kem_groups", None)

        return translated

    @field_validator("ike_dh_groups", mode="before")
    @classmethod
    def normalize_ike_dh_groups(cls, value):
        values = value if isinstance(value, list) else [value]
        return dedupe_preserve_order([normalize_dh_group(item) for item in values])

    @field_validator("ike_kem_groups", mode="before")
    @classmethod
    def normalize_ike_kem_groups(cls, value):
        values = [] if value is None else (value if isinstance(value, list) else [value])
        return dedupe_preserve_order([normalize_kem_group(item) for item in values])

    @field_validator("prf_alg", mode="before")
    @classmethod
    def normalize_prf_alg(cls, value):
        return normalize_prf(value)

    @model_validator(mode="after")
    def validate_lists(self):
        if len(self.ike_proposals) == 0:
            raise ValueError("At least one IKE proposal is required")
        if len(self.ike_dh_groups) == 0:
            raise ValueError("At least one IKE DH group is required")
        if len(self.ike_kem_groups) > 7:
            raise ValueError("No more than 7 additional KEM groups are allowed")
        eap_methods = {
            self.local_auth_method,
            self.remote_auth_method,
        } & EAP_AUTH_METHODS
        if eap_methods and self.version != 2:
            raise ValueError("EAP authentication methods require IKEv2 (version=2)")
        return self

    def _bound_remote_access_reauth(self) -> None:
        """Force a remote-access connection to re-authenticate on a bounded clock.

        THIS MUST NEVER RAISE. ConnCreateModel is not only the request body: it
        is also how a stored connection is rehydrated (ConnectionOrm.to_model),
        and that path swallows every exception into None -- whereupon
        ConnMgr.get_all_connections reads None as "the file is gone" and DELETES
        the database row. A validator that rejects here does not report a bad
        configuration, it destroys a deployed VPN connection on the next GET or
        restart. So the model only ever COERCES, and the API write boundary owns
        rejection (see assert_reauth_within_bounds).

        <=0 rather than ==0: a negative is not a longer bound, it is nonsense
        that would otherwise sail past both branches and be handed to charon.
        """
        if not authenticates_users(self):
            return
        requested = self.reauth_time
        if requested <= 0:
            self.reauth_time = REMOTE_ACCESS_REAUTH_DEFAULT_SECS
        elif requested > REMOTE_ACCESS_REAUTH_MAX_SECS:
            # Clamped, not rejected -- see the docstring. A legacy row above the
            # ceiling is brought inside it rather than deleted. The API refuses
            # such a value outright, so on the write path this clamp is never
            # what the caller ends up with; it only ever lands on stored data.
            self.reauth_time = REMOTE_ACCESS_REAUTH_MAX_SECS
        else:
            return
        # What was ASKED FOR, kept because validation has already overwritten
        # the field: the router cannot otherwise tell a submitted 30 days from a
        # submitted 24h, nor a submitted 0 from an explicit 8h.
        self._reauth_requested = requested


class ConnCreateModel(BaseIKEConnModel, NameModel):
    child_sas: List[ChildConnCreateModel] = Field(
        description="Child SAs", json_schema_extra={"key": " child-sas"}
    )

    # NOTE: the reauth bound is deliberately NOT a validator on this model.
    #
    # This class is shared by the shipped Python client, so a validator here
    # runs in the CALLER's process: it would clamp the value before it was ever
    # serialised, `_reauth_requested` is private and omitted by
    # model_dump_json(), and the server would then receive an
    # already-in-range number. The request would be accepted with no rejection
    # and no audit event -- our own client silently defeating the control.
    #
    # So the two halves are applied where each is correct, both server-side:
    #   * rehydration clamps  (ConnectionOrm.to_model) -- must never raise,
    #     because to_model swallows exceptions to None and the caller then
    #     DELETES the row;
    #   * the write path rejects and audits (routers/ipsec.py), on the value as
    #     submitted.
    pass


def authenticates_users(conn: "BaseIKEConnModel") -> bool:
    """Does this connection authenticate END USERS, whatever its flags claim?

    The reauth bound exists because a user can be disabled and their tunnel must
    then go away within a stated window. So the question is not "did the caller
    tick remote_access", it is "does a person's credential decide whether this
    connection stays up".

    ``remote_access`` alone is NOT a safe test, and this is not theoretical:
    SswanCtrl builds ``remote_1`` from ``remote_auth_method`` and sets ``pools``
    from ``conn.pools`` REGARDLESS of the flag -- it only switches the child's
    ``remote_ts`` to ``dynamic``. A connection with ``remote_access=false``,
    ``remote_auth_method=eap-radius``, ``%any`` and a pool is therefore a fully
    working dial-up responder, and a security control keyed on a
    caller-controlled boolean is one the caller can switch off.

    But EAP or a pool ON ITS OWN is too broad in the other direction. A
    site-to-site tunnel may legitimately authenticate a PEER GATEWAY with
    EAP-TLS, and a responder pool may hand a virtual IP to an appliance
    initiator. Bounding those churns a machine-to-machine tunnel for a
    revocation story that does not apply to it -- and would contradict the
    promise, made in this file and in the release notes, that site-to-site is
    left alone.

    The discriminator is TOPOLOGY plus authentication. A dial-up responder
    accepts connections from ANY address, because that is what dial-up means; a
    site-to-site names its peer. So: an explicit remote_access, or a
    ``%any`` responder that either authenticates with EAP or assigns pool
    addresses.
    """
    if conn.remote_access:
        return True
    host = str(getattr(conn.remote_host, "host", conn.remote_host) or "")
    if host.strip().lower() not in ("%any", "0.0.0.0", "::"):
        # A named peer. Whatever it authenticates with, it is one gateway
        # talking to another specific gateway.
        return False
    return conn.remote_auth_method in EAP_AUTH_METHODS or bool(conn.pools)


def clamp_remote_access_reauth(conn: "ConnCreateModel") -> "ConnCreateModel":
    """Bring a STORED connection inside the bound. Rehydration only.

    Never raises, and that is the whole contract: ConnectionOrm.to_model()
    swallows every exception into None and ConnMgr.get_all_connections() then
    deletes the row as missing, so a rejection here would destroy a deployed VPN
    connection whose only fault is a value an older release accepted.

    Applied at rehydration rather than as a model validator because this class
    is shared with the API client: clamping in the caller's process would strip
    the evidence the server needs to reject and audit the write.
    """
    conn._bound_remote_access_reauth()
    return conn


def assert_reauth_within_bounds(conn: "ConnCreateModel") -> None:
    """Refuse an out-of-bounds reauth_time. API WRITE PATH ONLY.

    Deliberately a function the router calls rather than a validator on the
    model. ConnCreateModel is also the rehydration model, and that path turns
    any exception into a DELETED database row (ConnectionOrm.to_model swallows
    it to None; ConnMgr.get_all_connections then removes the entry as missing).
    Raising inside the model would therefore delete a deployed connection whose
    only sin is a value an older release accepted -- destroying configuration to
    enforce a bound is worse than the unbounded value ever was.

    Raises ValueError; the router maps it to 4xx.
    """
    if not authenticates_users(conn):
        return
    # The value AS SUBMITTED. Nothing has clamped it: the model deliberately
    # does not, so that what the server judges is what the operator sent rather
    # than what the client library decided on their behalf.
    if conn.reauth_time < 0:
        raise ValueError("reauth_time must not be negative")
    if conn.reauth_time > REMOTE_ACCESS_REAUTH_MAX_SECS:
        raise ValueError(
            f"reauth_time must be at most {REMOTE_ACCESS_REAUTH_MAX_SECS}s "
            f"({REMOTE_ACCESS_REAUTH_MAX_SECS // 3600}h) on a remote-access "
            "connection: it bounds how long a disabled directory user keeps an "
            "established tunnel, and credentials are only re-checked at "
            "reauthentication"
        )


def apply_remote_access_reauth_default(conn: "ConnCreateModel") -> int | None:
    """Raise a remote-access reauth_time of 0 to the bounded default.

    API WRITE PATH ONLY, and server-side: the caller asked for unbounded and is
    getting a bound instead, which is an override of an explicit security
    setting and therefore has to be auditable. Returns the value the operator
    submitted when it was overridden, or None when nothing changed -- so the
    router can audit the override without inventing a line for an operator who
    chose the default themselves.

    Call AFTER assert_reauth_within_bounds: this only handles 0, and a negative
    must be refused rather than quietly turned into 8 hours.
    """
    if not authenticates_users(conn) or conn.reauth_time != 0:
        return None
    conn.reauth_time = REMOTE_ACCESS_REAUTH_DEFAULT_SECS
    return 0


class ClientProfileModel(BaseModel):
    """An importable dial-up client VPN profile derived from a remote-access
    connection (strongSwan .sswan-style), for provisioning end-user clients."""

    name: str = Field(description="Profile / connection name")
    server: str = Field(
        description="Gateway address the client connects to (from local_host)",
        examples=["vpn.example.com"],
    )
    server_id: str = Field(
        description="Expected gateway IKE identity the client validates",
        examples=["CN=vpn.example.com"],
        default="",
    )
    vpn_type: str = Field(
        description="Client VPN type: ikev2-eap-tls (client cert), ikev2-eap "
        "(username/password), or ikev2-cert (mutual cert).",
        examples=["ikev2-eap"],
    )
    username: str | None = Field(
        description="EAP identity hint for username/password (EAP) profiles",
        default=None,
    )
    remote_ts: List[str] = Field(
        description="Split-tunnel networks reachable through the tunnel "
        "(the gateway-side subnets pushed to the client)",
        default=[],
    )

    # --- EAP server validation -------------------------------------------
    #
    # Present when directory authentication is in service. Without these a
    # client cannot validate the AAA server it is about to send a directory
    # password to: strongSwan falls back to checking the inner certificate
    # against the IKE gateway identity (which is NOT what the broker presents,
    # unless the IKE credential is deliberately reused) and Windows prompts the
    # user to accept whatever it is offered. Either way the outcome an operator
    # reaches by hand is "turn validation off", which hands the user's corporate
    # password to any rogue EAP server.
    eap_method: str | None = Field(
        default=None,
        description="Outer EAP method the client should use: 'ttls' (tunnelled, "
        "required for Windows) or 'gtc' (bare, strongSwan only).",
        examples=["ttls"],
    )
    eap_inner_method: str | None = Field(
        default=None,
        description="Inner method inside the TTLS tunnel: 'pap' for Windows "
        "(its TTLS cannot do inner EAP-GTC) or 'gtc' for strongSwan (its TTLS "
        "defines only the EAP-Message AVP and so cannot do inner PAP).",
        examples=["pap"],
    )
    aaa_id: str | None = Field(
        default=None,
        description="Identity of the EAP/AAA server the client must validate "
        "the tunnelled certificate against -- strongSwan 'aaa_id', Windows "
        "'ServerNames'. Distinct from server_id, which is the IKE gateway.",
        examples=["CN=aaa.example.com"],
    )
    eap_server_cert_pem: str | None = Field(
        default=None,
        description="The certificate the broker presents inside the EAP tunnel, "
        "so a client can be provisioned to trust exactly it.",
    )
    eap_server_cert_sha256: str | None = Field(
        default=None,
        description="SHA-256 fingerprint of eap_server_cert_pem. Identifies the "
        "leaf; it is NOT what Windows pins against (see eap_server_ca_sha1).",
    )
    eap_server_ca_pem: str | None = Field(
        default=None,
        description="The root CA that anchors eap_server_cert_pem, so a client "
        "can be provisioned to trust exactly that issuer.",
    )
    eap_server_ca_sha1: str | None = Field(
        default=None,
        description="SHA-1 thumbprint of eap_server_ca_pem, uppercase unspaced "
        "hex. This is what Windows compares in TrustedRootCAHashes; the field "
        "means a ROOT CA SHA-1, so the leaf's SHA-256 can never match it.",
    )
    require_server_validation: bool = Field(
        default=True,
        description="Whether the generated profile forbids the user from "
        "accepting an unvalidated EAP server (Windows DisablePrompt). Always "
        "true: a prompt is how a directory password reaches a rogue server.",
    )
    # --- what the gateway will actually negotiate -------------------------
    #
    # A client has to propose something the gateway accepts. strongSwan's
    # built-in default proposals already cover this gateway's, so its profile
    # needs nothing; Windows' built-in defaults do NOT, and a Windows profile
    # that omits the suite fails with 13868 ERROR_IPSEC_IKE_POLICY_MATCH before
    # authentication is even attempted. These are the connection's own values,
    # carried here in the schema's neutral spelling so the renderer can map them
    # to each client's -- never hard-coded, or an operator who changes the
    # connection's proposals gets a profile that cannot connect.
    ike_encryption: ProposalEncryptionEnum | None = Field(
        default=None,
        description="Most-preferred IKE (Phase 1) encryption algorithm the "
        "gateway offers.",
        examples=[ProposalEncryptionEnum.AES256GCM.value],
    )
    ike_prf: str | None = Field(
        default=None,
        description="IKE (Phase 1) pseudo-random function the gateway offers.",
        examples=["PRF_HMAC_SHA2_384"],
    )
    ike_dh_group: DhGroupEnum | None = Field(
        default=None,
        description="Most-preferred IKE (Phase 1) Diffie-Hellman group.",
        examples=[DhGroupEnum.ECP_384.value],
    )
    esp_encryption: ProposalEncryptionEnum | None = Field(
        default=None,
        description="Most-preferred ESP (Phase 2) encryption algorithm.",
        examples=[ProposalEncryptionEnum.AES256GCM.value],
    )
    esp_pfs_group: DhGroupEnum | None = Field(
        default=None,
        description="Most-preferred ESP (Phase 2) PFS group.",
        examples=[DhGroupEnum.ECP_384.value],
    )

    swanctl_conf: str | None = Field(
        default=None,
        description="Ready-to-use strongSwan swanctl.conf fragment.",
    )
    windows_profile_xml: str | None = Field(
        default=None,
        description=(
            "Windows EAPHost/VPNv2 profile XML for IKEv2 EAP-TTLS with inner "
            "PAP. Server validation pins the issuing root CA by SHA-1 thumbprint "
            "(TrustedRootCAHashes) and forbids the user from accepting an "
            "unvalidated server (DisablePrompt), which is what makes the "
            "cleartext inner password safe. Conforms to Microsoft's published "
            "EAP-TTLS profile schema."
        ),
    )


class PoolModel(NameModel):
    """A named virtual-IP address pool served by the strongSwan ``attr`` plugin.

    Loaded into charon via the VICI ``load-pool`` command (separate from
    connection load). ``dns`` is pushed to the client as a configuration
    payload, so a pool carries both the address range and the DNS servers.
    """

    addrs: str = Field(
        description="Address range/subnet to assign, e.g. '10.66.0.0/24' or "
        "'10.66.0.10-10.66.0.250'",
        examples=["10.66.0.0/24"],
    )
    dns: List[str] = Field(
        description="DNS servers pushed to clients via configuration payload",
        default=[],
        max_length=8,
        examples=[["10.66.0.1"]],
    )
    dns_domain: List[str] = Field(
        description="DNS search domains pushed to clients (INTERNAL_DNS_DOMAIN). "
        "Clients use these as search domains and, for split-DNS, resolve these "
        "domains via the tunnel DNS servers.",
        default=[],
        max_length=8,
        examples=[["corp.example.com"]],
    )

    @field_validator("dns_domain", mode="after")
    @classmethod
    def validate_dns_domain(cls, value: List[str]) -> List[str]:
        allowed = re.compile(r"(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")
        cleaned = []
        for entry in value:
            d = entry.strip().rstrip(".")
            if not d or len(d) > 255 or not all(
                allowed.match(part) for part in d.split(".")
            ):
                raise ValueError(f"Invalid DNS domain: {entry}")
            cleaned.append(d)
        return cleaned

    @field_validator("addrs", mode="after")
    @classmethod
    def validate_addrs(cls, value: str) -> str:
        """Accept a CIDR subnet/single IP (e.g. 10.66.0.0/24) or an inclusive
        'start-end' range whose endpoints share an address family."""
        text = value.strip()
        if "-" in text:
            start, _, end = text.partition("-")
            try:
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
            except ValueError as exc:
                raise ValueError(f"Invalid address range: {value}") from exc
            if start_ip.version != end_ip.version:
                raise ValueError("Address range endpoints must be the same family")
            if int(end_ip) < int(start_ip):
                raise ValueError("Address range end must not precede start")
            return text
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid address subnet: {value}") from exc
        return text

    @field_validator("dns", mode="after")
    @classmethod
    def validate_dns(cls, value: List[str]) -> List[str]:
        for entry in value:
            try:
                ipaddress.ip_address(entry.strip())
            except ValueError as exc:
                raise ValueError(f"Invalid DNS server address: {entry}") from exc
        return [entry.strip() for entry in value]


class SAModel(BaseIKEConnModel, extra="allow"):
    name: str = Field(description="IPsec Connection Name", examples=["Connection-1"])
    mobike: bool | None = Field(  # type: ignore[assignment]  # runtime SA view: null when unknown
        description=(
            "MOBIKE status derived from strongSwan IKE task state. "
            "This is null when the active SA view does not expose it."
        ),
        default=None,
    )
    uniqueid: str = Field(description="Unique ID for this SA")
    state: str = Field(description="State of this SA", examples=["ESTABLISHED"])
    assigned_vips: List[str] | None = Field(
        description=(
            "Virtual IPs assigned to a remote-access peer for this SA "
            "(from the connection's pool). Null when not a dial-up SA."
        ),
        default=None,
    )
    initiator: str = Field(
        description="Indicates if this is the initiator",
        examples=["yes"],
        default="no",
    )
    initiator_spi: str = Field(
        description="Initiator's SPI Value hex string",
        examples=["17c06cc2fc722e8a"],
        json_schema_extra={"key": " initiator-spi"},
    )
    responder_spi: str = Field(
        description="Responder's SPI Value hex string",
        examples=["27c06cc2fc722e8a"],
        json_schema_extra={"key": " responder-spi"},
    )
    established: int = Field(
        description="Established time in seconds", examples=[60], default=0
    )
    # These two names mean the opposite of what they mean on the connection they
    # came from, and nothing said so. On a connection, rekey_time/reauth_time are
    # the CONFIGURED intervals; charon reports the same vici keys on a live SA as
    # the time REMAINING, and the generic key mapper puts them in the same fields.
    # Redeclared here for the description alone -- type, default and vici key are
    # unchanged, so the mapping and the swanctl rendering behave exactly as before.
    rekey_time: int = Field(  # type: ignore[assignment]
        description=(
            "Seconds REMAINING before this live IKE SA rekeys -- not the "
            "configured interval that the same field name carries on a "
            "connection. 0 when IKE rekeying is disabled."
        ),
        examples=[14100],
        default=60 * 60 * 4,
        json_schema_extra={"key": " rekey-time"},
    )
    reauth_time: int = Field(  # type: ignore[assignment]
        description=(
            "Seconds REMAINING before this live IKE SA must reauthenticate -- "
            "not the configured interval. 0 when reauthentication is disabled."
        ),
        examples=[3540],
        default=0,
        json_schema_extra={"key": " reauth-time"},
    )
    child_sas: List[ChildSAModel] = Field(
        description="Child SAs", json_schema_extra={"key": " child-sas"}
    )
    nat_remote: str = Field(
        description="Network Address Translation Remote setting",
        examples=["yes", "no"],
        json_schema_extra={"key": "nat-remote"},
        default="no",
    )
    nat_any: str = Field(
        description="Network Address Translation Any setting",
        examples=["yes", "no"],
        json_schema_extra={"key": "nat-any"},
        default="no",
    )
    tasks_passive: List[str] = Field(
        description="Tasks Passive",
        examples=[["IKE_INIT", "IKE_CERT_PRE", "IKE_AUTH"]],
        json_schema_extra={"key": "tasks-passive"},
        default=[],
    )
    tasks_active: List[str] | None = Field(description="Tasks Active", default=[])

    tasks_queued: List[str] = Field(
        description="List of currently queued tasks for execution",
        examples=[["CHILD_CREATE"]],
        json_schema_extra={"key": "tasks-queued"},
        default=[],
    )

    @model_validator(mode="after")
    def set_runtime_mobike_from_tasks(self):
        task_lists = [self.tasks_active, self.tasks_passive, self.tasks_queued]
        seen_task_state = False
        mobike_enabled = False

        for task_list in task_lists:
            if not task_list:
                continue
            seen_task_state = True
            if "IKE_MOBIKE" in task_list:
                mobike_enabled = True
                break

        self.mobike = mobike_enabled if seen_task_state else None
        return self


class SaRekeyModel(BaseModel):
    """Ask charon to replace the keys on a live SA.

    Three distinct operations share one request because charon's vici ``rekey``
    command does, and the selector is what picks between them:

    * ``child_name`` set -- rekey that CHILD_SA (a CREATE_CHILD_SA exchange that
      installs a replacement and retires the old one).
    * ``child_name`` unset, ``reauth`` false -- rekey the IKE_SA (fresh keys on
      the same authenticated session).
    * ``child_name`` unset, ``reauth`` true -- REAUTHENTICATE the IKE_SA: the
      peers re-run authentication from scratch and every CHILD_SA is
      re-established under the new IKE_SA.

    Reauthentication otherwise happens on its own only when ``reauth_time``
    elapses -- typically eight hours -- so this is the way to exercise it on
    demand.
    """

    connection_name: str = Field(
        description=(
            "Name of the IKE connection whose SA to act on. Every active SA of "
            "that connection matches, so a dial-up connection with many sessions "
            "rekeys all of them; the response reports how many matched."
        ),
        examples=["Connection-1"],
        pattern="^[-_()0-9a-zA-Z]+$",
    )
    child_name: str | None = Field(
        description=(
            "Rekey this CHILD_SA of the connection instead of the IKE_SA. "
            "Omit to act on the IKE_SA."
        ),
        examples=["Connection-1-child_sa"],
        pattern="^[-_()0-9a-zA-Z]+$",
        default=None,
    )
    session_id: str | None = Field(
        description=(
            "Act on this single IKE_SA (its `uniqueid` from the SA listing) "
            "instead of every session sharing the connection name. A "
            "site-to-site connection has one session and the distinction does "
            "not arise; a remote-access connection has one per connected "
            "client, so without this a request aimed at one user's session "
            "reauthenticates all of them."
        ),
        examples=["7"],
        pattern="^[0-9]+$",
        default=None,
    )
    reauth: bool = Field(
        description=(
            "Reauthenticate the IKE_SA rather than rekey it. Only meaningful "
            "without child_name -- charon has no notion of reauthenticating a "
            "single CHILD_SA and would silently ignore the flag, so the "
            "combination is rejected instead."
        ),
        default=False,
    )

    @model_validator(mode="after")
    def reject_reauth_of_a_child(self):
        if self.reauth and self.child_name:
            raise ValueError(
                "reauth applies to the IKE_SA; omit child_name to reauthenticate"
            )
        return self


class SaRekeyResultModel(BaseModel):
    """What charon did, not merely that the request parsed.

    ``matched`` is the field that matters: charon answers a selector that names
    no live SA with success=no and zero matches rather than an error, so a
    caller (or a test) that checks only the status code cannot tell "rekeyed"
    from "there was nothing there".
    """

    matched: int = Field(
        description="Number of live SAs the selector matched and queued work for",
        examples=[1],
    )
    success: bool = Field(description="True when charon accepted the request")
    message: str | None = Field(
        description="charon's error text when success is false", default=None
    )


class SaLivenessModel(BaseModel):
    """Whether a connection is actually carrying traffic, not merely established.

    A connection can report ESTABLISHED with zero drops and still forward
    nothing, so check these counters rather than the connection state when
    traffic is missing.

    Sampled by the 1 Hz statistics thread rather than on request, so two callers
    a second apart see the same numbers and a caller cannot change the answer by
    polling faster. ``sample_age_seconds`` says how old the sample is -- if the
    statistics thread has stopped, that number grows and the rest of this record
    is stale.
    """

    name: str = Field(description="IKE connection name", examples=["Connection-1"])
    unique_id: str = Field(description="IKE_SA unique id", examples=["1"])
    state: str = Field(description="IKE_SA state", examples=["ESTABLISHED"])
    child_sa_count: int = Field(
        description=(
            "Number of CHILD_SAs on this IKE_SA. One per configured child is "
            "steady state; a second appears briefly around a rekey. A count "
            "that climbs and does not come down is the signature of "
            "superseded children that are never reaped."
        ),
        examples=[1],
    )
    child_sa_states: dict[str, int] = Field(
        description=(
            "Census of CHILD_SA states, e.g. {'INSTALLED': 1, 'DELETED': 4}. "
            "Anything other than INSTALLED persisting here is a leak."
        ),
        examples=[{"INSTALLED": 1}],
    )
    bytes_in: int = Field(description="Bytes received over this IKE_SA's children")
    bytes_out: int = Field(description="Bytes sent over this IKE_SA's children")
    packets_in: int = Field(description="Packets received over this IKE_SA's children")
    packets_out: int = Field(description="Packets sent over this IKE_SA's children")
    forwarding: bool = Field(
        description=(
            "True when the counters above advanced recently. False on an SA that "
            "is established but moving nothing -- an idle tunnel looks the same "
            "as a broken one here, which is why idle_seconds is reported too."
        )
    )
    idle_seconds: int | None = Field(
        description=(
            "Seconds since the counters last advanced. Null when they have not "
            "advanced since the SA was first sampled (a tunnel that has never "
            "carried traffic), which is a different thing from a tunnel that "
            "stopped."
        ),
        examples=[0],
    )
    sample_age_seconds: int = Field(
        description=(
            "Age of this sample. Normally 0 or 1; a large value means the "
            "statistics thread is not running and these numbers are stale."
        ),
        examples=[0],
    )
    ike_rekey_seconds: int | None = Field(
        description=(
            "Seconds until this IKE_SA is scheduled to rekey. Null when IKE "
            "rekeying is disabled. Note this is time REMAINING, unlike the "
            "identically named field on a connection, which is the configured "
            "interval."
        ),
        examples=[14100],
        default=None,
    )
    ike_reauth_seconds: int | None = Field(
        description=(
            "Seconds until this IKE_SA must reauthenticate. Null when "
            "reauthentication is disabled. Time REMAINING, as above."
        ),
        examples=[3540],
        default=None,
    )
