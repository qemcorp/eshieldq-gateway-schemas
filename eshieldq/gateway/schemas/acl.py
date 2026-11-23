#!/usr/bin/python3


import hashlib
import json
from collections.abc import Sequence
from enum import Enum
from ipaddress import IPv4Network
from typing import ClassVar

from pydantic import BaseModel, Field, ValidationInfo, model_validator

from eshieldq.gateway.schemas.inet import MacAddress
from eshieldq.gateway.schemas.intf import IfaceRoleTypes
from eshieldq.gateway.schemas.stats import SysTimeModel

API_ACL = "/acl"
API_ACL_V1 = API_ACL + "/v1"


class AclAction(Enum):
    ACL_ACTION_API_DENY = 0
    ACL_ACTION_API_PERMIT = 1
    ACL_ACTION_API_PERMIT_REFLECT = 2


class IpProtocol(Enum):
    IP_API_PROTO_HOPOPT = 0
    IP_API_PROTO_ICMP = 1
    IP_API_PROTO_IGMP = 2
    IP_API_PROTO_TCP = 6
    IP_API_PROTO_UDP = 17
    IP_API_PROTO_GRE = 47
    IP_API_PROTO_ESP = 50
    IP_API_PROTO_AH = 51
    IP_API_PROTO_ICMP6 = 58
    IP_API_PROTO_EIGRP = 88
    IP_API_PROTO_OSPF = 89
    IP_API_PROTO_SCTP = 132
    IP_API_PROTO_RESERVED = 255


# vl_api_macip_acl_rule_t struct from VPP
class MacIpAclRule(BaseModel):
    """MACIP ACL Rules are ingress only ACL which permit/deny traffic based MAC and IP address matches"""

    is_permit: AclAction = Field(description="Rule Action")
    src_mac: MacAddress = Field(
        description="Source MAC Address",
    )
    src_mac_mask: MacAddress = Field(
        description="Source MAC Address Mask",
    )
    src_prefix: IPv4Network = Field(
        description="Source Prefix",
    )
    interface_role: IfaceRoleTypes = Field(
        description="Interface to apply this rule to", default=IfaceRoleTypes.WAN
    )
    priority: int = Field(
        description="Priority in which to apply this rule (highest priority Rules are applied first)",
        ge=0,
        le=4294967295,
        default=0,
    )

    # convert the rule to a string
    def to_string(self) -> str:
        return f"{self.is_permit}-{self.src_mac}-{self.src_mac_mask}-{self.src_prefix}"

    def encode(self) -> dict:
        return {
            "is_permit": self.is_permit.value,
            "src_mac": str(self.src_mac),
            "src_mac_mask": str(self.src_mac_mask),
            "src_prefix": str(self.src_prefix),
        }

    @classmethod
    def from_vapi(cls, vapi_rule, interface_role: IfaceRoleTypes):
        return cls(
            is_permit=vapi_rule.is_permit,
            src_prefix=IPv4Network(str(vapi_rule.src_prefix)),
            src_mac=MacAddress(vapi_rule.src_mac),
            src_mac_mask=MacAddress(vapi_rule.src_mac_mask),
            interface_role=interface_role,
        )

    def __eq__(self, other):
        if not isinstance(other, MacIpAclRule):
            return False
        # don't compare priority (this is only used for sorting)
        a = self.model_dump()
        a.pop("priority", None)
        b = other.model_dump()
        b.pop("priority", None)
        return a == b


# vl_api_acl_rule_t struct from VPP
class IpAclRule(BaseModel):
    """ACL IP Rules permit traffic based on a number of Layer3/Layer4 fields"""

    is_permit: AclAction = Field(
        description="Rule Action",
    )
    src_prefix: IPv4Network = Field(
        description="Source Prefix",
    )
    dst_prefix: IPv4Network = Field(
        description="Source Prefix",
    )
    proto: int = Field(
        description=(
            "IP protocol number (0 = any). Port ranges apply to TCP and UDP; for ICMP and "
            "ICMPv6 they match type (source, 0-255) and code (destination, 0-255). "
            "Any other protocol, including 0, carries no ports: leave both ranges at 0-0 or 0-65535."
        ),
        ge=0,
        le=255,
    )
    src_port_first: int = Field(
        description="Source Port First (ICMP type first). Must not exceed Source Port Last.",
        ge=0,
        le=65535,
        default=0,
    )
    src_port_last: int = Field(
        description="Source Port Last (ICMP type last). Must be at least Source Port First.",
        ge=0,
        le=65535,
        default=0,
    )
    dst_port_first: int = Field(
        description="Destination Port First (ICMP code first). Must not exceed Destination Port Last.",
        ge=0,
        le=65535,
        default=0,
    )
    dst_port_last: int = Field(
        description="Destination Port Last (ICMP code last). Must be at least Destination Port First.",
        ge=0,
        le=65535,
        default=0,
    )
    tcp_flags_mask: int = Field(
        description="TCP flag bits to compare. Only for protocol 6 (TCP); leave 0 otherwise.",
        ge=0,
        le=255,
        default=0,
    )
    tcp_flags_value: int = Field(
        description="Required value of the compared TCP flag bits. Only for protocol 6 (TCP), and only bits set in TCP Flags Mask.",
        ge=0,
        le=255,
        default=0,
    )
    is_input: bool = Field(description="Input or Output")
    interface_role: IfaceRoleTypes = Field(
        description="Interface to apply this rule to: wan or lan. The management interface has no ACL.",
        default=IfaceRoleTypes.WAN,
    )
    priority: int = Field(
        description="Priority in which to apply this rule (highest priority Rules are applied first)",
        ge=0,
        le=4294967295,
        default=0,
    )

    #: VPP fills the two L4 match fields for TCP/UDP (ports) and ICMP/ICMPv6 (type, code) only.
    PORTED_PROTOCOLS: ClassVar[frozenset[int]] = frozenset(
        {
            IpProtocol.IP_API_PROTO_ICMP.value,
            IpProtocol.IP_API_PROTO_TCP.value,
            IpProtocol.IP_API_PROTO_UDP.value,
            IpProtocol.IP_API_PROTO_ICMP6.value,
        }
    )
    ICMP_PROTOCOLS: ClassVar[frozenset[int]] = frozenset(
        {IpProtocol.IP_API_PROTO_ICMP.value, IpProtocol.IP_API_PROTO_ICMP6.value}
    )
    #: The only interface roles with a VPP interface an ACL can be bound to.
    ACL_INTERFACE_ROLES: ClassVar[frozenset[IfaceRoleTypes]] = frozenset(
        {IfaceRoleTypes.WAN, IfaceRoleTypes.LAN}
    )
    #: Validation context that reads a rule the appliance already holds without the request check.
    STORED: ClassVar[dict] = {"acl_rule_stored": True}

    @classmethod
    def from_stored(cls, data: dict) -> "IpAclRule":
        return cls.model_validate(data, context=cls.STORED)

    @model_validator(mode="after")
    def _rule_means_what_it_says(self, info: ValidationInfo) -> "IpAclRule":
        """Refuse a rule VPP would accept and apply differently from how it reads."""
        if info.context and info.context.get("acl_rule_stored"):
            return self
        for side in ("src", "dst"):
            first = getattr(self, f"{side}_port_first")
            last = getattr(self, f"{side}_port_last")
            if first > last:
                raise ValueError(
                    f"{side}_port_first ({first}) is greater than {side}_port_last ({last}); "
                    "the range would match nothing"
                )
        if self.proto not in self.PORTED_PROTOCOLS:
            for side in ("src", "dst"):
                first = getattr(self, f"{side}_port_first")
                last = getattr(self, f"{side}_port_last")
                if first != 0 or last not in (0, 65535):
                    raise ValueError(
                        f"protocol {self.proto} carries no ports the filter can match: {side} port range "
                        f"must be 0-0 or 0-65535, not {first}-{last}"
                    )
        if self.proto in self.ICMP_PROTOCOLS:
            for side, what in (("src", "type"), ("dst", "code")):
                first = getattr(self, f"{side}_port_first")
                if first > 255:
                    raise ValueError(
                        f"ICMP {what} is 8-bit: {side} range starting at {first} could never match"
                    )
        if self.proto != IpProtocol.IP_API_PROTO_TCP.value and (
            self.tcp_flags_mask or self.tcp_flags_value
        ):
            raise ValueError(
                f"tcp_flags_mask/tcp_flags_value are only compared on TCP (protocol 6), not protocol {self.proto}"
            )
        if self.tcp_flags_value & ~self.tcp_flags_mask & 0xFF:
            raise ValueError(
                f"tcp_flags_value 0x{self.tcp_flags_value:02x} sets bits outside tcp_flags_mask "
                f"0x{self.tcp_flags_mask:02x}; the rule could never match"
            )
        if self.interface_role not in self.ACL_INTERFACE_ROLES:
            raise ValueError(
                f"interface_role {self.interface_role.value!r} has no ACL interface; use wan or lan"
            )
        return self

    def __eq__(self, other):
        if not isinstance(other, IpAclRule):
            return False
        # don't compare priority (this is only used for sorting)
        a = self.model_dump()
        a.pop("priority", None)
        b = other.model_dump()
        b.pop("priority", None)
        return a == b

    # create new instance from raw data
    @classmethod
    def from_vapi(cls, vapi_rule, is_input: bool, interface_role: IfaceRoleTypes):
        return cls.from_stored(
            dict(
                is_permit=vapi_rule.is_permit,
                src_prefix=vapi_rule.src_prefix,
                dst_prefix=vapi_rule.dst_prefix,
                proto=vapi_rule.proto,
                src_port_first=vapi_rule.srcport_or_icmptype_first,
                src_port_last=vapi_rule.srcport_or_icmptype_last,
                dst_port_first=vapi_rule.dstport_or_icmpcode_first,
                dst_port_last=vapi_rule.dstport_or_icmpcode_last,
                tcp_flags_mask=vapi_rule.tcp_flags_mask,
                tcp_flags_value=vapi_rule.tcp_flags_value,
                is_input=is_input,
                interface_role=interface_role,
            )
        )

    # convert the rule to a string
    def to_string(self) -> str:
        in_out_str = "In" if self.is_input else "Out"
        return f"{self.is_permit.value}-{in_out_str}-{self.src_port_last}-{self.src_port_first}-{self.dst_port_last}-{self.dst_port_first}-{self.proto}-{self.src_prefix}-{self.dst_prefix}-{self.tcp_flags_mask}-{self.tcp_flags_value}"

    def encode(self) -> dict:
        return {
            "is_permit": self.is_permit.value,
            "proto": self.proto,
            "srcport_or_icmptype_first": self.src_port_first,
            "srcport_or_icmptype_last": self.src_port_last,
            "src_prefix": str(self.src_prefix),
            "dstport_or_icmpcode_first": self.dst_port_first,
            "dstport_or_icmpcode_last": self.dst_port_last,
            "dst_prefix": str(self.dst_prefix),
            "tcp_flags_mask": self.tcp_flags_mask,
            "tcp_flags_value": self.tcp_flags_value,
        }


class AclStats(SysTimeModel):

    rule_description: str = Field(
        description="ACL Rule Tag Description",
    )
    packets: int = Field(
        description="Packets Filtered by ACL",
    )
    bytes: int = Field(
        description="Bytes Filtered by ACL",
    )


# ---------------------------------------------------------------------------
# Concurrency token for the whole-set writes.
#
# ORDER-SENSITIVE: equal priorities are legal and the per-list push sorts by
# priority alone (a stable sort), so the stored order decides which of two
# equal-priority rules matches first. That makes the token OPAQUE -- it hashes
# the stored rows in stored order, which is not the order GET returns, so a
# client echoes it rather than computing one.
# ---------------------------------------------------------------------------

#: 128 bits of a sha256, which is ample for an equality check on a rule set and
#: keeps the header short enough to read in a log line.
_REVISION_BITS = 32

ACL_REVISION_HEADER = "ETag"
ACL_IF_MATCH_HEADER = "If-Match"


def acl_ruleset_revision(rules: Sequence[IpAclRule | MacIpAclRule]) -> str:
    """The concurrency token of one stored rule set, in stored order."""
    canonical = json.dumps(
        [_revision_fields(rule) for rule in rules],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:_REVISION_BITS]


def _revision_fields(rule: IpAclRule | MacIpAclRule) -> dict:
    """Every field that decides what the rule DOES, priority included.

    Not the vpp encoding: that drops `interface_role`/`is_input`, which select
    the list rather than travel in it.
    """
    fields = rule.model_dump(mode="json")
    # Not policy: a set restored into fresh rows must keep its token.
    fields.pop("id", None)
    return fields


def quote_etag(revision: str) -> str:
    """An ETag field value. Strong validators are quoted (RFC 9110 8.8.3)."""
    return f'"{revision}"'


def if_match_allows(header: str | None, revision: str) -> bool:
    """Whether an `If-Match` field value admits a set at `revision`.

    Strong comparison (RFC 9110 13.1.1): `*` matches any existing state, a list
    is satisfied by any member, and a weak validator never matches -- a 412,
    not a 400. `None` is not "no match": the caller decides what an absent
    precondition means.
    """
    for candidate in split_if_match(header or ""):
        if candidate == "*" or candidate == quote_etag(revision):
            return True
    return False


def split_if_match(header: str) -> list[str]:
    """The members of an `If-Match` field value (RFC 9110 8.8.3, 13.1.1).

    Raises `ValueError` naming the fault but NOT quoting the field, because
    the caller renders that reason into an error body and an audit record.
    A malformed field is a 400 and a valid non-match a 412. Parsed as a grammar, not split on commas: a comma is
    legal inside a quoted tag. A bare unquoted token is accepted -- the quoting
    is easily lost through a shell, and refusing it would fail in the direction
    that skips the check.
    """
    members: list[str] = []
    rest = header.strip()
    if rest == "*":
        return ["*"]
    while rest:
        weak = False
        if rest.startswith("W/"):
            weak, rest = True, rest[2:]
        quoted = rest.startswith('"')
        if quoted:
            closing = rest.find('"', 1)
            if closing < 0:
                raise ValueError("an entity-tag is not closed")
            # A zero-length opaque tag is legal, and so is a quoted "*" -- which
            # is an ordinary tag, NOT the wildcard.
            tag, rest = rest[1:closing], rest[closing + 1 :]
        else:
            tag, _, rest = rest.partition(",")
            tag = tag.strip()
            rest = "," + rest if rest or _ else rest
            if not tag:
                raise ValueError("an entity-tag is malformed")
        if any(c in tag for c in ' \t"'):
            raise ValueError("an entity-tag is malformed")
        if tag == "*" and not quoted:
            # Only ever legal on its own; kept bare so the check below sees it.
            members.append("*")
        else:
            members.append(f"W/{quote_etag(tag)}" if weak else quote_etag(tag))
        rest = rest.strip()
        if not rest:
            break
        if not rest.startswith(","):
            raise ValueError("entity-tags are not comma-separated")
        rest = rest[1:].strip()
        if not rest:
            raise ValueError("the field ends in a comma")
    if not members:
        raise ValueError("If-Match is empty")
    if "*" in members:
        raise ValueError("'*' cannot be combined with entity-tags")
    return members
