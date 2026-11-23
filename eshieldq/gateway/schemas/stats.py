#!/usr/bin/python3

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

API_STATS = "/stats"
API_STATS_V1 = API_STATS + "/v1"
API_STATS_V2 = API_STATS + "/v2"


class SysTimeModel(BaseModel):
    time: datetime = Field(
        description="System Time ISO formatted",
        examples=["2021-01-01T00:00:00+00:00"],
    )


class StatsStringModel(BaseModel):
    stats: str = Field(description="Statistics string")


class NameValue(BaseModel):
    name: str = Field(description="Name")
    value: int = Field(description="Value", examples=[1000])


class DpStats(SysTimeModel):
    stats: List[NameValue] = Field(description="Statistics List")


class HistoryWindow(str, Enum):
    """Selectable history look-back windows for the v2 history endpoints."""

    m1 = "1m"
    m5 = "5m"
    m10 = "10m"
    m30 = "30m"
    h1 = "1h"
    h6 = "6h"
    h12 = "12h"
    h24 = "24h"

    def to_seconds(self) -> int:
        return {
            "1m": 60,
            "5m": 300,
            "10m": 600,
            "30m": 1800,
            "1h": 3600,
            "6h": 21600,
            "12h": 43200,
            "24h": 86400,
        }[self.value]


class DpSeries(BaseModel):
    """Compact columnar history: counter names are listed once, bucket
    timestamps are a parallel int array (epoch ms), and each series' values are
    an int array aligned to those timestamps. Far smaller on the wire than a
    list of per-sample DpStats when serving long, downsampled windows."""

    resolution_s: int = Field(
        description="Seconds per bucket actually served for this window."
    )
    window_s: int = Field(description="Requested look-back window, in seconds.")
    names: List[str] = Field(description="Counter names, listed once.")
    t_ms: List[int] = Field(
        description="Bucket timestamps as epoch milliseconds, one per column."
    )
    values: List[List[Optional[int]]] = Field(
        description=(
            "One array per name, aligned to t_ms. A cell is null when that "
            "counter had no value in that bucket -- NOT zero. The sampler omits "
            "a gauge it cannot measure rather than publishing a wrong number, so "
            "zero-filling here would turn 'unknown' into a real reading: an "
            "appliance whose management-CPU split was briefly unavailable would "
            "chart as 0% busy, which is a claim, not an absence."
        )
    )


class StatusEnum(str, Enum):
    UP = "UP"
    DOWN = "DOWN"
    CONFIGURING = "CONFIGURING"
    RESTARTING = "RESTARTING"
    UNKNOWN = "UNKNOWN"


class ComponentEnum(str, Enum):
    vpp = "vpp"
    charon = "charon"
    ssh = "ssh"
    SecureKeyDataplane = "SecureKey-dataplane"
    https = "https"


class StatusModel(BaseModel):
    component: ComponentEnum = Field(description="Component Name")
    status: StatusEnum = Field(description="Status")


class FileDataModel(BaseModel):
    file_name: str = Field(description="Filename")
    data: bytes = Field(description="File Data")


class MachineIDModel(BaseModel):
    machine_id: str = Field(
        description="Machine ID for this device",
        examples=["089a2ff00dd9476ffd7ff2aaabc34ed89"],
    )


class SwVersionModel(BaseModel):
    name: str = Field(
        description="Software Application Name",
        # The first entry of the version list is the appliance itself, read from
        # /etc/sw-version; the rest are its python components. Both the example
        # and the shape of the version below are what the Swagger UI shows a
        # user, so they have to be what an appliance actually reports.
        examples=["eshieldq_gateway"],
    )
    version: str = Field(
        description="Version",
        # Major.Minor of the release plus the build number, e.g. 3.1.1782515705.
        examples=["3.1.1782515705"],
    )


class SystemVersionModel(BaseModel):
    software: List[SwVersionModel] = Field(
        description="Software Application Versions",
    )


class SystemReportModel(BaseModel):
    name: str = Field(
        description="Software Component Name",
        examples=["Secure Boot", "cpuinfo", "meminfo"],
    )
    data: str = Field(
        description="Report data",
        examples=["Enabled", "Disabled", "Not Available"],
    )
