#!/usr/bin/python3


from enum import Enum

from pydantic import BaseModel, Field

API_CRYPTO = "/crypto"
API_CRYPTO_V1 = API_CRYPTO + "/v1"


class CryptoExecutionModeEnum(str, Enum):
    """Choose how SecureKey uses available CPU capacity for crypto processing.

    Security mode reserves dedicated CPU cores for SecureKey crypto processing.
    Performance mode processes crypto alongside VPN traffic to maximize
    throughput. Changing the mode requires a reboot.
    """

    DEDICATED = "dedicated"
    INLINE_PG = "inline_pg"


class CryptoSettings(BaseModel):
    async_enabled: bool = Field(
        description="True if Async Crypto is enabled", default=True
    )
    secure_key_enabled: bool = Field(
        description="True if Secure Key Crypto Engine is enabled. Changing this setting requires a reboot",
        default=True,
    )
    execution_mode: CryptoExecutionModeEnum = Field(
        description=(
            "Choose how SecureKey uses available CPU capacity for crypto "
            "processing. 'Security mode — dedicated crypto cores' reserves "
            "dedicated CPU cores for SecureKey crypto processing. 'Performance "
            "mode — inline crypto' processes crypto alongside VPN traffic to "
            "maximize throughput. Changing this setting requires a reboot."
        ),
        default=CryptoExecutionModeEnum.INLINE_PG,
    )
