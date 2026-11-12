from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, Optional, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

STCAI_PROCESS_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


class TelemetrySourceType(str, Enum):
    WINDOWS_SYSMON = "windows_sysmon"
    LINUX_AUDITD = "linux_auditd"


class EventCategory(str, Enum):
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACTIVITY = "file_activity"
    PRIVILEGE_CHANGE = "privilege_change"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class HostContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str = Field(..., min_length=1)
    os_family: str = Field(..., pattern="^(windows|linux)$")
    ip_address: Optional[Union[IPv4Address, IPv6Address]] = None
    asset_criticality: str = Field(
        default="standard",
        pattern="^(low|standard|high|critical_sovereign)$",
    )

    @field_validator("hostname", mode="before")
    @classmethod
    def normalize_hostname(cls, v: str) -> str:
        return v.strip().lower()


class UserIdentityContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    effective_user: str
    effective_uid: Optional[int] = None
    login_uid: Optional[str] = None
    session_id: Optional[str] = None
    privilege_level: Optional[str] = None

    @field_validator("login_uid", mode="before")
    @classmethod
    def clean_unset_linux_auid(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        val_str = str(v).strip()
        if val_str in ("4294967295", "-1", "unset"):
            return None
        return val_str


class ProcessLineageContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_uid: str
    parent_entity_uid: Optional[str] = None
    pid: int = Field(..., ge=0)
    ppid: Optional[int] = Field(default=None, ge=0)
    executable: str = Field(..., min_length=1)
    command_line: Optional[str] = None
    parent_executable: Optional[str] = None
    parent_command_line: Optional[str] = None
    working_directory: Optional[str] = None
    sha256_hash: Optional[str] = Field(default=None, pattern="^[a-fA-F0-9]{64}$")
    syscall_name: Optional[str] = None

    @field_validator("entity_uid", "parent_entity_uid", mode="before")
    @classmethod
    def strip_sysmon_braces(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return str(v).strip().strip("{}").lower()


class NetworkActivityContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: str = Field(..., pattern="^(tcp|udp|icmp|raw|unknown)$")
    source_ip: Optional[Union[IPv4Address, IPv6Address]] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_ip: Union[IPv4Address, IPv6Address]
    destination_port: int = Field(..., ge=0, le=65535)
    initiated_outbound: bool = True


class FileActivityContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target_filename: str = Field(..., min_length=1)
    operation: str = Field(..., pattern="^(create|modify|delete|open|chmod|rename)$")
    inode: Optional[int] = None
    mode_octal: Optional[str] = None


class IntegrityMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ingested_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_payload_sha256: str = Field(..., pattern="^[a-f0-9]{64}$")
    clock_drift_seconds: float = 0.0
    mitre_rule_tag: Optional[str] = None


class NormalizedTelemetryEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default="1.0.0", frozen=True)
    event_uid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_event_id: str
    source_type: TelemetrySourceType
    category: EventCategory
    outcome: EventOutcome = Field(default=EventOutcome.SUCCESS)
    timestamp_utc: datetime

    host: HostContext
    user: UserIdentityContext
    process: ProcessLineageContext
    network: Optional[NetworkActivityContext] = None
    file: Optional[FileActivityContext] = None
    integrity: IntegrityMetadata
    raw_attributes: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp_utc", mode="before")
    @classmethod
    def ensure_utc_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        if isinstance(v, str):
            cleaned = v.strip().replace(" ", "T")
            if not cleaned.endswith("Z") and "+" not in cleaned[-6:]:
                cleaned += "Z"
            dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        raise ValueError(f"Unsupported timestamp format: {v!r}")

    @model_validator(mode="after")
    def validate_category_payload_consistency(self) -> "NormalizedTelemetryEvent":
        if self.category == EventCategory.NETWORK_CONNECTION and self.network is None:
            raise ValueError("network context must be populated when category is 'network_connection'")
        if self.category == EventCategory.FILE_ACTIVITY and self.file is None:
            raise ValueError("file context must be populated when category is 'file_activity'")
        return self

    @staticmethod
    def build_synthetic_process_uid(hostname: str, pid: int, time_bucket: str = "") -> str:
        seed = f"{hostname.strip().lower()}:{pid}:{time_bucket}"
        return str(uuid.uuid5(STCAI_PROCESS_NAMESPACE, seed))

    @staticmethod
    def compute_raw_sha256(raw_record: Union[str, Dict[str, Any]]) -> str:
        if isinstance(raw_record, dict):
            serialized = json.dumps(raw_record, sort_keys=True, separators=(",", ":"))
        else:
            serialized = str(raw_record).strip()
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
