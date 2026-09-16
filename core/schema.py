"""
Concrete Canonical Normalized Schema for Universal Log Pre-processing.
Compliant with OCSF v1.1 (Open Cybersecurity Schema Framework) and ECS (Elastic Common Schema).
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List
from enum import Enum
import uuid
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EventCategory(str, Enum):
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    SYSTEM = "system"
    SECURITY = "security"
    APPLICATION = "application"
    SENSOR = "sensor"
    UNKNOWN = "unknown"


class EventAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    LOG = "log"
    ALERT = "alert"
    MODIFY = "modify"
    UNKNOWN = "unknown"


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    ALERT = "alert"
    EMERGENCY = "emergency"


class EventStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventMetadata(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    category: EventCategory = EventCategory.UNKNOWN
    type: str = "generic"
    action: EventAction = EventAction.UNKNOWN
    severity: EventSeverity = EventSeverity.INFO
    status: EventStatus = EventStatus.UNKNOWN


class TimestampMetadata(BaseModel):
    raw: Optional[str] = None
    normalized: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    epoch_us: int = Field(default_factory=lambda: int(datetime.now(timezone.utc).timestamp() * 1_000_000))
    timezone: str = "UTC"


class GeoLocation(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class Endpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    domain: Optional[str] = None
    is_private: Optional[bool] = None
    geo: Optional[GeoLocation] = None


class NetworkDetails(BaseModel):
    protocol: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    direction: Optional[str] = None  # inbound, outbound, internal, unknown


class DeviceDetails(BaseModel):
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    ip: Optional[str] = None


class ActorDetails(BaseModel):
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    user_id: Optional[str] = None


class ProcessDetails(BaseModel):
    pid: Optional[int] = None
    name: Optional[str] = None
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None


class ConfidenceBreakdown(BaseModel):
    format_confidence: float = 0.0
    field_extraction_confidence: float = 0.0
    schema_mapping_confidence: float = 0.0
    overall_confidence: float = 0.0


class ProcessingMetadata(BaseModel):
    format_detected: str = "UNKNOWN"
    parser_used: str = "NONE"
    inference_used: bool = False
    latency_us: int = 0
    confidence: ConfidenceBreakdown = Field(default_factory=ConfidenceBreakdown)
    warnings: List[str] = Field(default_factory=list)
    error_codes: List[str] = Field(default_factory=list)


class ThreatIntel(BaseModel):
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    tactic: Optional[str] = None
    risk_score: int = 0


class CanonicalLogRecord(BaseModel):
    """
    Unified Defense Canonical Log Schema (DCLS) compatible with OCSF v1.1.
    Guarantees zero data loss via raw_log and unmapped fields.
    """
    event: EventMetadata = Field(default_factory=EventMetadata)
    timestamp: TimestampMetadata = Field(default_factory=TimestampMetadata)
    device: DeviceDetails = Field(default_factory=DeviceDetails)
    src_endpoint: Endpoint = Field(default_factory=Endpoint)
    dst_endpoint: Endpoint = Field(default_factory=Endpoint)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    actor: ActorDetails = Field(default_factory=ActorDetails)
    process: ProcessDetails = Field(default_factory=ProcessDetails)
    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    raw_log: str = ""
    unmapped: Dict[str, Any] = Field(default_factory=dict)
    processing_metadata: ProcessingMetadata = Field(default_factory=ProcessingMetadata)

    def to_ocsf_dict(self) -> Dict[str, Any]:
        """Export as standard OCSF JSON dictionary."""
        return self.model_dump()

