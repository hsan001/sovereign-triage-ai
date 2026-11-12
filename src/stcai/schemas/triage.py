from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TriageVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class MitreTechniqueMapping(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(..., pattern=r"^T\d{4}(?:\.\d{3})?$", description="MITRE ATT&CK ID e.g. T1059.001")
    tactic: str = Field(..., min_length=2)
    technique_name: str = Field(..., min_length=2)
    evidence_node_id: str = Field(..., min_length=2)


class ExtractedIOC(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ioc_type: str = Field(..., pattern="^(ip|domain|sha256|filepath|command_line|user_account)$")
    value: str = Field(..., min_length=1)
    source_node_id: str = Field(..., min_length=1)


class SovereignResidencyMetadata(BaseModel):
    """
    DESC ISR v2.0 Domain 13 (Cloud Security & Sovereign Data Residency) proof block.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    inference_endpoint: str
    air_gap_verified: bool = True
    data_residency_zone: str = Field(default="UAE-Sovereign-OnPrem")
    model_identifier: str
    adversarial_injection_detected: bool = False
    sanitized_injection_patterns: List[str] = Field(default_factory=list)


class IncidentTriageReport(BaseModel):
    """
    Canonical output of Module 3 consumed by Module 4 (pySigma) and Module 5 (DESC ISR Auditor).
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    report_version: str = Field(default="1.0.0", frozen=True)
    generated_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verdict: TriageVerdict
    severity: IncidentSeverity
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    executive_summary: str = Field(..., min_length=10)
    root_cause_node_id: str = Field(..., min_length=1)
    kill_chain_narrative: List[str] = Field(..., min_length=1)
    mitre_techniques: List[MitreTechniqueMapping] = Field(default_factory=list)
    extracted_iocs: List[ExtractedIOC] = Field(default_factory=list)
    recommended_containment_actions: List[str] = Field(..., min_length=1)
    sovereign_residency: SovereignResidencyMetadata
    desc_isr_domain6_evidence_hashes: List[str] = Field(default_factory=list)

    @field_validator("confidence_score", mode="before")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        return round(float(v), 4)
