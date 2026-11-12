from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ComplianceStatus(str, Enum):
    COMPLIANT_MITIGATED = "compliant_mitigated"
    VIOLATION_DETECTED = "violation_detected"
    REQUIRES_ESCALATION = "requires_escalation"


class DescIsrControlMapping(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    domain_number: int = Field(..., ge=1, le=13)
    domain_name: str
    control_id: str = Field(..., pattern=r"^DESC-ISR-D\d{2}\.\d+$")
    control_requirement: str
    nesa_ias_reference: str
    compliance_status: ComplianceStatus
    technical_evidence: str


class StatutoryLegalAssessment(BaseModel):
    """
    Maps technical incident indicators to UAE statutory frameworks:
    - Federal Decree-Law No. 34 of 2021 (Combating Rumors and Cybercrimes)
    - Federal Decree-Law No. 45 of 2021 (Personal Data Protection Law / PDPL)
    - Dubai Law No. 11 of 2014 (Establishing DESC)
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    statute_name: str
    applicable_articles: List[str]
    relevance_summary: str
    mandatory_notification_sla_hours: int = Field(..., ge=1, le=72)


class DescIsrComplianceReport(BaseModel):
    """
    Canonical output of Module 5 (DESC ISR v2.0 & UAE Regulatory Compliance Auditor).
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_version: str = Field(default="2.0.0", frozen=True)
    audited_at_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    host_asset_criticality: str
    overall_compliance_posture: ComplianceStatus
    desc_reporting_sla_hours: int = Field(..., ge=1, le=72)
    sovereign_air_gap_certified: bool
    tamper_evident_log_count: int = Field(..., ge=0)
    control_mappings: List[DescIsrControlMapping] = Field(..., min_length=1)
    statutory_assessments: List[StatutoryLegalAssessment] = Field(..., min_length=1)
    auditor_attestation: str
