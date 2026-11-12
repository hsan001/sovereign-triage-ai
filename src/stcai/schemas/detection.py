from __future__ import annotations

from datetime import date
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SigmaLogSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    category: str = Field(..., min_length=2, description="e.g., process_creation, network_connection, file_event")
    product: str = Field(..., pattern="^(windows|linux)$")
    service: Optional[str] = Field(default=None, description="e.g., sysmon, auditd")


class SynthesizedDetectionBundle(BaseModel):
    """
    Canonical output of Module 4 (Sigma Synthesizer & Multi-SIEM Transpiler).
    Aligned with DESC ISR v2.0 Domain 8 & Domain 4 automated defense deployment.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(..., pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    title: str = Field(..., min_length=5)
    status: str = Field(default="experimental")
    level: str = Field(..., pattern="^(informational|low|medium|high|critical)$")
    author: str = Field(default="S-TCAI Autonomous Detection Engine (DESC ISR v2.0)")
    created_date: str = Field(default_factory=lambda: date.today().isoformat())
    logsource: SigmaLogSource
    detection: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)
    falsepositives: List[str] = Field(default_factory=list)
    sigma_yaml: str = Field(..., min_length=20, description="Serialized standard Sigma YAML rule")
    splunk_spl: str = Field(..., min_length=10, description="Transpiled Splunk Search Processing Language query")
    sentinel_kql: str = Field(..., min_length=10, description="Transpiled Microsoft Sentinel Kusto Query Language query")
    source_root_node_id: str
    desc_isr_controls: List[str] = Field(default_factory=list)
