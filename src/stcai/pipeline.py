from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from stcai.compliance.desc_isr_auditor import DescIsrComplianceAuditor
from stcai.detection.sigma_synthesizer import SigmaRuleSynthesizer
from stcai.graph.provenance import ProvenanceGraphEngine
from stcai.ingest.normalizer import AuditdNormalizer, SysmonNormalizer
from stcai.schemas.compliance import DescIsrComplianceReport
from stcai.schemas.detection import SynthesizedDetectionBundle
from stcai.schemas.telemetry import NormalizedTelemetryEvent
from stcai.schemas.triage import IncidentTriageReport, TriageVerdict
from stcai.triage.engine import AirGappedTriageEngine


@dataclass(frozen=True)
class SovereignPipelineResult:
    normalized_events: List[NormalizedTelemetryEvent]
    dag_context: Dict[str, Any]
    mermaid_diagram: str
    triage_report: IncidentTriageReport
    detection_bundle: Optional[SynthesizedDetectionBundle]
    compliance_report: DescIsrComplianceReport

    def to_executive_markdown(self) -> str:
        """
        Generates a complete, recruiter- and auditor-ready Markdown Incident & Compliance Dossier.
        """
        lines = [
            "# S-TCAI Sovereign Incident Triage & DESC ISR v2.0 Compliance Dossier",
            "",
            f"- **Verdict:** `{self.triage_report.verdict.value.upper()}`",
            f"- **Severity:** `{self.triage_report.severity.value.upper()}` (Confidence: `{self.triage_report.confidence_score}`)",
            f"- **Root-Cause Node:** `{self.triage_report.root_cause_node_id}`",
            f"- **Asset Criticality:** `{self.compliance_report.host_asset_criticality}`",
            f"- **DESC Mandatory Notification SLA:** `{self.compliance_report.desc_reporting_sla_hours} hours`",
            f"- **Sovereign Air-Gap Verified:** `{self.compliance_report.sovereign_air_gap_certified}` (`{self.triage_report.sovereign_residency.inference_endpoint}`)",
            "",
            "## 1. Executive Summary",
            self.triage_report.executive_summary,
            "",
            "## 2. Causal Provenance Graph (Mermaid DAG)",
            "```mermaid",
            self.mermaid_diagram,
            "```",
            "",
            "## 3. DESC ISR v2.0 & UAE NESA IAS Control Audit",
            "| Domain | Control ID | NESA Reference | Status | Technical Evidence |",
            "|---|---|---|---|---|",
        ]
        for ctrl in self.compliance_report.control_mappings:
            lines.append(
                f"| Domain {ctrl.domain_number}: {ctrl.domain_name} | `{ctrl.control_id}` | `{ctrl.nesa_ias_reference}` | `{ctrl.compliance_status.value}` | {ctrl.technical_evidence} |"
            )

        lines.extend(
            [
                "",
                "## 4. UAE Statutory & Cybercrime Law Alignment",
            ]
        )
        for stat in self.compliance_report.statutory_assessments:
            arts = ", ".join(stat.applicable_articles)
            lines.append(
                f"- **{stat.statute_name}** ({arts}) — *SLA: {stat.mandatory_notification_sla_hours}h*: {stat.relevance_summary}"
            )

        if self.detection_bundle is not None:
            lines.extend(
                [
                    "",
                    f"## 5. Synthesized Detection-as-Code (`{self.detection_bundle.rule_id}`)",
                    "### Sigma YAML Specification",
                    "```yaml",
                    self.detection_bundle.sigma_yaml.strip(),
                    "```",
                    "### Splunk SPL Query",
                    "```spl",
                    self.detection_bundle.splunk_spl,
                    "```",
                    "### Microsoft Sentinel KQL Query",
                    "```kql",
                    self.detection_bundle.sentinel_kql,
                    "```",
                ]
            )

        return "\n".join(lines)


class SovereignTriagePipeline:
    """
    End-to-End Orchestrator connecting Modules 1 through 5:
    Module 1 (Normalizer) -> Module 2 (Causal DAG & Noise Pruner) ->
    Module 3 (Air-Gapped LLM Triage) -> Module 4 (Sigma/SPL/KQL Synthesizer) ->
    Module 5 (DESC ISR v2.0 & UAE Statutory Compliance Auditor).
    """

    def __init__(
        self,
        risk_threshold: int = 30,
        endpoint_url: str = "http://127.0.0.1:11434/api/chat",
        model_identifier: str = "llama3.1:8b-instruct-q4_K_M",
    ) -> None:
        self.risk_threshold = risk_threshold
        self.triage_engine = AirGappedTriageEngine(
            endpoint_url=endpoint_url,
            model_identifier=model_identifier,
        )

    def run_from_events(
        self,
        events: List[NormalizedTelemetryEvent],
        prune_noise: bool = True,
    ) -> SovereignPipelineResult:
        graph_engine = ProvenanceGraphEngine(risk_threshold=self.risk_threshold)
        graph_engine.ingest_events(events)
        if prune_noise:
            graph_engine.prune_benign_noise()

        dag_ctx = graph_engine.to_llm_context_dict()
        mermaid_str = graph_engine.to_mermaid()
        triage_report = self.triage_engine.triage_dag(dag_ctx)

        detection_bundle: Optional[SynthesizedDetectionBundle] = None
        if triage_report.verdict != TriageVerdict.BENIGN and dag_ctx.get("topological_nodes"):
            detection_bundle = SigmaRuleSynthesizer.synthesize_from_triage(triage_report, dag_ctx)

        compliance_report = DescIsrComplianceAuditor.audit_incident(
            triage_report=triage_report,
            dag_context=dag_ctx,
            detection_bundle=detection_bundle,
        )

        return SovereignPipelineResult(
            normalized_events=events,
            dag_context=dag_ctx,
            mermaid_diagram=mermaid_str,
            triage_report=triage_report,
            detection_bundle=detection_bundle,
            compliance_report=compliance_report,
        )

    def run_sysmon_json_records(
        self,
        records: Iterable[Dict[str, Any]],
        asset_criticality: str = "standard",
        prune_noise: bool = True,
    ) -> SovereignPipelineResult:
        events = [
            SysmonNormalizer.parse_dict(r, asset_criticality=asset_criticality)
            for r in records
        ]
        return self.run_from_events(events, prune_noise=prune_noise)

    def run_auditd_lines(
        self,
        lines: Iterable[str],
        default_hostname: str = "linux-sovereign-node",
        asset_criticality: str = "standard",
        prune_noise: bool = True,
    ) -> SovereignPipelineResult:
        normalizer = AuditdNormalizer(
            default_hostname=default_hostname,
            asset_criticality=asset_criticality,
        )
        events = normalizer.parse_stream(lines)
        return self.run_from_events(events, prune_noise=prune_noise)
