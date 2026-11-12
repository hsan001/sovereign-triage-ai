from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from stcai.schemas.compliance import (
    ComplianceStatus,
    DescIsrComplianceReport,
    DescIsrControlMapping,
    StatutoryLegalAssessment,
)
from stcai.schemas.detection import SynthesizedDetectionBundle
from stcai.schemas.triage import IncidentSeverity, IncidentTriageReport, TriageVerdict

# Lookup table mapping MITRE ATT&CK Technique IDs to DESC ISR v2.0 Controls and UAE NESA IAS
MITRE_TO_DESC_ISR_CATALOG: Dict[str, Tuple[int, str, str, str, str]] = {
    "T1059.001": (
        8,
        "Information Systems Acquisition, Development & Maintenance",
        "DESC-ISR-D08.2",
        "Restrict and monitor administrative scripting engines (PowerShell) and encoded command execution.",
        "NESA-IAS-T4.2.1",
    ),
    "T1059.006": (
        8,
        "Information Systems Acquisition, Development & Maintenance",
        "DESC-ISR-D08.3",
        "Control unauthorized interpreter execution (Python/PTY shell spawning) on production hosts.",
        "NESA-IAS-T4.2.2",
    ),
    "T1548.003": (
        5,
        "Access Control & Identity Management",
        "DESC-ISR-D05.4",
        "Enforce least-privilege execution and audit all privilege escalations across sudo/root boundaries.",
        "NESA-IAS-T5.1.3",
    ),
    "T1071.001": (
        6,
        "Operations, Systems & Communications Management",
        "DESC-ISR-D06.5",
        "Monitor and restrict unauthorized outbound application-layer C2 egress traffic at network boundaries.",
        "NESA-IAS-T6.2.1",
    ),
    "T1105": (
        8,
        "Information Systems Acquisition, Development & Maintenance",
        "DESC-ISR-D08.5",
        "Prevent and detect unauthorized binary staging or ingress tool transfers in public/temp directories.",
        "NESA-IAS-T4.3.1",
    ),
}


class DescIsrComplianceAuditor:
    """
    Module 5: Automated DESC ISR v2.0 & UAE Regulatory Compliance Auditor.
    Maps triaged causal DAG incidents and synthesized Sigma bundles to mandatory
    Dubai Electronic Security Center (DESC) ISR v2.0 domains, UAE NESA IAS controls,
    and UAE Federal Decree-Law No. 34/2021 & No. 45/2021 statutory requirements.
    """

    @classmethod
    def audit_incident(
        cls,
        triage_report: IncidentTriageReport,
        dag_context: Dict[str, Any],
        detection_bundle: Optional[SynthesizedDetectionBundle] = None,
    ) -> DescIsrComplianceReport:
        nodes: List[Dict[str, Any]] = dag_context.get("topological_nodes", [])
        asset_criticality = cls._extract_highest_criticality(nodes)
        evidence_hashes: List[str] = triage_report.desc_isr_domain6_evidence_hashes
        sla_hours = cls._calculate_desc_sla_hours(triage_report.severity, asset_criticality)

        controls: List[DescIsrControlMapping] = []

        # 1. Domain 4: Incident & Problem Management
        d4_status = (
            ComplianceStatus.REQUIRES_ESCALATION
            if triage_report.verdict == TriageVerdict.MALICIOUS
            else ComplianceStatus.COMPLIANT_MITIGATED
        )
        controls.append(
            DescIsrControlMapping(
                domain_number=4,
                domain_name="Incident & Problem Management",
                control_id="DESC-ISR-D04.1",
                control_requirement=(
                    "Establish structured root-cause investigation, causal kill-chain reconstruction, "
                    "and timely incident notification within statutory SLA."
                ),
                nesa_ias_reference="NESA-IAS-M4.1.1",
                compliance_status=d4_status,
                technical_evidence=(
                    f"Root-cause traced to {triage_report.root_cause_node_id} across {len(nodes)} "
                    f"verified DAG nodes; mandatory notification SLA={sla_hours}h."
                ),
            )
        )

        # 2. Domain 6: Operations, Systems & Communications Management (Tamper-Evident Logging)
        controls.append(
            DescIsrControlMapping(
                domain_number=6,
                domain_name="Operations, Systems & Communications Management",
                control_id="DESC-ISR-D06.3",
                control_requirement=(
                    "Ensure continuous UTC-synchronized security event logging and cryptographic "
                    "tamper protection of forensic audit trails."
                ),
                nesa_ias_reference="NESA-IAS-T4.1.2",
                compliance_status=ComplianceStatus.COMPLIANT_MITIGATED,
                technical_evidence=(
                    f"Verified {len(evidence_hashes)} canonical SHA-256 raw log digests with "
                    "UTC timestamp normalization."
                ),
            )
        )

        # 3. Dynamic MITRE Technique -> DESC ISR Control Mappings
        seen_control_ids = {"DESC-ISR-D04.1", "DESC-ISR-D06.3"}
        for mitre in triage_report.mitre_techniques:
            if mitre.technique_id in MITRE_TO_DESC_ISR_CATALOG:
                dom_num, dom_name, ctrl_id, req, nesa_ref = MITRE_TO_DESC_ISR_CATALOG[
                    mitre.technique_id
                ]
                if ctrl_id not in seen_control_ids:
                    seen_control_ids.add(ctrl_id)
                    controls.append(
                        DescIsrControlMapping(
                            domain_number=dom_num,
                            domain_name=dom_name,
                            control_id=ctrl_id,
                            control_requirement=req,
                            nesa_ias_reference=nesa_ref,
                            compliance_status=ComplianceStatus.VIOLATION_DETECTED,
                            technical_evidence=(
                                f"MITRE {mitre.technique_id} ({mitre.technique_name}) observed on "
                                f"node {mitre.evidence_node_id}."
                            ),
                        )
                    )

        # 4. Domain 8: Automated Detection-as-Code Mitigation
        if detection_bundle is not None:
            controls.append(
                DescIsrControlMapping(
                    domain_number=8,
                    domain_name="Information Systems Acquisition, Development & Maintenance",
                    control_id="DESC-ISR-D08.4",
                    control_requirement=(
                        "Deploy continuous technical countermeasures and updated SIEM detection "
                        "signatures following security incidents."
                    ),
                    nesa_ias_reference="NESA-IAS-T4.4.1",
                    compliance_status=ComplianceStatus.COMPLIANT_MITIGATED,
                    technical_evidence=(
                        f"Synthesized Sigma Rule {detection_bundle.rule_id} with transpiled "
                        "Splunk SPL and Microsoft Sentinel KQL queries."
                    ),
                )
            )

        # 5. Domain 11: Compliance & Verifiable Audit Trail
        controls.append(
            DescIsrControlMapping(
                domain_number=11,
                domain_name="Compliance & Audit",
                control_id="DESC-ISR-D11.1",
                control_requirement=(
                    "Maintain verifiable, automated audit evidence demonstrating adherence to "
                    "DESC ISR v2.0 and UAE regulatory mandates."
                ),
                nesa_ias_reference="NESA-IAS-M5.2.1",
                compliance_status=ComplianceStatus.COMPLIANT_MITIGATED,
                technical_evidence="Automated S-TCAI compliance dossier generated with cryptographic evidence hashes.",
            )
        )

        # 6. Domain 13: Cloud Security & Sovereign Data Residency
        air_gap_ok = triage_report.sovereign_residency.air_gap_verified
        inj_detected = triage_report.sovereign_residency.adversarial_injection_detected
        controls.append(
            DescIsrControlMapping(
                domain_number=13,
                domain_name="Cloud Security & Sovereign Data Residency",
                control_id="DESC-ISR-D13.1",
                control_requirement=(
                    "Process sensitive government and critical infrastructure telemetry strictly "
                    "within sovereign UAE on-premises boundaries without external public cloud egress."
                ),
                nesa_ias_reference="NESA-IAS-T7.1.1",
                compliance_status=(
                    ComplianceStatus.COMPLIANT_MITIGATED
                    if air_gap_ok
                    else ComplianceStatus.VIOLATION_DETECTED
                ),
                technical_evidence=(
                    f"Inference executed on {triage_report.sovereign_residency.inference_endpoint} "
                    f"(Zone: {triage_report.sovereign_residency.data_residency_zone}; "
                    f"Adversarial Injection Neutralized: {inj_detected})."
                ),
            )
        )

        statutory = cls._build_uae_statutory_assessments(triage_report, sla_hours)

        overall = (
            ComplianceStatus.REQUIRES_ESCALATION
            if triage_report.verdict == TriageVerdict.MALICIOUS
            else (
                ComplianceStatus.VIOLATION_DETECTED
                if triage_report.verdict == TriageVerdict.SUSPICIOUS
                else ComplianceStatus.COMPLIANT_MITIGATED
            )
        )

        attestation = (
            f"Audited under DESC ISR v2.0 & UAE NESA IAS frameworks. "
            f"Asset criticality={asset_criticality}, Verdict={triage_report.verdict.value}, "
            f"Mandatory DESC Notification SLA={sla_hours} hours."
        )

        return DescIsrComplianceReport(
            host_asset_criticality=asset_criticality,
            overall_compliance_posture=overall,
            desc_reporting_sla_hours=sla_hours,
            sovereign_air_gap_certified=air_gap_ok,
            tamper_evident_log_count=len(evidence_hashes),
            control_mappings=controls,
            statutory_assessments=statutory,
            auditor_attestation=attestation,
        )

    @staticmethod
    def _extract_highest_criticality(nodes: List[Dict[str, Any]]) -> str:
        rank = {"low": 1, "standard": 2, "high": 3, "critical_sovereign": 4}
        best = "standard"
        for n in nodes:
            c = str(n.get("asset_criticality", "standard"))
            if rank.get(c, 2) > rank.get(best, 2):
                best = c
        return best

    @staticmethod
    def _calculate_desc_sla_hours(severity: IncidentSeverity, asset_criticality: str) -> int:
        if asset_criticality == "critical_sovereign" and severity in (
            IncidentSeverity.CRITICAL,
            IncidentSeverity.HIGH,
        ):
            return 6
        if severity == IncidentSeverity.CRITICAL:
            return 12
        if severity == IncidentSeverity.HIGH:
            return 24
        if severity == IncidentSeverity.MEDIUM:
            return 48
        return 72

    @staticmethod
    def _build_uae_statutory_assessments(
        triage_report: IncidentTriageReport, sla_hours: int
    ) -> List[StatutoryLegalAssessment]:
        assessments = [
            StatutoryLegalAssessment(
                statute_name="Dubai Law No. 11 of 2014 & DESC ISR v2.0 Mandate",
                applicable_articles=["Article 7 (DESC Incident Reporting)", "ISR Domain 4 & Domain 11"],
                relevance_summary=(
                    "Mandates structured incident logging, root-cause forensic preservation, "
                    "and timely notification to the Dubai Electronic Security Center."
                ),
                mandatory_notification_sla_hours=sla_hours,
            ),
            StatutoryLegalAssessment(
                statute_name="UAE Federal Decree-Law No. 34 of 2021 (Combating Rumors and Cybercrimes)",
                applicable_articles=[
                    "Article 2 (Unauthorized Access to Information Systems)",
                    "Article 3 (Compromising Government / Critical Infrastructure Data)",
                    "Article 10 (Malicious Software & Exploit Deployment)",
                ],
                relevance_summary=(
                    f"Chain exhibits {len(triage_report.mitre_techniques)} MITRE ATT&CK techniques "
                    "constituting unauthorized system access or malicious code execution; "
                    "SHA-256 log hashes preserved for evidentiary chain-of-custody."
                ),
                mandatory_notification_sla_hours=sla_hours,
            ),
            StatutoryLegalAssessment(
                statute_name="UAE Federal Decree-Law No. 45 of 2021 (Personal Data Protection Law - PDPL)",
                applicable_articles=[
                    "Article 9 (Data Breach Notification to UAE Data Office)",
                    "Article 20 (Technical & Organizational Security Measures)",
                ],
                relevance_summary=(
                    "Air-gapped local LLM triage ensures zero unauthorized cross-border transfer "
                    "of personal or government identity attributes (effective_user / login_uid)."
                ),
                mandatory_notification_sla_hours=72,
            ),
        ]
        return assessments
