from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from stcai.compliance.desc_isr_auditor import DescIsrComplianceAuditor
from stcai.pipeline import SovereignPipelineResult, SovereignTriagePipeline
from stcai.schemas.compliance import ComplianceStatus
from stcai.schemas.telemetry import (
    EventCategory,
    EventOutcome,
    HostContext,
    IntegrityMetadata,
    NormalizedTelemetryEvent,
    ProcessLineageContext,
    TelemetrySourceType,
    UserIdentityContext,
)
from stcai.schemas.triage import IncidentSeverity, TriageVerdict

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_end_to_end_sysmon_pipeline_critical_sovereign_sla() -> None:
    """Test 1: End-to-end Sysmon execution with critical_sovereign asset classification."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_sysmon_json_records(records, asset_criticality="critical_sovereign")

    assert isinstance(result, SovereignPipelineResult)
    assert result.triage_report.verdict == TriageVerdict.MALICIOUS
    assert result.compliance_report.desc_reporting_sla_hours == 6
    assert result.compliance_report.overall_compliance_posture == ComplianceStatus.REQUIRES_ESCALATION
    assert result.compliance_report.sovereign_air_gap_certified is True
    assert result.detection_bundle is not None
    assert result.compliance_report.host_asset_criticality == "critical_sovereign"


def test_end_to_end_auditd_pipeline_privesc_compliance() -> None:
    """Test 2: End-to-end Linux auditd execution mapping Sudo privilege escalation & C2 egress."""
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_auditd_lines(log_lines, asset_criticality="high")

    assert result.triage_report.verdict == TriageVerdict.MALICIOUS
    ctrl_ids = [c.control_id for c in result.compliance_report.control_mappings]
    assert "DESC-ISR-D05.4" in ctrl_ids  # Sudo Privilege Escalation
    assert "DESC-ISR-D06.5" in ctrl_ids  # Outbound C2 Egress


def test_desc_isr_mandatory_domains_present() -> None:
    """Test 3: Verify mandatory DESC ISR Domains 4, 6, 8, 11, and 13 are present on breach triage."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_sysmon_json_records(records)

    ctrl_ids = {c.control_id: c for c in result.compliance_report.control_mappings}
    expected_controls = [
        ("DESC-ISR-D04.1", "NESA-IAS-M4.1.1"),
        ("DESC-ISR-D06.3", "NESA-IAS-T4.1.2"),
        ("DESC-ISR-D08.4", "NESA-IAS-T4.4.1"),
        ("DESC-ISR-D11.1", "NESA-IAS-M5.2.1"),
        ("DESC-ISR-D13.1", "NESA-IAS-T7.1.1"),
    ]

    for ctrl_id, nesa_ref in expected_controls:
        assert ctrl_id in ctrl_ids, f"Expected control {ctrl_id} not found in mappings"
        assert ctrl_ids[ctrl_id].nesa_ias_reference == nesa_ref


def test_uae_statutory_cybercrime_and_pdpl_assessments() -> None:
    """Test 4: Verify statutory mapping to Dubai Law 11/2014, Cybercrimes Law 34/2021, and PDPL 45/2021."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_sysmon_json_records(records)

    assessments = result.compliance_report.statutory_assessments
    assert len(assessments) == 3

    statute_names = [a.statute_name for a in assessments]
    assert any("Dubai Law No. 11 of 2014" in s for s in statute_names)
    assert any("UAE Federal Decree-Law No. 34 of 2021" in s for s in statute_names)
    assert any("UAE Federal Decree-Law No. 45 of 2021" in s for s in statute_names)

    cybercrime_stat = next(a for a in assessments if "34 of 2021" in a.statute_name)
    assert "Article 2 (Unauthorized Access to Information Systems)" in cybercrime_stat.applicable_articles
    assert "Article 10 (Malicious Software & Exploit Deployment)" in cybercrime_stat.applicable_articles

    pdpl_stat = next(a for a in assessments if "45 of 2021" in a.statute_name)
    assert "Article 9 (Data Breach Notification to UAE Data Office)" in pdpl_stat.applicable_articles
    assert pdpl_stat.mandatory_notification_sla_hours == 72


def test_sla_calculation_matrix_across_severities() -> None:
    """Test 5: Verify DESC mandatory reporting SLA calculation matrix across asset criticality."""
    # Critical sovereign asset
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.CRITICAL, "critical_sovereign") == 6
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.HIGH, "critical_sovereign") == 6

    # Standard asset
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.CRITICAL, "standard") == 12
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.HIGH, "standard") == 24
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.MEDIUM, "standard") == 48
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.LOW, "standard") == 72
    assert DescIsrComplianceAuditor._calculate_desc_sla_hours(IncidentSeverity.INFORMATIONAL, "standard") == 72


def test_tamper_evident_log_hash_count_matches_events() -> None:
    """Test 6: Verify tamper-evident SHA-256 evidence log count matches source events."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_sysmon_json_records(records)

    assert result.compliance_report.tamper_evident_log_count == 3
    assert len(result.triage_report.desc_isr_domain6_evidence_hashes) == 3


def test_executive_markdown_dossier_generation() -> None:
    """Test 7: Generate auditor-ready Executive Markdown incident and compliance dossier."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_sysmon_json_records(records)

    md = result.to_executive_markdown()

    assert "# S-TCAI Sovereign Incident Triage & DESC ISR v2.0 Compliance Dossier" in md
    assert "```mermaid" in md
    assert "| Domain | Control ID | NESA Reference | Status | Technical Evidence |" in md
    assert "UAE Federal Decree-Law No. 34 of 2021" in md
    assert "```yaml" in md
    assert "```spl" in md
    assert "```kql" in md


def test_benign_pipeline_run_posture_and_no_sigma_bundle() -> None:
    """Test 8: Benign activity yields COMPLIANT_MITIGATED posture and skips Sigma synthesis."""
    benign_evt = NormalizedTelemetryEvent(
        source_event_id="benign-100",
        source_type=TelemetrySourceType.WINDOWS_SYSMON,
        category=EventCategory.PROCESS_CREATION,
        outcome=EventOutcome.SUCCESS,
        timestamp_utc=datetime.now(timezone.utc),
        host=HostContext(hostname="sov-win-srv01", os_family="windows"),
        user=UserIdentityContext(effective_user=r"SOVEREIGN\alice"),
        process=ProcessLineageContext(
            entity_uid="benign-proc-guid-001",
            pid=3456,
            executable=r"C:\Windows\notepad.exe",
            command_line="notepad.exe",
        ),
        integrity=IntegrityMetadata(
            raw_payload_sha256="c" * 64,
            clock_drift_seconds=0.0,
        ),
    )

    pipeline = SovereignTriagePipeline()
    result = pipeline.run_from_events([benign_evt], prune_noise=False)

    assert result.triage_report.verdict == TriageVerdict.BENIGN
    assert result.detection_bundle is None
    assert result.compliance_report.overall_compliance_posture == ComplianceStatus.COMPLIANT_MITIGATED
    assert result.compliance_report.desc_reporting_sla_hours == 72
