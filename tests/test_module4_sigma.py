from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from stcai.detection.sigma_synthesizer import SigmaRuleSynthesizer
from stcai.graph.provenance import ProvenanceGraphEngine
from stcai.ingest.normalizer import AuditdNormalizer, SysmonNormalizer
from stcai.schemas.detection import SynthesizedDetectionBundle
from stcai.schemas.triage import (
    IncidentSeverity,
    IncidentTriageReport,
    SovereignResidencyMetadata,
    TriageVerdict,
)
from stcai.triage.engine import AirGappedTriageEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _build_windows_pipeline_output() -> tuple[IncidentTriageReport, dict]:
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    events = [SysmonNormalizer.parse_dict(r) for r in records]
    graph_engine = ProvenanceGraphEngine()
    graph_engine.ingest_events(events)
    graph_engine.prune_benign_noise()
    dag_context = graph_engine.to_llm_context_dict()

    triage_engine = AirGappedTriageEngine()
    report = triage_engine.triage_dag(dag_context)
    return report, dag_context


def _build_linux_pipeline_output() -> tuple[IncidentTriageReport, dict]:
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    normalizer = AuditdNormalizer(default_hostname="sov-linux-node01")
    events = normalizer.parse_stream(log_lines)
    graph_engine = ProvenanceGraphEngine()
    graph_engine.ingest_events(events)
    graph_engine.prune_benign_noise()
    dag_context = graph_engine.to_llm_context_dict()

    triage_engine = AirGappedTriageEngine()
    report = triage_engine.triage_dag(dag_context)
    return report, dag_context


def test_windows_sysmon_sigma_rule_synthesis_end_to_end() -> None:
    """Test 1: End-to-end Windows Sysmon attack chain detection bundle synthesis."""
    report, dag_context = _build_windows_pipeline_output()
    bundle = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)

    assert isinstance(bundle, SynthesizedDetectionBundle)
    assert bundle.logsource.product == "windows"
    assert bundle.logsource.service == "sysmon"
    assert bundle.logsource.category == "process_creation"

    det = bundle.detection
    assert "selection_process" in det
    assert det["selection_process"]["Image|endswith"] == "powershell.exe"
    assert det["selection_process"]["ParentImage|endswith"] == "WINWORD.EXE"
    assert "selection_network" in det
    assert det["selection_network"]["DestinationIp"] == "185.220.101.45"
    assert det["selection_network"]["DestinationPort"] == 443
    assert "selection_file" in det
    assert "updater.exe" in det["selection_file"]["TargetFilename|endswith"]


def test_linux_auditd_sigma_rule_synthesis_end_to_end() -> None:
    """Test 2: End-to-end Linux auditd privilege escalation detection bundle synthesis."""
    report, dag_context = _build_linux_pipeline_output()
    bundle = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)

    assert bundle.logsource.product == "linux"
    assert bundle.logsource.service == "auditd"

    det = bundle.detection
    assert "selection_process" in det
    assert "import pty" in det["selection_process"]["CommandLine|contains"]
    assert "selection_network" in det
    assert det["selection_network"]["DestinationIp"] == "10.10.10.5"


def test_sigma_yaml_valid_deserialization_and_schema() -> None:
    """Test 3: Sigma YAML serialization conformance and tag validation."""
    report, dag_context = _build_windows_pipeline_output()
    bundle = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)

    parsed = yaml.safe_load(bundle.sigma_yaml)
    assert isinstance(parsed, dict)

    required_keys = ["title", "id", "status", "logsource", "detection", "level", "tags"]
    for key in required_keys:
        assert key in parsed, f"Missing required Sigma key: {key}"

    tags = parsed["tags"]
    assert "attack.t1059.001" in tags
    assert "desc_isr.domain_4" in tags
    assert "desc_isr.domain_8" in tags
    assert "stcai.autonomous" in tags


def test_splunk_spl_transpilation_syntax() -> None:
    """Test 4: Transpilation of synthesized rule into valid Splunk SPL syntax."""
    report, dag_context = _build_windows_pipeline_output()
    bundle = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)

    spl = bundle.splunk_spl
    assert spl.startswith("index=*")
    assert 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"' in spl
    assert 'Image="*powershell.exe"' in spl
    assert 'ParentImage="*WINWORD.EXE"' in spl
    assert 'DestinationIp="185.220.101.45"' in spl
    assert "| table _time host" in spl


def test_sentinel_kql_transpilation_syntax() -> None:
    """Test 5: Transpilation of synthesized rule into valid Microsoft Sentinel KQL syntax."""
    report, dag_context = _build_windows_pipeline_output()
    bundle = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)

    kql = bundle.sentinel_kql
    assert "DeviceProcessEvents" in kql
    assert "FolderPath endswith 'powershell.exe'" in kql
    assert "InitiatingProcessFileName endswith 'WINWORD.EXE'" in kql
    assert "RemoteIP =~ '185.220.101.45'" in kql
    assert "RemotePort == 443" in kql
    assert "| project TimeGenerated, DeviceName" in kql


def test_deterministic_uuidv5_rule_id_reproducibility() -> None:
    """Test 6: Rule ID generation is strictly deterministic and reproducible via UUIDv5."""
    report, dag_context = _build_windows_pipeline_output()
    bundle1 = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)
    bundle2 = SigmaRuleSynthesizer.synthesize_from_triage(report, dag_context)

    assert bundle1.rule_id == bundle2.rule_id
    assert len(bundle1.rule_id) == 36


def test_benign_triage_verdict_skips_sigma_synthesis() -> None:
    """Test 7: BENIGN triage verdicts raise ValueError to avoid generating false positive rules."""
    _, dag_context = _build_windows_pipeline_output()

    benign_report = IncidentTriageReport(
        verdict=TriageVerdict.BENIGN,
        severity=IncidentSeverity.LOW,
        confidence_score=0.99,
        executive_summary="All observed telemetry verified benign.",
        root_cause_node_id="proc:root",
        kill_chain_narrative=["No breach detected"],
        recommended_containment_actions=["No action required"],
        sovereign_residency=SovereignResidencyMetadata(
            inference_endpoint="http://127.0.0.1:11434/api/chat",
            model_identifier="llama3.1:8b",
        ),
    )

    with pytest.raises(ValueError) as exc_info:
        SigmaRuleSynthesizer.synthesize_from_triage(benign_report, dag_context)
    assert "Sigma synthesis is skipped for BENIGN triage verdicts." in str(exc_info.value)


def test_empty_dag_context_rejected() -> None:
    """Test 8: Reject empty or invalid DAG context during Sigma rule synthesis."""
    report, _ = _build_windows_pipeline_output()

    with pytest.raises(ValueError) as exc_info:
        SigmaRuleSynthesizer.synthesize_from_triage(report, {"topological_nodes": []})
    assert "Cannot synthesize Sigma rule from empty DAG context." in str(exc_info.value)
