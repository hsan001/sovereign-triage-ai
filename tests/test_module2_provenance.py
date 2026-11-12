from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
import pytest

from stcai.graph.provenance import (
    NodeType,
    ProvenanceGraphEngine,
)
from stcai.ingest.normalizer import AuditdNormalizer, SysmonNormalizer
from stcai.schemas.telemetry import (
    EventCategory,
    EventOutcome,
    HostContext,
    IntegrityMetadata,
    NetworkActivityContext,
    NormalizedTelemetryEvent,
    ProcessLineageContext,
    TelemetrySourceType,
    UserIdentityContext,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _create_synthetic_event(
    entity_uid: str,
    executable: str,
    parent_entity_uid: str | None = None,
    command_line: str | None = None,
    category: EventCategory = EventCategory.PROCESS_CREATION,
    network: NetworkActivityContext | None = None,
    raw_hash: str | None = None,
    timestamp: datetime | None = None,
    hostname: str = "sov-win-srv01.ad.sovereign.ae",
    os_family: str = "windows",
) -> NormalizedTelemetryEvent:
    ts = timestamp or datetime.now(timezone.utc)
    return NormalizedTelemetryEvent(
        source_event_id="syn-001",
        source_type=TelemetrySourceType.WINDOWS_SYSMON if os_family == "windows" else TelemetrySourceType.LINUX_AUDITD,
        category=category,
        outcome=EventOutcome.SUCCESS,
        timestamp_utc=ts,
        host=HostContext(hostname=hostname, os_family=os_family),
        user=UserIdentityContext(effective_user="SYSTEM"),
        process=ProcessLineageContext(
            entity_uid=entity_uid,
            parent_entity_uid=parent_entity_uid,
            pid=1000,
            executable=executable,
            command_line=command_line,
        ),
        network=network,
        integrity=IntegrityMetadata(
            raw_payload_sha256=raw_hash or ("a" * 64),
            clock_drift_seconds=0.0,
        ),
    )


def test_sysmon_attack_chain_dag_construction() -> None:
    """Test 1: Sysmon attack chain DAG construction and causal edge verification."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    events = [SysmonNormalizer.parse_dict(r) for r in records]
    engine = ProvenanceGraphEngine()
    engine.ingest_events(events)

    # Verify DAG validity
    assert nx.is_directed_acyclic_graph(engine.graph) is True

    word_node = "proc:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ps_node = "proc:11111111-2222-3333-4444-555555555555"
    net_node = "net:185.220.101.45:443/tcp"
    file_node = "file:sov-win-srv01.ad.sovereign.ae:C:\\Users\\Public\\updater.exe"

    # Confirm nodes exist in graph
    assert word_node in engine.graph
    assert ps_node in engine.graph
    assert net_node in engine.graph
    assert file_node in engine.graph

    # Confirm causal edges and relations
    assert engine.graph.has_edge(word_node, ps_node)
    assert engine.graph.edges[word_node, ps_node]["relation"] == "SPAWNED"

    assert engine.graph.has_edge(ps_node, net_node)
    assert engine.graph.edges[ps_node, net_node]["relation"] == "CONNECTED_TO"

    assert engine.graph.has_edge(ps_node, file_node)
    assert engine.graph.edges[ps_node, file_node]["relation"] == "FILE_CREATE"


def test_auditd_privesc_chain_dag_and_auid_scoring() -> None:
    """Test 2: Linux auditd privilege escalation scoring and auid tracking."""
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    normalizer = AuditdNormalizer(default_hostname="sov-linux-node01")
    events = normalizer.parse_stream(log_lines)
    assert len(events) == 3

    engine = ProvenanceGraphEngine()
    engine.ingest_events(events)

    assert nx.is_directed_acyclic_graph(engine.graph) is True

    # Event 1 corresponds to python3 with auid=1001 escalating to root
    py_event = events[0]
    py_node_id = f"proc:{py_event.process.entity_uid}"
    assert py_node_id in engine.graph

    py_node_data = engine.graph.nodes[py_node_id]
    assert py_node_data["risk_score"] >= 50
    assert "linux_auid_privilege_escalation(auid=1001->root)" in py_node_data["risk_reasons"]
    assert py_node_data["effective_user"] == "root"


def test_powershell_base64_auto_deobfuscation() -> None:
    """Test 3: Automatic PowerShell Base64 decoding and high-risk scoring."""
    b64_payload = "aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkA"
    cmd_line = f"powershell.exe -enc {b64_payload}"

    record = {
        "EventID": "1",
        "Computer": "SOV-WIN-SRV01.ad.sovereign.ae",
        "EventData": {
            "UtcTime": "2026-11-12 14:00:00.000",
            "ProcessGuid": "{77777777-8888-9999-aaaa-bbbbbbbbbbbb}",
            "ProcessId": "5050",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": cmd_line,
            "ParentProcessGuid": "{12345678-1234-1234-1234-123456789012}",
            "ParentProcessId": "1000",
            "ParentImage": "C:\\Windows\\explorer.exe",
        },
    }

    evt = SysmonNormalizer.parse_dict(record)
    engine = ProvenanceGraphEngine()
    engine.add_event(evt)

    ps_node_id = "proc:77777777-8888-9999-aaaa-bbbbbbbbbbbb"
    assert ps_node_id in engine.graph
    node_data = engine.graph.nodes[ps_node_id]

    assert node_data["decoded_command_line"] == "iex (new-object net.webclient)"
    assert "encoded_powershell_payload" in node_data["risk_reasons"]
    assert node_data["risk_score"] >= 50


def test_pid_reuse_temporal_cycle_breaking() -> None:
    """Test 4: OS PID reuse cycle detection, versioned splitting, and DAG invariant preservation."""
    engine = ProvenanceGraphEngine()

    t1 = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 12, 10, 5, 0, tzinfo=timezone.utc)

    # Process A spawns Process B
    evt1 = _create_synthetic_event(
        entity_uid="guid-b",
        executable="proc_b.exe",
        parent_entity_uid="guid-a",
        timestamp=t1,
    )
    engine.add_event(evt1)
    assert engine.graph.has_edge("proc:guid-a", "proc:guid-b")

    # Later, recycled PID telemetry claims Process B spawned Process A (cycle)
    evt2 = _create_synthetic_event(
        entity_uid="guid-a",
        executable="proc_a_recycled.exe",
        parent_entity_uid="guid-b",
        timestamp=t2,
    )
    split_id = engine.add_event(evt2)

    assert engine.cycles_broken == 1
    assert split_id == "proc:guid-a#cycle_1"
    assert "proc:guid-a#cycle_1" in engine.graph
    assert engine.graph.has_edge("proc:guid-b", "proc:guid-a#cycle_1")
    assert nx.is_directed_acyclic_graph(engine.graph) is True


def test_bidirectional_ancestral_noise_pruning() -> None:
    """Test 5: Bi-directional ancestral reachability pruning of benign background noise."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    attack_events = [SysmonNormalizer.parse_dict(r) for r in records]

    # Generate 12 disconnected benign background process events (risk_score = 0)
    benign_events = []
    benign_exes = ["svchost.exe", "SearchIndexer.exe", "conhost.exe", "taskhostw.exe"]
    for i in range(12):
        exe = benign_exes[i % len(benign_exes)]
        b_evt = _create_synthetic_event(
            entity_uid=f"benign-proc-guid-{i:03d}",
            executable=f"C:\\Windows\\System32\\{exe}",
            command_line=f"{exe} -k unprovoked",
            raw_hash=f"b{i:02d}" + "0" * 61,
        )
        benign_events.append(b_evt)

    engine = ProvenanceGraphEngine(risk_threshold=30)
    engine.ingest_events(attack_events + benign_events)

    # Before pruning: 4 attack nodes (WINWORD, PowerShell, NET, FILE) + 12 benign nodes = 16 nodes
    assert engine.graph.number_of_nodes() == 16

    engine.prune_benign_noise()
    metrics = engine.last_pruning_metrics
    assert metrics is not None
    assert metrics.pruned_nodes_count >= 12
    assert metrics.reduction_percentage >= 70.0

    # Ensure all 12 benign nodes were purged
    for i in range(12):
        assert f"proc:benign-proc-guid-{i:03d}" not in engine.graph

    # CRITICAL: WINWORD.EXE had risk_score = 0, but MUST BE RETAINED because it is
    # the causal ancestor (entry root) of the high-risk powershell.exe seed node!
    word_node = "proc:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ps_node = "proc:11111111-2222-3333-4444-555555555555"
    assert word_node in engine.graph
    assert ps_node in engine.graph
    assert "net:185.220.101.45:443/tcp" in engine.graph
    assert "file:sov-win-srv01.ad.sovereign.ae:C:\\Users\\Public\\updater.exe" in engine.graph


def test_topological_llm_context_serialization() -> None:
    """Test 6: Strict topological serialization for LLM triage context."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    events = [SysmonNormalizer.parse_dict(r) for r in records]
    engine = ProvenanceGraphEngine()
    engine.ingest_events(events)
    engine.prune_benign_noise()

    llm_dict = engine.to_llm_context_dict()

    assert llm_dict["dag_verified"] is True
    assert llm_dict["node_count"] == 4
    assert llm_dict["edge_count"] == 3

    # Root entry node must be WINWORD.EXE
    word_node = "proc:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert word_node in llm_dict["root_entry_nodes"]

    # All evidence hashes must be present
    evidence_hashes = llm_dict["desc_isr_domain6_evidence_hashes"]
    assert len(evidence_hashes) == 3
    for evt in events:
        assert evt.integrity.raw_payload_sha256 in evidence_hashes


def test_mermaid_flowchart_export() -> None:
    """Test 7: Export to valid Mermaid flowchart format with standard syntax."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    events = [SysmonNormalizer.parse_dict(r) for r in records]
    engine = ProvenanceGraphEngine()
    engine.ingest_events(events)

    mermaid_code = engine.to_mermaid()

    assert mermaid_code.startswith("graph TD")
    assert "-->|SPAWNED|" in mermaid_code
    assert "-->|CONNECTED_TO|" in mermaid_code
    assert "-->|FILE_CREATE|" in mermaid_code


def test_multi_event_node_metadata_merging() -> None:
    """Test 8: Node metadata merging and raw evidence SHA-256 accumulation."""
    engine = ProvenanceGraphEngine()

    hash1 = "1" * 64
    hash2 = "2" * 64
    t1 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 12, 12, 1, 0, tzinfo=timezone.utc)

    evt1 = _create_synthetic_event(
        entity_uid="shared-proc-01",
        executable="app.exe",
        raw_hash=hash1,
        timestamp=t1,
    )
    evt2 = _create_synthetic_event(
        entity_uid="shared-proc-01",
        executable="app.exe",
        raw_hash=hash2,
        timestamp=t2,
    )

    engine.add_event(evt1)
    engine.add_event(evt2)

    # Process node must not be duplicated
    assert engine.graph.number_of_nodes() == 1
    node_data = engine.graph.nodes["proc:shared-proc-01"]

    # Both raw evidence hashes must be preserved
    assert hash1 in node_data["evidence_sha256_list"]
    assert hash2 in node_data["evidence_sha256_list"]
    assert node_data["first_seen_utc"] == t1.isoformat()
    assert node_data["last_seen_utc"] == t2.isoformat()
