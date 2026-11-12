from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from pydantic import ValidationError

from stcai.ingest.normalizer import AuditdNormalizer, SysmonNormalizer
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

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_sysmon_parsing_json_and_xml() -> None:
    """Test 1: Sysmon JSON & XML parsing across Event IDs 1, 3, and 11."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    assert len(records) == 3

    # Event 1: Process Creation (ID 1)
    evt1 = SysmonNormalizer.parse_dict(records[0], asset_criticality="critical_sovereign")
    assert evt1.source_event_id == "1"
    assert evt1.source_type == TelemetrySourceType.WINDOWS_SYSMON
    assert evt1.category == EventCategory.PROCESS_CREATION
    assert evt1.outcome == EventOutcome.SUCCESS
    assert evt1.host.hostname == "sov-win-srv01.ad.sovereign.ae"
    assert evt1.host.asset_criticality == "critical_sovereign"
    assert evt1.process.executable.lower().endswith("powershell.exe")

    # Event 2: Network Connection (ID 3)
    evt2 = SysmonNormalizer.parse_dict(records[1])
    assert evt2.source_event_id == "3"
    assert evt2.category == EventCategory.NETWORK_CONNECTION
    assert evt2.network is not None
    assert evt2.network.destination_ip == IPv4Address("185.220.101.45")
    assert evt2.network.destination_port == 443
    assert evt2.network.protocol == "tcp"

    # Event 3: File Activity (ID 11)
    evt3 = SysmonNormalizer.parse_dict(records[2])
    assert evt3.source_event_id == "11"
    assert evt3.category == EventCategory.FILE_ACTIVITY
    assert evt3.file is not None
    assert evt3.file.target_filename == r"C:\Users\Public\updater.exe"
    assert evt3.file.operation == "create"

    # XML Parsing verification for Event 1
    sample_xml = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
        <Computer>SOV-WIN-SRV01.ad.sovereign.ae</Computer>
        <EventRecordID>1001</EventRecordID>
      </System>
      <EventData>
        <Data Name="UtcTime">2026-11-12 12:00:00.000</Data>
        <Data Name="ProcessGuid">{{11111111-2222-3333-4444-555555555555}}</Data>
        <Data Name="ProcessId">4100</Data>
        <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgA</Data>
        <Data Name="User">SOVEREIGN\\victim</Data>
        <Data Name="Hashes">SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</Data>
        <Data Name="ParentProcessGuid">{{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}}</Data>
        <Data Name="ParentProcessId">3200</Data>
        <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
      </EventData>
    </Event>"""
    evt_xml = SysmonNormalizer.parse_xml(sample_xml, asset_criticality="critical_sovereign")
    assert evt_xml.source_event_id == "1"
    assert evt_xml.category == EventCategory.PROCESS_CREATION
    assert evt_xml.process.entity_uid == "11111111-2222-3333-4444-555555555555"
    assert evt_xml.process.parent_entity_uid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_sysmon_brace_normalization_and_sha256_extraction() -> None:
    """Test 2: ProcessGuid brace normalization and SHA-256 extraction."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    evt = SysmonNormalizer.parse_dict(records[0])

    # Brace normalization and lowercase
    assert evt.process.entity_uid == "11111111-2222-3333-4444-555555555555"
    assert evt.process.parent_entity_uid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert "{" not in evt.process.entity_uid and "}" not in evt.process.entity_uid
    assert "{" not in (evt.process.parent_entity_uid or "")

    # SHA256 extraction
    expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert evt.process.sha256_hash == expected_hash
    assert len(evt.process.sha256_hash) == 64


def test_auditd_multiline_grouping_and_proctitle_decoding() -> None:
    """Test 3: Linux auditd multi-line grouping and hex PROCTITLE decoding."""
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    normalizer = AuditdNormalizer(default_hostname="sov-linux-node01")
    events = normalizer.parse_stream(log_lines)

    assert len(events) == 3

    # Event 1 contains SYSCALL, PROCTITLE, CWD, and PATH records grouped together
    evt1 = events[0]
    assert evt1.source_event_id == "1731430000.100:501"
    assert evt1.category == EventCategory.PROCESS_CREATION
    assert evt1.process.executable == "/usr/bin/python3"
    assert evt1.process.working_directory == "/var/www/html"

    # PROCTITLE decoding: '2F7573722F62696E2F707974686F6E33002D6300696D706F727420707479'
    # -> "/usr/bin/python3 -c import pty"
    assert evt1.process.command_line == "/usr/bin/python3 -c import pty"


def test_auditd_stateful_lineage_continuity() -> None:
    """Test 4: Stateful Linux pid -> ppid synthetic UUIDv5 lineage continuity."""
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    normalizer = AuditdNormalizer(default_hostname="sov-linux-node01")
    events = normalizer.parse_stream(log_lines)

    evt1 = events[0]  # PID 2100
    evt3 = events[2]  # PID 2105, PPID 2100

    assert evt1.process.pid == 2100
    assert evt3.process.pid == 2105
    assert evt3.process.ppid == 2100

    # Lineage continuity: child's parent_entity_uid must equal parent's entity_uid
    assert evt3.process.parent_entity_uid == evt1.process.entity_uid
    assert evt3.process.parent_executable == evt1.process.executable


def test_auditd_binary_sockaddr_hex_unpacking() -> None:
    """Test 5: Binary SOCKADDR hex unpacking to 10.10.10.5:443."""
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    normalizer = AuditdNormalizer(default_hostname="sov-linux-node01")
    events = normalizer.parse_stream(log_lines)

    evt2 = events[1]  # syscall=42 (connect)
    assert evt2.source_event_id == "1731430001.200:502"
    assert evt2.category == EventCategory.NETWORK_CONNECTION
    assert evt2.network is not None
    assert evt2.network.destination_ip == IPv4Address("10.10.10.5")
    assert evt2.network.destination_port == 443
    assert evt2.network.protocol == "tcp"
    assert evt2.network.initiated_outbound is True


def test_auditd_auid_normalization_unset_vs_preserved() -> None:
    """Test 6: Linux auid=4294967295 normalization to None vs preserved auid=1001 on euid=0."""
    fixture_path = FIXTURES_DIR / "auditd_privesc_chain.log"
    with open(fixture_path, "r", encoding="utf-8") as f:
        log_lines = f.readlines()

    normalizer = AuditdNormalizer(default_hostname="sov-linux-node01")
    events = normalizer.parse_stream(log_lines)

    # Event 1: Web shell escalating to root with auid=1001 preserved
    evt1 = events[0]
    assert evt1.user.login_uid == "1001"
    assert evt1.user.effective_uid == 0
    assert evt1.user.effective_user == "root"
    assert evt1.user.privilege_level == "root"

    # Event 3: Daemon / unset auid=4294967295 normalized to None
    evt3 = events[2]
    assert evt3.user.login_uid is None
    assert evt3.user.effective_uid == 0
    assert evt3.user.effective_user == "root"


def test_desc_isr_domain6_integrity_and_clock_drift() -> None:
    """Test 7: DESC ISR v2.0 Domain 6 tamper-evident raw_payload_sha256 and clock_drift_seconds."""
    fixture_path = FIXTURES_DIR / "sysmon_attack_chain.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    # Ingestion timestamp 15.5 seconds after event UtcTime (2026-11-12 12:00:00Z)
    ingested_at = datetime(2026, 11, 12, 12, 0, 15, 500000, tzinfo=timezone.utc)
    evt = SysmonNormalizer.parse_dict(records[0], ingested_at=ingested_at)

    # Clock drift: 15.5 seconds
    assert evt.integrity.clock_drift_seconds == 15.5
    assert evt.integrity.ingested_at_utc == ingested_at

    # Raw payload SHA-256 integrity calculation
    expected_hash = hashlib.sha256(
        json.dumps(records[0], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert evt.integrity.raw_payload_sha256 == expected_hash
    assert len(evt.integrity.raw_payload_sha256) == 64


def test_pydantic_validation_network_without_context_fails() -> None:
    """Test 8: Pydantic validation failure when category='network_connection' lacks network context."""
    now = datetime.now(timezone.utc)
    valid_host = HostContext(hostname="host1", os_family="linux")
    valid_user = UserIdentityContext(effective_user="root")
    valid_proc = ProcessLineageContext(entity_uid="proc-1", pid=100, executable="/bin/true")
    valid_integrity = IntegrityMetadata(
        raw_payload_sha256="0" * 64,
        clock_drift_seconds=0.0,
    )

    # Category is network_connection but network is None -> Must fail validation
    with pytest.raises(ValidationError) as exc_info:
        NormalizedTelemetryEvent(
            source_event_id="test-001",
            source_type=TelemetrySourceType.LINUX_AUDITD,
            category=EventCategory.NETWORK_CONNECTION,
            timestamp_utc=now,
            host=valid_host,
            user=valid_user,
            process=valid_proc,
            network=None,  # Missing network context
            integrity=valid_integrity,
        )
    assert "network context must be populated when category is 'network_connection'" in str(exc_info.value)

    # Category is file_activity but file is None -> Must fail validation
    with pytest.raises(ValidationError) as exc_info_file:
        NormalizedTelemetryEvent(
            source_event_id="test-002",
            source_type=TelemetrySourceType.LINUX_AUDITD,
            category=EventCategory.FILE_ACTIVITY,
            timestamp_utc=now,
            host=valid_host,
            user=valid_user,
            process=valid_proc,
            file=None,  # Missing file context
            integrity=valid_integrity,
        )
    assert "file context must be populated when category is 'file_activity'" in str(exc_info_file.value)
