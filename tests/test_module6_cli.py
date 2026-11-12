from __future__ import annotations

from pathlib import Path
import pytest

from stcai.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cli_sysmon_generates_markdown_dossier_file(tmp_path: Path) -> None:
    """Test 1: CLI parses Sysmon attack chain and generates valid Markdown dossier file."""
    input_file = FIXTURES_DIR / "sysmon_attack_chain.json"
    output_file = tmp_path / "sysmon_dossier.md"

    exit_code = main(
        [
            "-i",
            str(input_file),
            "-s",
            "sysmon",
            "-c",
            "critical_sovereign",
            "-o",
            str(output_file),
        ]
    )

    assert exit_code == 0
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "# S-TCAI Sovereign Incident Triage & DESC ISR v2.0 Compliance Dossier" in content
    assert "DESC-ISR-D13.1" in content
    assert "critical_sovereign" in content
    assert "6 hours" in content


def test_cli_auditd_generates_markdown_dossier_file(tmp_path: Path) -> None:
    """Test 2: CLI parses Linux auditd log and generates compliance dossier with privesc mappings."""
    input_file = FIXTURES_DIR / "auditd_privesc_chain.log"
    output_file = tmp_path / "auditd_dossier.md"

    exit_code = main(
        [
            "-i",
            str(input_file),
            "-s",
            "auditd",
            "-c",
            "high",
            "-o",
            str(output_file),
        ]
    )

    assert exit_code == 0
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "DESC-ISR-D05.4" in content
    assert "DESC-ISR-D06.5" in content


def test_cli_stdout_output_when_no_output_file_specified(capsys: pytest.CaptureFixture[str]) -> None:
    """Test 3: CLI outputs Markdown directly to stdout when --output-md is omitted."""
    input_file = FIXTURES_DIR / "sysmon_attack_chain.json"

    exit_code = main(
        [
            "-i",
            str(input_file),
            "-s",
            "sysmon",
            "-c",
            "standard",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "# S-TCAI Sovereign Incident Triage & DESC ISR v2.0 Compliance Dossier" in captured.out
    assert "```mermaid" in captured.out
    assert "```yaml" in captured.out


def test_cli_missing_input_file_returns_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    """Test 4: CLI returns non-zero error code when input file does not exist."""
    exit_code = main(
        [
            "-i",
            "nonexistent_file_path_12345.json",
            "-s",
            "sysmon",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error: Input file not found" in captured.err
