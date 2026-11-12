# Sovereign-Triage & Compliance AI (S-TCAI)

Sovereign-Triage & Compliance AI (S-TCAI) is a specialized SOC triage engine engineered for high-assurance sovereign environments, specifically aligned with the **Dubai Electronic Security Center (DESC) Information Security Regulation (ISR v2.0)**.

## Key Regulatory & Technical Alignment
- **DESC ISR v2.0 Domain 4 (Incident Management)**: Reconstructs multi-stage attack lineages across process trees, network sockets, and file activity for rapid containment and root-cause analysis.
- **DESC ISR v2.0 Domain 6 (Operational Logging & Integrity)**: Centralized normalization of heterogeneous telemetry (Windows Sysmon and Linux auditd) with tamper-evident SHA-256 payload integrity hashing and clock-drift accounting.
- **DESC ISR v2.0 Domain 8 (Secure Systems)**: Strict Pydantic-based schema validation forbidding unknown attributes and enforcing strict type invariants.
- **DESC ISR v2.0 Domain 11 (Compliance & Audit)**: Structured audit logging metadata with MITRE ATT&CK tagging and deterministic UUIDv5 synthetic lineage reconstruction.
- **DESC ISR v2.0 Domain 13 (Cloud Security & Sovereign Data Residency)**: Telemetry tagging for asset criticality (`critical_sovereign`) and data boundary enforcement.

## Project Structure
```text
sovereign-triage-ai/
├── pyproject.toml
├── README.md
├── src/
│   └── stcai/
│       ├── __init__.py
│       ├── schemas/
│       │   ├── __init__.py
│       │   └── telemetry.py
│       └── ingest/
│           ├── __init__.py
│           └── normalizer.py
└── tests/
    ├── __init__.py
    ├── fixtures/
    │   ├── sysmon_attack_chain.json
    │   └── auditd_privesc_chain.log
    └── test_module1_normalizer.py
```

## Running Verification Suite
```bash
pytest -v
```
