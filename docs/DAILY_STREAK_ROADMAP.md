# S-TCAI 14-Day MITRE ATT&CK & DESC ISR Expansion Roadmap
**Sovereign-Triage & Compliance AI (`hsan001/sovereign-triage-ai`)**  
*Daily 10-Minute Engineering Backlog for Continuous Detection Catalog Growth & Authentic GitHub Contribution Velocity*

---

## Strategic Objective

This roadmap provides a structured, high-signal, 14-day engineering backlog designed for rapid 10-minute daily execution. Each milestone contributes verifiable, production-grade detection logic, automated unit testing, or compliance enhancements mapped to the **Dubai Electronic Security Center (DESC) Information Security Regulation (ISR v2.0)** and **UAE National Electronic Security Authority (NESA) Information Assurance Standards (IAS)**.

Every task contains:
1. **Target Feature / Threat Technique**: Specific MITRE ATT&CK technique and audit telemetry source.
2. **Regulatory Mapping**: DESC ISR v2.0 domain, control identifier, and UAE statutory requirement.
3. **Exact Code & Test Blueprint**: File locations and test criteria ensuring 100% CI pass rate.
4. **Git Commit Command**: Clean conventional commit command for an authentic contribution history.

---

## Daily Backlog Schedule

```
+----------------------------------------------------------------------------------------------------+
| S-TCAI 14-DAY CONTINUOUS DETECTION & COMPLIANCE ENGINEERING SPRINT                                 |
+---------+----------------------------------------------+---------------------------+---------------+
| Day     | Milestone / Feature                          | Threat / Control Focus    | Verification  |
+---------+----------------------------------------------+---------------------------+---------------+
| Day 1   | T1003.001 LSASS Credential Dumping          | Sysmon Event ID 10        | Pytest Test   |
| Day 2   | T1053.003 Linux Cron Persistence             | auditd openat/chmod       | Pytest Test   |
| Day 3   | T1562.001 Impair Defenses (auditd/Defender)  | Security Tampering        | Pytest Test   |
| Day 4   | T1021.002 SMB Admin Shares Lateral Movement  | TCP 445 / IPC$            | Pytest Test   |
| Day 5   | T1543.002 Linux systemd Service Persistence  | Daemon Creation           | Pytest Test   |
| Day 6   | T1070.004 Indicator Removal (Anti-Forensics) | Sysmon 23 / unlink        | Pytest Test   |
| Day 7   | T1218.011 LOLBin Rundll32 Proxy Execution    | rundll32.exe Abuse        | Pytest Test   |
| Day 8   | CLI Machine-Readable Output (--output-json)  | Programmatic SOAR / SIEM  | CLI Test      |
| Day 9   | OASIS SARIF v2.1.0 Exporter                  | GitHub Security Tab       | SARIF Schema  |
| Day 10  | Custom DESC ISR Statutory SLA Configuration  | YAML Escalation Overrides | Config Test   |
| Day 11  | Causal Graph Pruning Benchmarking Script     | Synthetic 10k Event Test  | Benchmark Run |
| Day 12  | Linux Cron Persistence Evidence Dossier      | End-to-End Triage Dossier | Live Artifact |
| Day 13  | Multi-Engine Transpiler Validator            | Splunk & Sentinel Linter  | Script Check  |
| Day 14  | S-TCAI v1.1.0 Milestone Release & Changelog  | Version Cut & Tag         | GitHub Tag    |
+---------+----------------------------------------------+---------------------------+---------------+
```

---

### Day 1: Credential Access - LSASS Memory Dumping (`T1003.001`)

- **Objective**: Add detection and DESC ISR audit mapping for OS Credential Dumping targeting `lsass.exe` via Windows Sysmon ProcessAccess (Event ID 10) or Minidump calls.
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 5 (*Access Control & Identity Management*)
  - **Control ID**: `DESC-ISR-D05.4` (*Enforce privilege boundaries and audit unauthorized memory access to authentication subsystems*)
  - **UAE NESA IAS**: `NESA-IAS-T5.1.3`
  - **UAE Legal SLA**: Immediate escalation under UAE Cybercrimes Decree-Law No. 34/2021 (Article 2 - Unauthorized Access to Authentication Systems).
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1003.001` entry to `MITRE_TO_DESC_ISR_CATALOG`.
  - `tests/test_compliance.py`: Add `test_lsass_dumping_compliance_audit()`.
- **Implementation Blueprint**:
  ```python
  # src/stcai/compliance/desc_isr_auditor.py
  "T1003.001": (
      5,
      "Access Control & Identity Management",
      "DESC-ISR-D05.4",
      "Prevent and audit unauthorized access to OS credential stores (LSASS memory dumping).",
      "NESA-IAS-T5.1.3",
  ),
  ```
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(compliance): map MITRE T1003.001 LSASS dumping to DESC-ISR-D05.4"
  git push origin main
  ```

---

### Day 2: Persistence - Linux Cron Job Manipulation (`T1053.003`)

- **Objective**: Ingest Linux `auditd` file creation/modification telemetry (`PATH`, `openat`, `creat`) targeting `/etc/cron.*`, `/var/spool/cron/crontabs/`, and synthesize detection rules.
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 8 (*Information Systems Acquisition, Development & Maintenance*)
  - **Control ID**: `DESC-ISR-D08.2` (*Control unauthorized persistent tasks and scheduled system processes*)
  - **UAE NESA IAS**: `NESA-IAS-T4.2.1`
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1053.003` to `MITRE_TO_DESC_ISR_CATALOG`.
  - `tests/test_compliance.py`: Add test for cron persistence audit mapping.
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(compliance): add MITRE T1053.003 Linux cron persistence detection & DESC audit"
  git push origin main
  ```

---

### Day 3: Defense Evasion - Impair Defenses (`T1562.001`)

- **Objective**: Detect unauthorized administrative attempts to disable host security controls (e.g., `auditctl -e 0`, `systemctl stop auditd`, or `Set-MpPreference -DisableRealtimeMonitoring $true`).
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 6 (*Operations, Systems & Communications Management*)
  - **Control ID**: `DESC-ISR-D06.1` (*Protect audit logging subsystems against unauthorized modification, suppression, or termination*)
  - **UAE NESA IAS**: `NESA-IAS-T6.1.1`
  - **Statutory Severity**: CRITICAL violation under DESC ISR logging integrity mandates.
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1562.001` entry.
  - `tests/test_compliance.py`: Add `test_defense_tampering_triggers_critical_sla()`.
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(detection): detect security agent suppression (T1562.001) with DESC-ISR-D06.1 audit"
  git push origin main
  ```

---

### Day 4: Lateral Movement - SMB / Windows Admin Shares (`T1021.002`)

- **Objective**: Ingest Windows Sysmon Network Connection (Event ID 3) and Process Creation (Event ID 1) referencing `IPC$`, `ADMIN$`, or `C$` shares over TCP port 445.
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 6 (*Operations, Systems & Communications Management*)
  - **Control ID**: `DESC-ISR-D06.5` (*Segregate network boundaries and restrict lateral administrative RPC/SMB sessions*)
  - **UAE NESA IAS**: `NESA-IAS-T6.2.1`
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1021.002` entry.
  - `tests/test_compliance.py`: Add test verifying SMB lateral movement containment recommendations.
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(compliance): map lateral movement T1021.002 to DESC-ISR-D06.5 network segregation"
  git push origin main
  ```

---

### Day 5: Persistence - Linux systemd Service Creation (`T1543.002`)

- **Objective**: Capture Linux `auditd` events writing unit files to `/etc/systemd/system/` or `/usr/lib/systemd/system/` followed by `systemctl enable/daemon-reload`.
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 8 (*Information Systems Acquisition, Development & Maintenance*)
  - **Control ID**: `DESC-ISR-D08.2` (*Validate and record all persistent daemon configurations*)
  - **UAE NESA IAS**: `NESA-IAS-T4.2.1`
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1543.002`.
  - `tests/test_compliance.py`: Add verification for Linux daemon persistence rule synthesis.
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(compliance): register T1543.002 systemd persistence in DESC ISR control engine"
  git push origin main
  ```

---

### Day 6: Defense Evasion - Indicator Removal on Host (`T1070.004`)

- **Objective**: Detect file deletion and anti-forensics activity (Sysmon Event ID 23 FileDelete, or Linux `auditd` `unlinkat` syscall on log directories `/var/log/*`).
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 6 (*Operations, Systems & Communications Management*)
  - **Control ID**: `DESC-ISR-D06.2` (*Ensure log non-repudiation and prevent premature or unauthorized forensic artifact purge*)
  - **UAE NESA IAS**: `NESA-IAS-T6.1.2`
  - **Statutory Mandate**: UAE Federal Decree-Law No. 34 of 2021, Article 5 (Tampering with Electronic Evidence).
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1070.004` entry.
  - `tests/test_compliance.py`: Add test for anti-forensic evidence destruction alert.
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(compliance): map T1070.004 evidence deletion to DESC-ISR-D06.2 log preservation"
  git push origin main
  ```

---

### Day 7: Defense Evasion - Rundll32 Proxy Execution (`T1218.011`)

- **Objective**: Flag Living-off-the-Land Binary (LOLBin) execution abusing `rundll32.exe` to execute unbacked DLLs or ordinal exports from `AppData` / `Temp` paths.
- **Regulatory Mapping**:
  - **DESC ISR Domain**: Domain 8 (*Information Systems Acquisition, Development & Maintenance*)
  - **Control ID**: `DESC-ISR-D08.4` (*Enforce software execution policies and prevent unapproved binary proxying*)
  - **UAE NESA IAS**: `NESA-IAS-T4.2.3`
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Add `T1218.011` entry.
  - `tests/test_transpiler.py`: Add test verifying transpiled Splunk SPL / Sentinel KQL targeting `rundll32.exe`.
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_transpiler.py
  git commit -m "feat(detection): synthesize LOLBin rundll32.exe rules with DESC-ISR-D08.4 compliance"
  git push origin main
  ```

---

### Day 8: CLI Engineering - Structured JSON Export (`--output-json`)

- **Objective**: Add `--output-json <path>` CLI flag to `src/stcai/cli.py` enabling SOAR playbooks (e.g., Splunk SOAR, Cortex XSOAR) to consume raw `SovereignTriageReport` JSON payloads.
- **Files to Modify**:
  - `src/stcai/cli.py`: Add `--output-json` argument and write output payload when specified.
  - `tests/test_cli.py`: Add test validating programmatic JSON file emission.
- **Commit Command**:
  ```bash
  git add src/stcai/cli.py tests/test_cli.py
  git commit -m "feat(cli): add --output-json flag for automated SOAR/SIEM pipeline integration"
  git push origin main
  ```

---

### Day 9: Standard Formats - OASIS SARIF v2.1.0 Exporter

- **Objective**: Create `src/stcai/formatters/sarif.py` to convert `DescComplianceAudit` into OASIS SARIF format (`sarif-schema-2.1.0.json`) so triage findings render natively in GitHub's Code Scanning / Security tab.
- **Files to Create**:
  - `src/stcai/formatters/__init__.py`
  - `src/stcai/formatters/sarif.py`
  - `tests/test_sarif_export.py`
- **Commit Command**:
  ```bash
  git add src/stcai/formatters/ tests/test_sarif_export.py
  git commit -m "feat(formatters): add OASIS SARIF v2.1.0 exporter for GitHub Security integration"
  git push origin main
  ```

---

### Day 10: Regulatory Customization - Custom DESC ISR SLA Config

- **Objective**: Support enterprise-specific SLA overrides via YAML configuration (`--config stcai-sla.yaml`) allowing custom notification thresholds for DESC ISR Domain 4.
- **Files to Modify**:
  - `src/stcai/compliance/desc_isr_auditor.py`: Accept optional custom SLA configuration dictionary.
  - `tests/test_compliance.py`: Test custom SLA overrides (e.g., 30-minute critical notification window).
- **Commit Command**:
  ```bash
  git add src/stcai/compliance/desc_isr_auditor.py tests/test_compliance.py
  git commit -m "feat(compliance): allow custom DESC ISR SLA threshold configuration via YAML"
  git push origin main
  ```

---

### Day 11: Performance Verification - Graph Pruning Benchmark Script

- **Objective**: Add `scripts/benchmark_pruning.py` to stress-test the NetworkX provenance engine against 1,000 to 20,000 synthetic events and verify >70% noise reduction under 250ms.
- **Files to Create**:
  - `scripts/benchmark_pruning.py`
- **Execution**:
  ```bash
  python scripts/benchmark_pruning.py
  ```
- **Commit Command**:
  ```bash
  git add scripts/benchmark_pruning.py
  git commit -m "perf(graph): add provenance graph pruning latency benchmark script"
  git push origin main
  ```

---

### Day 12: Forensic Documentation - Linux Cron Persistence Dossier

- **Objective**: Generate a live forensic evidence markdown report (`docs/evidence/LINUX_CRON_DESC_DOSSIER.md`) documenting the provenance chain, transpiled Sigma/SPL/KQL, and DESC ISR audit for `T1053.003`.
- **Files to Create**:
  - `docs/evidence/LINUX_CRON_DESC_DOSSIER.md`
- **Commit Command**:
  ```bash
  git add docs/evidence/LINUX_CRON_DESC_DOSSIER.md
  git commit -m "docs(evidence): publish Linux cron persistence live forensic dossier"
  git push origin main
  ```

---

### Day 13: Detection Quality - Multi-Engine Transpiler Validator

- **Objective**: Create `scripts/validate_rules.py` verifying generated Sigma v2.0 YAML conforms to official Sigma specifications and that transpiled Splunk SPL and Sentinel KQL contain balanced parentheses and valid operators.
- **Files to Create**:
  - `scripts/validate_rules.py`
  - `tests/test_transpiler_syntax.py`
- **Commit Command**:
  ```bash
  git add scripts/validate_rules.py tests/test_transpiler_syntax.py
  git commit -m "test(detection): add automated Splunk SPL and Sentinel KQL syntax validator"
  git push origin main
  ```

---

### Day 14: Release Milestone - S-TCAI v1.1.0 Release & CHANGELOG

- **Objective**: Bump version in `pyproject.toml` to `1.1.0`, finalize `CHANGELOG.md` with the 14-day enhancement sprint accomplishments, and create a git release tag.
- **Files to Modify**:
  - `pyproject.toml`: Version `1.1.0`
  - `CHANGELOG.md`: Detailed changelog entries for v1.1.0
- **Commands**:
  ```bash
  git add pyproject.toml CHANGELOG.md
  git commit -m "chore(release): cut S-TCAI v1.1.0 with expanded DESC ISR detection catalog"
  git tag -a v1.1.0 -m "S-TCAI v1.1.0 - Expanded DESC ISR Catalog & Detection Engineering Suite"
  git push origin main --tags
  ```

---

## Daily 10-Minute Execution Protocol

For each day:
1. Open terminal in `C:\Users\G14\Desktop\ANTIGRAVITY\sovereign-triage-ai`.
2. Apply the day's code modification.
3. Run the automated test suite:
   ```bash
   pytest tests/ -v
   ```
4. Commit and push:
   ```bash
   git add <modified files>
   git commit -m "<conventional commit message>"
   git push origin main
   ```
5. Confirm GitHub Actions CI passes green:
   ```bash
   gh run watch
   ```
