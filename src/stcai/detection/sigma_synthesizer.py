from __future__ import annotations

import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import yaml

from stcai.schemas.detection import SigmaLogSource, SynthesizedDetectionBundle
from stcai.schemas.triage import IncidentTriageReport, TriageVerdict

STCAI_SIGMA_NAMESPACE = uuid.UUID("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")


class SigmaRuleSynthesizer:
    """
    Module 4: Detection-as-Code Sigma Rule Synthesizer & Multi-SIEM Transpiler.
    Converts triaged causal DAG attack chains into validated Sigma YAML rules
    and transpiles them directly into Splunk SPL and Microsoft Sentinel KQL.
    """

    @classmethod
    def synthesize_from_triage(
        cls,
        triage_report: IncidentTriageReport,
        dag_context: Dict[str, Any],
    ) -> SynthesizedDetectionBundle:
        if triage_report.verdict == TriageVerdict.BENIGN:
            raise ValueError("Sigma synthesis is skipped for BENIGN triage verdicts.")

        nodes: List[Dict[str, Any]] = dag_context.get("topological_nodes", [])
        if not nodes:
            raise ValueError("Cannot synthesize Sigma rule from empty DAG context.")

        os_family = cls._detect_os_family(nodes)
        primary_proc_node = cls._select_primary_malicious_process(nodes)
        net_nodes = [n for n in nodes if n.get("node_type") == "network"]
        file_nodes = [n for n in nodes if n.get("node_type") == "file"]

        selection_process: Dict[str, Any] = {}
        if primary_proc_node:
            exe = primary_proc_node.get("executable")
            if exe and exe != "unknown_parent":
                selection_process["Image|endswith"] = cls._extract_basename(exe)

            parent_exe = cls._find_parent_executable(primary_proc_node["node_id"], dag_context)
            if parent_exe and parent_exe != "unknown_parent":
                selection_process["ParentImage|endswith"] = cls._extract_basename(parent_exe)

            cmd_tokens = cls._extract_high_signal_cmd_tokens(primary_proc_node)
            if cmd_tokens:
                selection_process["CommandLine|contains"] = cmd_tokens

            if primary_proc_node.get("sha256_hash"):
                selection_process["Hashes|contains"] = primary_proc_node["sha256_hash"]

        selection_network: Dict[str, Any] = {}
        if net_nodes:
            ips = sorted({str(n["destination_ip"]) for n in net_nodes if n.get("destination_ip")})
            ports = sorted({int(n["destination_port"]) for n in net_nodes if n.get("destination_port") is not None})
            if ips:
                selection_network["DestinationIp"] = ips if len(ips) > 1 else ips[0]
            if ports:
                selection_network["DestinationPort"] = ports if len(ports) > 1 else ports[0]

        selection_file: Dict[str, Any] = {}
        if file_nodes:
            fpaths = sorted({str(n["target_filename"]) for n in file_nodes if n.get("target_filename")})
            if fpaths:
                selection_file["TargetFilename|endswith"] = [cls._extract_basename(p) for p in fpaths]

        detection_block: Dict[str, Any] = {}
        condition_clauses: List[str] = []

        if selection_process:
            detection_block["selection_process"] = selection_process
            condition_clauses.append("selection_process")
        if selection_network:
            detection_block["selection_network"] = selection_network
            condition_clauses.append("selection_network")
        if selection_file:
            detection_block["selection_file"] = selection_file
            condition_clauses.append("selection_file")

        if not condition_clauses:
            detection_block["selection_fallback"] = {"CommandLine|contains": "suspicious"}
            condition_clauses.append("selection_fallback")

        if "selection_process" in condition_clauses and len(condition_clauses) > 1:
            aux = " or ".join(c for c in condition_clauses if c != "selection_process")
            detection_block["condition"] = f"selection_process or ({aux})"
        else:
            detection_block["condition"] = " or ".join(condition_clauses)

        rule_seed = f"{triage_report.root_cause_node_id}:{os_family}:{triage_report.severity.value}"
        rule_id = str(uuid.uuid5(STCAI_SIGMA_NAMESPACE, rule_seed))

        mitre_tags = sorted(
            {f"attack.{m.technique_id.lower()}" for m in triage_report.mitre_techniques}
        )
        desc_controls = [
            "DESC-ISR-D04.2 (Incident Detection & Triage)",
            "DESC-ISR-D06.3 (Operational Audit Logging)",
            "DESC-ISR-D08.4 (Automated Threat Signature Deployment)",
            "DESC-ISR-D13.1 (Sovereign On-Premises Execution)",
        ]
        all_tags = mitre_tags + ["desc_isr.domain_4", "desc_isr.domain_8", "stcai.autonomous"]

        logsource = SigmaLogSource(
            category="process_creation",
            product=os_family,
            service="sysmon" if os_family == "windows" else "auditd",
        )

        title = (
            f"S-TCAI Autonomous Detection: {os_family.capitalize()} Causal Attack Chain "
            f"({triage_report.root_cause_node_id})"
        )
        today_str = date.today().isoformat()

        sigma_dict: Dict[str, Any] = {
            "title": title,
            "id": rule_id,
            "status": "experimental",
            "description": triage_report.executive_summary,
            "author": "S-TCAI Autonomous Detection Engine (DESC ISR v2.0)",
            "date": today_str,
            "logsource": logsource.model_dump(exclude_none=True),
            "detection": detection_block,
            "falsepositives": [
                "Legitimate administrative maintenance scripts verified via change management"
            ],
            "level": triage_report.severity.value,
            "tags": all_tags,
        }

        sigma_yaml_str = yaml.safe_dump(sigma_dict, sort_keys=False, default_flow_style=False)
        splunk_query = cls.transpile_to_splunk_spl(os_family, detection_block)
        sentinel_query = cls.transpile_to_sentinel_kql(os_family, detection_block)

        return SynthesizedDetectionBundle(
            rule_id=rule_id,
            title=title,
            status="experimental",
            level=triage_report.severity.value,
            author="S-TCAI Autonomous Detection Engine (DESC ISR v2.0)",
            created_date=today_str,
            logsource=logsource,
            detection=detection_block,
            tags=all_tags,
            falsepositives=sigma_dict["falsepositives"],
            sigma_yaml=sigma_yaml_str,
            splunk_spl=splunk_query,
            sentinel_kql=sentinel_query,
            source_root_node_id=triage_report.root_cause_node_id,
            desc_isr_controls=desc_controls,
        )

    @classmethod
    def transpile_to_splunk_spl(cls, os_family: str, detection: Dict[str, Any]) -> str:
        source_filter = (
            'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
            if os_family == "windows"
            else 'sourcetype="linux:audit"'
        )
        sub_clauses: List[str] = []

        for sel_key, sel_body in detection.items():
            if sel_key == "condition" or not isinstance(sel_body, dict):
                continue
            field_exprs: List[str] = []
            for raw_field, val in sel_body.items():
                field_name = raw_field.split("|")[0]
                modifier = raw_field.split("|")[1] if "|" in raw_field else "exact"
                field_exprs.append(cls._format_splunk_field(field_name, modifier, val))
            if field_exprs:
                sub_clauses.append("(" + " AND ".join(field_exprs) + ")")

        where_block = " OR ".join(sub_clauses) if sub_clauses else 'CommandLine="*"'
        return f"index=* {source_filter} ({where_block}) | table _time host User Image ParentImage CommandLine DestinationIp DestinationPort TargetFilename"

    @classmethod
    def transpile_to_sentinel_kql(cls, os_family: str, detection: Dict[str, Any]) -> str:
        kql_field_map = {
            "Image": "FolderPath",
            "ParentImage": "InitiatingProcessFileName",
            "CommandLine": "ProcessCommandLine",
            "Hashes": "SHA256",
            "DestinationIp": "RemoteIP",
            "DestinationPort": "RemotePort",
            "TargetFilename": "FileName",
        }
        table_name = "DeviceProcessEvents"
        kql_groups: List[str] = []

        for sel_key, sel_body in detection.items():
            if sel_key == "condition" or not isinstance(sel_body, dict):
                continue
            exprs: List[str] = []
            for raw_field, val in sel_body.items():
                base_field = raw_field.split("|")[0]
                modifier = raw_field.split("|")[1] if "|" in raw_field else "exact"
                kql_col = kql_field_map.get(base_field, base_field)
                exprs.append(cls._format_kql_field(kql_col, modifier, val))
            if exprs:
                kql_groups.append("(" + " and ".join(exprs) + ")")

        where_clause = " or ".join(kql_groups) if kql_groups else "true"
        return (
            f"{table_name}\n"
            f"| where {where_clause}\n"
            f"| project TimeGenerated, DeviceName, AccountName, FolderPath, InitiatingProcessFileName, ProcessCommandLine, SHA256"
        )

    @staticmethod
    def _format_splunk_field(field_name: str, modifier: str, val: Any) -> str:
        def _esc(s: Any) -> str:
            return str(s).replace("\\", "\\\\").replace('"', '\\"')

        values = val if isinstance(val, list) else [val]
        parts: List[str] = []
        for item in values:
            escaped = _esc(item)
            if modifier == "endswith":
                parts.append(f'{field_name}="*{escaped}"')
            elif modifier == "contains":
                parts.append(f'{field_name}="*{escaped}*"')
            else:
                parts.append(f'{field_name}="{escaped}"')
        return "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]

    @staticmethod
    def _format_kql_field(kql_col: str, modifier: str, val: Any) -> str:
        def _esc(s: Any) -> str:
            return str(s).replace("'", "''")

        values = val if isinstance(val, list) else [val]
        parts: List[str] = []
        for item in values:
            if isinstance(item, int) and modifier == "exact":
                parts.append(f"{kql_col} == {item}")
                continue
            escaped = _esc(item)
            if modifier == "endswith":
                parts.append(f"{kql_col} endswith '{escaped}'")
            elif modifier == "contains":
                parts.append(f"{kql_col} has '{escaped}'")
            else:
                parts.append(f"{kql_col} =~ '{escaped}'")
        return "(" + " or ".join(parts) + ")" if len(parts) > 1 else parts[0]

    @staticmethod
    def _detect_os_family(nodes: List[Dict[str, Any]]) -> str:
        for n in nodes:
            if n.get("os_family") in ("windows", "linux"):
                return str(n["os_family"])
        return "windows"

    @staticmethod
    def _select_primary_malicious_process(nodes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        proc_nodes = [n for n in nodes if n.get("node_type") == "process"]
        if not proc_nodes:
            return None
        return max(proc_nodes, key=lambda n: int(n.get("risk_score", 0)))

    @staticmethod
    def _find_parent_executable(proc_node_id: str, dag_context: Dict[str, Any]) -> Optional[str]:
        nodes_by_id = {n["node_id"]: n for n in dag_context.get("topological_nodes", [])}
        for edge in dag_context.get("causal_edges", []):
            if edge.get("target") == proc_node_id and edge.get("relation") == "SPAWNED":
                parent_node = nodes_by_id.get(edge.get("source", ""))
                if parent_node and parent_node.get("executable"):
                    return str(parent_node["executable"])
        return None

    @staticmethod
    def _extract_basename(path_str: str) -> str:
        norm = path_str.strip().replace("\\", "/")
        return norm.split("/")[-1] if "/" in norm else norm

    @staticmethod
    def _extract_high_signal_cmd_tokens(proc_node: Dict[str, Any]) -> List[str]:
        raw_cmd = f"{proc_node.get('command_line') or ''} {proc_node.get('decoded_command_line') or ''}"
        candidate_keywords = [
            "-nop",
            "-w hidden",
            "-enc",
            "import pty",
            "/dev/tcp/",
            "nc -e",
            "webclient",
            "mimikatz",
            "sekurlsa",
            "REDACTED_ADVERSARIAL",
        ]
        found: List[str] = []
        lower_cmd = raw_cmd.lower()
        for kw in candidate_keywords:
            if kw.lower() in lower_cmd and kw not in found:
                found.append(kw)
        return found
