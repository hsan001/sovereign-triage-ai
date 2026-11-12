from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set

import networkx as nx

from stcai.schemas.telemetry import (
    EventCategory,
    NormalizedTelemetryEvent,
)

POWERSHELL_ENC_REGEX = re.compile(
    r"(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)

SUSPICIOUS_CMD_PATTERNS = re.compile(
    r"(-nop|-w\s+hidden|-windowstyle\s+hidden|import\s+pty|/dev/tcp/|nc\s+-e|curl\s+.*\|\s*(?:ba)?sh|chmod\s+\+s|whoami|mimikatz|sekurlsa)",
    re.IGNORECASE,
)

SUSPICIOUS_FILE_PATTERNS = re.compile(
    r"(\\users\\public\\|\\appdata\\local\\temp\\|/tmp/|/dev/shm/|/etc/shadow|/etc/sudoers|\.ps1$|\.vbs$|\.bat$|\.elf$)",
    re.IGNORECASE,
)


class NodeType(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"


@dataclass(frozen=True)
class GraphPruningMetrics:
    total_nodes_before: int
    retained_nodes_after: int
    pruned_nodes_count: int
    reduction_percentage: float
    high_signal_seed_count: int
    cycles_broken: int


class ProvenanceGraphEngine:
    """
    Module 2: Causal Provenance Graph & Bi-Directional Ancestral Noise-Pruning Engine.
    Aligned with DESC ISR v2.0 Domain 4 (Incident & Problem Management / Root-Cause Analysis)
    and Domain 6 (Tamper-Evident Audit Trail Continuity).
    """

    def __init__(self, risk_threshold: int = 30) -> None:
        self.risk_threshold = risk_threshold
        self.graph: nx.DiGraph = nx.DiGraph()
        self._cycles_broken: int = 0
        self._cycle_counter: int = 0
        self._last_pruning_metrics: Optional[GraphPruningMetrics] = None

    @property
    def cycles_broken(self) -> int:
        return self._cycles_broken

    @property
    def last_pruning_metrics(self) -> Optional[GraphPruningMetrics]:
        return self._last_pruning_metrics

    def ingest_events(self, events: Iterable[NormalizedTelemetryEvent]) -> nx.DiGraph:
        sorted_events = sorted(events, key=lambda e: e.timestamp_utc)
        for evt in sorted_events:
            self.add_event(evt)
        return self.graph

    def add_event(self, evt: NormalizedTelemetryEvent) -> str:
        proc_node_id = f"proc:{evt.process.entity_uid}"
        decoded_b64 = self._try_decode_powershell_b64(evt.process.command_line)
        event_risk, risk_reasons = self._score_event(evt, decoded_b64)

        self._upsert_process_node(
            node_id=proc_node_id,
            evt=evt,
            decoded_command=decoded_b64,
            risk_score=event_risk,
            risk_reasons=risk_reasons,
        )

        if evt.process.parent_entity_uid:
            parent_node_id = f"proc:{evt.process.parent_entity_uid}"
            if parent_node_id not in self.graph:
                self.graph.add_node(
                    parent_node_id,
                    node_type=NodeType.PROCESS.value,
                    entity_uid=evt.process.parent_entity_uid,
                    pid=evt.process.ppid,
                    executable=evt.process.parent_executable or "unknown_parent",
                    command_line=evt.process.parent_command_line,
                    decoded_command_line=self._try_decode_powershell_b64(evt.process.parent_command_line),
                    hostname=evt.host.hostname,
                    os_family=evt.host.os_family,
                    asset_criticality=evt.host.asset_criticality,
                    effective_user=evt.user.effective_user,
                    login_uid=evt.user.login_uid,
                    first_seen_utc=evt.timestamp_utc.isoformat(),
                    last_seen_utc=evt.timestamp_utc.isoformat(),
                    risk_score=0,
                    risk_reasons=[],
                    evidence_sha256_list=[],
                    mitre_tags=[],
                )
            proc_node_id = self._add_causal_edge_dag_safe(
                source_id=parent_node_id,
                target_id=proc_node_id,
                relation="SPAWNED",
                evt=evt,
            )

        if evt.category == EventCategory.NETWORK_CONNECTION and evt.network is not None:
            net_node_id = (
                f"net:{evt.network.destination_ip}:{evt.network.destination_port}/{evt.network.protocol}"
            )
            if net_node_id not in self.graph:
                self.graph.add_node(
                    net_node_id,
                    node_type=NodeType.NETWORK.value,
                    destination_ip=str(evt.network.destination_ip),
                    destination_port=evt.network.destination_port,
                    protocol=evt.network.protocol,
                    initiated_outbound=evt.network.initiated_outbound,
                    first_seen_utc=evt.timestamp_utc.isoformat(),
                    last_seen_utc=evt.timestamp_utc.isoformat(),
                    risk_score=max(40, event_risk),
                    risk_reasons=list(set(risk_reasons + ["outbound_network_connection"])),
                    evidence_sha256_list=[evt.integrity.raw_payload_sha256],
                )
            else:
                self._merge_node_metadata(net_node_id, evt, event_risk, risk_reasons)

            self._add_causal_edge_dag_safe(
                source_id=proc_node_id,
                target_id=net_node_id,
                relation="CONNECTED_TO",
                evt=evt,
            )

        if evt.category == EventCategory.FILE_ACTIVITY and evt.file is not None:
            norm_path = evt.file.target_filename.strip()
            file_node_id = f"file:{evt.host.hostname}:{norm_path}"
            if file_node_id not in self.graph:
                self.graph.add_node(
                    file_node_id,
                    node_type=NodeType.FILE.value,
                    target_filename=norm_path,
                    operation=evt.file.operation,
                    inode=evt.file.inode,
                    mode_octal=evt.file.mode_octal,
                    hostname=evt.host.hostname,
                    first_seen_utc=evt.timestamp_utc.isoformat(),
                    last_seen_utc=evt.timestamp_utc.isoformat(),
                    risk_score=event_risk,
                    risk_reasons=list(risk_reasons),
                    evidence_sha256_list=[evt.integrity.raw_payload_sha256],
                )
            else:
                self._merge_node_metadata(file_node_id, evt, event_risk, risk_reasons)

            self._add_causal_edge_dag_safe(
                source_id=proc_node_id,
                target_id=file_node_id,
                relation=f"FILE_{evt.file.operation.upper()}",
                evt=evt,
            )

        return proc_node_id

    def _upsert_process_node(
        self,
        node_id: str,
        evt: NormalizedTelemetryEvent,
        decoded_command: Optional[str],
        risk_score: int,
        risk_reasons: List[str],
    ) -> None:
        ts_iso = evt.timestamp_utc.isoformat()
        if node_id not in self.graph:
            mitre_tags = [evt.integrity.mitre_rule_tag] if evt.integrity.mitre_rule_tag else []
            self.graph.add_node(
                node_id,
                node_type=NodeType.PROCESS.value,
                entity_uid=evt.process.entity_uid,
                pid=evt.process.pid,
                ppid=evt.process.ppid,
                executable=evt.process.executable,
                command_line=evt.process.command_line,
                decoded_command_line=decoded_command,
                working_directory=evt.process.working_directory,
                sha256_hash=evt.process.sha256_hash,
                hostname=evt.host.hostname,
                os_family=evt.host.os_family,
                asset_criticality=evt.host.asset_criticality,
                effective_user=evt.user.effective_user,
                login_uid=evt.user.login_uid,
                privilege_level=evt.user.privilege_level,
                first_seen_utc=ts_iso,
                last_seen_utc=ts_iso,
                risk_score=risk_score,
                risk_reasons=list(dict.fromkeys(risk_reasons)),
                evidence_sha256_list=[evt.integrity.raw_payload_sha256],
                mitre_tags=mitre_tags,
            )
        else:
            node_data = self.graph.nodes[node_id]
            if node_data.get("executable") == "unknown_parent" and evt.process.executable:
                node_data["executable"] = evt.process.executable
            if not node_data.get("command_line") and evt.process.command_line:
                node_data["command_line"] = evt.process.command_line
            if not node_data.get("decoded_command_line") and decoded_command:
                node_data["decoded_command_line"] = decoded_command
            if not node_data.get("sha256_hash") and evt.process.sha256_hash:
                node_data["sha256_hash"] = evt.process.sha256_hash
            self._merge_node_metadata(node_id, evt, risk_score, risk_reasons)

    def _merge_node_metadata(
        self,
        node_id: str,
        evt: NormalizedTelemetryEvent,
        risk_score: int,
        risk_reasons: List[str],
    ) -> None:
        node_data = self.graph.nodes[node_id]
        ts_iso = evt.timestamp_utc.isoformat()
        if ts_iso < node_data.get("first_seen_utc", ts_iso):
            node_data["first_seen_utc"] = ts_iso
        if ts_iso > node_data.get("last_seen_utc", ts_iso):
            node_data["last_seen_utc"] = ts_iso

        node_data["risk_score"] = min(100, max(node_data.get("risk_score", 0), risk_score))
        existing_reasons = node_data.get("risk_reasons", [])
        for r in risk_reasons:
            if r not in existing_reasons:
                existing_reasons.append(r)
        node_data["risk_reasons"] = existing_reasons

        ev_list = node_data.get("evidence_sha256_list", [])
        if evt.integrity.raw_payload_sha256 not in ev_list:
            ev_list.append(evt.integrity.raw_payload_sha256)
        node_data["evidence_sha256_list"] = ev_list

        if evt.integrity.mitre_rule_tag:
            tags = node_data.get("mitre_tags", [])
            if evt.integrity.mitre_rule_tag not in tags:
                tags.append(evt.integrity.mitre_rule_tag)
            node_data["mitre_tags"] = tags

    def _add_causal_edge_dag_safe(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        evt: NormalizedTelemetryEvent,
    ) -> str:
        """
        Enforces strict Directed Acyclic Graph (DAG) invariants.
        If adding source_id -> target_id would create a self-loop or closed cycle
        (e.g., due to OS PID reuse), mints a versioned target node ID so causal
        chronology remains strictly acyclic without losing forensic telemetry.
        """
        actual_target_id = target_id
        if source_id == target_id or (
            source_id in self.graph
            and target_id in self.graph
            and nx.has_path(self.graph, target_id, source_id)
        ):
            self._cycles_broken += 1
            self._cycle_counter += 1
            actual_target_id = f"{target_id}#cycle_{self._cycle_counter}"
            orig_attrs = dict(self.graph.nodes[target_id]) if target_id in self.graph else {}
            orig_attrs["cycle_split_from"] = target_id
            self.graph.add_node(actual_target_id, **orig_attrs)

        ts_iso = evt.timestamp_utc.isoformat()
        if self.graph.has_edge(source_id, actual_target_id):
            edge_data = self.graph.edges[source_id, actual_target_id]
            edge_data["event_count"] = edge_data.get("event_count", 1) + 1
            if ts_iso > edge_data.get("last_timestamp_utc", ts_iso):
                edge_data["last_timestamp_utc"] = ts_iso
        else:
            self.graph.add_edge(
                source_id,
                actual_target_id,
                relation=relation,
                category=evt.category.value,
                first_timestamp_utc=ts_iso,
                last_timestamp_utc=ts_iso,
                event_count=1,
                source_event_id=evt.source_event_id,
            )
        return actual_target_id

    @classmethod
    def _score_event(
        cls,
        evt: NormalizedTelemetryEvent,
        decoded_b64: Optional[str],
    ) -> tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        cmd = f"{evt.process.command_line or ''} {decoded_b64 or ''}".strip()
        if decoded_b64:
            score += 50
            reasons.append("encoded_powershell_payload")

        if cmd and SUSPICIOUS_CMD_PATTERNS.search(cmd):
            score += 45
            reasons.append("suspicious_command_pattern")

        if evt.category == EventCategory.NETWORK_CONNECTION and evt.network is not None:
            score += 40
            reasons.append("network_egress_activity")

        if evt.category == EventCategory.FILE_ACTIVITY and evt.file is not None:
            if SUSPICIOUS_FILE_PATTERNS.search(evt.file.target_filename):
                score += 40
                reasons.append("suspicious_file_staging_path")
            elif evt.file.operation in ("delete", "chmod"):
                score += 30
                reasons.append(f"sensitive_file_op_{evt.file.operation}")

        if evt.category == EventCategory.PRIVILEGE_CHANGE:
            score += 55
            reasons.append("privilege_boundary_change")

        if (
            evt.user.effective_user == "root"
            and evt.user.login_uid is not None
            and evt.user.login_uid not in ("0", "root")
        ):
            score += 50
            reasons.append(f"linux_auid_privilege_escalation(auid={evt.user.login_uid}->root)")

        if evt.integrity.mitre_rule_tag:
            score += 35
            reasons.append(f"mitre_tag:{evt.integrity.mitre_rule_tag}")

        return min(100, score), reasons

    @staticmethod
    def _try_decode_powershell_b64(command_line: Optional[str]) -> Optional[str]:
        if not command_line:
            return None
        match = POWERSHELL_ENC_REGEX.search(command_line)
        if not match:
            return None
        b64_token = match.group(1).strip()
        try:
            raw_bytes = base64.b64decode(b64_token, validate=False)
            # PowerShell -EncodedCommand uses UTF-16LE by default; fallback to UTF-8 if no null bytes
            if b"\x00" in raw_bytes:
                decoded = raw_bytes.decode("utf-16le", errors="replace").strip()
            else:
                decoded = raw_bytes.decode("utf-8", errors="replace").strip()
            return decoded if decoded else None
        except (ValueError, Exception):
            return None

    def prune_benign_noise(self, min_risk_score: Optional[int] = None) -> nx.DiGraph:
        """
        Bi-Directional Ancestral Reachability Filter:
        Retains every seed node with risk_score >= threshold PLUS all of its
        causal ancestors (root-cause entry point) and all of its descendants
        (post-exploitation child processes, files, and network sockets).
        Removes all disconnected benign background trees.
        """
        threshold = self.risk_threshold if min_risk_score is None else min_risk_score
        total_before = self.graph.number_of_nodes()

        seed_nodes: Set[str] = {
            n
            for n, attr in self.graph.nodes(data=True)
            if attr.get("risk_score", 0) >= threshold
        }

        keep_nodes: Set[str] = set(seed_nodes)
        for seed in seed_nodes:
            keep_nodes.update(nx.ancestors(self.graph, seed))
            keep_nodes.update(nx.descendants(self.graph, seed))

        nodes_to_remove = set(self.graph.nodes()) - keep_nodes
        self.graph.remove_nodes_from(nodes_to_remove)

        retained_after = self.graph.number_of_nodes()
        pruned_count = total_before - retained_after
        reduction_pct = round((pruned_count / total_before) * 100.0, 2) if total_before > 0 else 0.0

        self._last_pruning_metrics = GraphPruningMetrics(
            total_nodes_before=total_before,
            retained_nodes_after=retained_after,
            pruned_nodes_count=pruned_count,
            reduction_percentage=reduction_pct,
            high_signal_seed_count=len(seed_nodes),
            cycles_broken=self._cycles_broken,
        )
        return self.graph

    def to_llm_context_dict(self) -> Dict[str, Any]:
        """
        Serializes the pruned DAG in strict topological order for Module 3
        (Air-Gapped Local LLM Triage) and Module 5 (DESC ISR Compliance Auditor).
        """
        if not nx.is_directed_acyclic_graph(self.graph):
            raise RuntimeError("Provenance graph violated DAG invariant prior to LLM serialization")

        ordered_node_ids = list(nx.topological_sort(self.graph))
        serialized_nodes: List[Dict[str, Any]] = []
        all_evidence_hashes: List[str] = []

        for nid in ordered_node_ids:
            attrs = dict(self.graph.nodes[nid])
            attrs["node_id"] = nid
            serialized_nodes.append(attrs)
            for h in attrs.get("evidence_sha256_list", []):
                if h not in all_evidence_hashes:
                    all_evidence_hashes.append(h)

        serialized_edges: List[Dict[str, Any]] = []
        for u, v, e_attrs in self.graph.edges(data=True):
            edge_entry = {"source": u, "target": v}
            edge_entry.update(e_attrs)
            serialized_edges.append(edge_entry)

        root_nodes = [n for n in ordered_node_ids if self.graph.in_degree(n) == 0]

        metrics_dict = (
            {
                "total_nodes_before": self._last_pruning_metrics.total_nodes_before,
                "retained_nodes_after": self._last_pruning_metrics.retained_nodes_after,
                "pruned_nodes_count": self._last_pruning_metrics.pruned_nodes_count,
                "reduction_percentage": self._last_pruning_metrics.reduction_percentage,
                "high_signal_seed_count": self._last_pruning_metrics.high_signal_seed_count,
                "cycles_broken": self._last_pruning_metrics.cycles_broken,
            }
            if self._last_pruning_metrics
            else None
        )

        return {
            "dag_verified": True,
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "root_entry_nodes": root_nodes,
            "pruning_metrics": metrics_dict,
            "topological_nodes": serialized_nodes,
            "causal_edges": serialized_edges,
            "desc_isr_domain6_evidence_hashes": all_evidence_hashes,
        }

    def to_mermaid(self) -> str:
        """
        Exports the causal provenance DAG as a Mermaid flowchart (`graph TD`)
        for GitHub README evidence visualization and incident reports.
        """
        lines = ["graph TD"]
        node_alias: Dict[str, str] = {}
        for idx, nid in enumerate(nx.topological_sort(self.graph), start=1):
            alias = f"N{idx}"
            node_alias[nid] = alias
            attrs = self.graph.nodes[nid]
            ntype = attrs.get("node_type", "process")
            risk = attrs.get("risk_score", 0)
            if ntype == NodeType.PROCESS.value:
                exe = str(attrs.get("executable", "proc")).replace('"', "'")
                pid = attrs.get("pid", "?")
                label = f"{exe} (PID:{pid} | Risk:{risk})"
                lines.append(f'    {alias}["{label}"]')
            elif ntype == NodeType.NETWORK.value:
                ip = attrs.get("destination_ip", "?")
                port = attrs.get("destination_port", "?")
                proto = attrs.get("protocol", "tcp")
                label = f"NET: {ip}:{port}/{proto}"
                lines.append(f'    {alias}(("{label}"))')
            elif ntype == NodeType.FILE.value:
                fname = str(attrs.get("target_filename", "file")).replace('"', "'")
                op = attrs.get("operation", "op")
                label = f"FILE ({op}): {fname}"
                lines.append(f'    {alias}[/"{label}"/]')

        for u, v, e_attrs in self.graph.edges(data=True):
            rel = e_attrs.get("relation", "LINK")
            lines.append(f"    {node_alias[u]} -->|{rel}| {node_alias[v]}")

        return "\n".join(lines)
