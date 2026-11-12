from __future__ import annotations

import binascii
import re
import socket
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from stcai.schemas.telemetry import (
    EventCategory,
    EventOutcome,
    FileActivityContext,
    HostContext,
    IntegrityMetadata,
    NetworkActivityContext,
    NormalizedTelemetryEvent,
    ProcessLineageContext,
    TelemetrySourceType,
    UserIdentityContext,
)

AUDIT_MSG_REGEX = re.compile(
    r"(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<body_kv>.*)"
)
KV_TOKEN_REGEX = re.compile(r'(\w+)=("[^"]*"|\S+)')
HEX_STRING_REGEX = re.compile(r"^[0-9A-Fa-f]+$")

SYSCALL_MAP: Dict[str, Tuple[str, EventCategory]] = {
    "59": ("execve", EventCategory.PROCESS_CREATION),
    "322": ("execveat", EventCategory.PROCESS_CREATION),
    "execve": ("execve", EventCategory.PROCESS_CREATION),
    "execveat": ("execveat", EventCategory.PROCESS_CREATION),
    "42": ("connect", EventCategory.NETWORK_CONNECTION),
    "connect": ("connect", EventCategory.NETWORK_CONNECTION),
    "2": ("open", EventCategory.FILE_ACTIVITY),
    "257": ("openat", EventCategory.FILE_ACTIVITY),
    "87": ("unlink", EventCategory.FILE_ACTIVITY),
    "263": ("unlinkat", EventCategory.FILE_ACTIVITY),
    "90": ("chmod", EventCategory.FILE_ACTIVITY),
    "open": ("open", EventCategory.FILE_ACTIVITY),
    "openat": ("openat", EventCategory.FILE_ACTIVITY),
    "unlink": ("unlink", EventCategory.FILE_ACTIVITY),
    "chmod": ("chmod", EventCategory.FILE_ACTIVITY),
    "105": ("setuid", EventCategory.PRIVILEGE_CHANGE),
    "101": ("ptrace", EventCategory.PRIVILEGE_CHANGE),
    "setuid": ("setuid", EventCategory.PRIVILEGE_CHANGE),
    "ptrace": ("ptrace", EventCategory.PRIVILEGE_CHANGE),
}


class SysmonNormalizer:
    SYSMON_CATEGORY_MAP: Dict[str, EventCategory] = {
        "1": EventCategory.PROCESS_CREATION,
        "3": EventCategory.NETWORK_CONNECTION,
        "8": EventCategory.PRIVILEGE_CHANGE,
        "10": EventCategory.PRIVILEGE_CHANGE,
        "11": EventCategory.FILE_ACTIVITY,
        "23": EventCategory.FILE_ACTIVITY,
    }

    @classmethod
    def parse_xml(
        cls,
        xml_str: str,
        asset_criticality: str = "standard",
        ingested_at: Optional[datetime] = None,
    ) -> NormalizedTelemetryEvent:
        root = ET.fromstring(xml_str.strip())
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        system_node = root.find("e:System", ns)
        if system_node is None:
            system_node = root.find("System")
        event_data_node = root.find("e:EventData", ns)
        if event_data_node is None:
            event_data_node = root.find("EventData")
        if system_node is None or event_data_node is None:
            raise ValueError("Invalid Sysmon XML: missing System or EventData block")

        def _sys_text(tag: str, default: str = "") -> str:
            el = system_node.find(f"e:{tag}", ns)
            if el is None:
                el = system_node.find(tag)
            return el.text.strip() if (el is not None and el.text) else default

        event_data: Dict[str, Any] = {}
        for data_el in event_data_node:
            name = data_el.attrib.get("Name")
            if name:
                event_data[name] = (data_el.text or "").strip()

        payload = {
            "EventID": _sys_text("EventID"),
            "Computer": _sys_text("Computer", "unknown-win-host"),
            "EventRecordID": _sys_text("EventRecordID", "0"),
            "EventData": event_data,
        }
        return cls.parse_dict(
            payload,
            asset_criticality=asset_criticality,
            raw_override=xml_str,
            ingested_at=ingested_at,
        )

    @classmethod
    def parse_dict(
        cls,
        record: Dict[str, Any],
        asset_criticality: str = "standard",
        raw_override: Optional[Union[str, Dict[str, Any]]] = None,
        ingested_at: Optional[datetime] = None,
    ) -> NormalizedTelemetryEvent:
        event_id = str(record.get("EventID") or record.get("event_id") or "").strip()
        if event_id not in cls.SYSMON_CATEGORY_MAP:
            raise ValueError(f"Unsupported Sysmon EventID: {event_id!r}")

        category = cls.SYSMON_CATEGORY_MAP[event_id]
        ed: Dict[str, Any] = record.get("EventData") or record.get("event_data") or record

        hostname = str(record.get("Computer") or record.get("host") or ed.get("Computer") or "unknown-win-host")
        utc_str = ed.get("UtcTime") or record.get("@timestamp")
        if not utc_str:
            raise ValueError("Sysmon record missing UtcTime / @timestamp")

        sha256_hash = cls._extract_sha256(ed.get("Hashes", ""))
        pid = int(ed.get("ProcessId") or ed.get("SourceProcessId") or 0)
        ppid = int(ed["ParentProcessId"]) if ed.get("ParentProcessId") is not None else None

        entity_uid = ed.get("ProcessGuid") or ed.get("SourceProcessGuid")
        if not entity_uid:
            entity_uid = NormalizedTelemetryEvent.build_synthetic_process_uid(hostname, pid, str(utc_str))

        parent_uid = ed.get("ParentProcessGuid")
        executable = ed.get("Image") or ed.get("SourceImage") or "unknown"

        network_ctx: Optional[NetworkActivityContext] = None
        if category == EventCategory.NETWORK_CONNECTION:
            proto = str(ed.get("Protocol", "tcp")).strip().lower()
            initiated = str(ed.get("Initiated", "true")).strip().lower() == "true"
            network_ctx = NetworkActivityContext(
                protocol=proto if proto in ("tcp", "udp", "icmp", "raw") else "unknown",
                source_ip=ed.get("SourceIp"),
                source_port=int(ed["SourcePort"]) if ed.get("SourcePort") else None,
                destination_ip=ed["DestinationIp"],
                destination_port=int(ed["DestinationPort"]),
                initiated_outbound=initiated,
            )

        file_ctx: Optional[FileActivityContext] = None
        if category == EventCategory.FILE_ACTIVITY:
            op = "delete" if event_id == "23" else "create"
            file_ctx = FileActivityContext(
                target_filename=ed["TargetFilename"],
                operation=op,
            )

        now_utc = ingested_at or datetime.now(timezone.utc)
        evt_ts = NormalizedTelemetryEvent.ensure_utc_timestamp(utc_str)
        drift = round((now_utc - evt_ts).total_seconds(), 3)
        raw_hash = NormalizedTelemetryEvent.compute_raw_sha256(raw_override if raw_override is not None else record)

        rule_tag = ed.get("RuleName")
        if rule_tag in ("-", ""):
            rule_tag = None

        return NormalizedTelemetryEvent(
            source_event_id=event_id,
            source_type=TelemetrySourceType.WINDOWS_SYSMON,
            category=category,
            outcome=EventOutcome.SUCCESS,
            timestamp_utc=evt_ts,
            host=HostContext(
                hostname=hostname,
                os_family="windows",
                asset_criticality=asset_criticality,
            ),
            user=UserIdentityContext(
                effective_user=ed.get("User", "SYSTEM"),
                login_uid=ed.get("LogonGuid") or ed.get("LogonId"),
                session_id=str(ed["TerminalSessionId"]) if ed.get("TerminalSessionId") is not None else None,
                privilege_level=ed.get("IntegrityLevel"),
            ),
            process=ProcessLineageContext(
                entity_uid=entity_uid,
                parent_entity_uid=parent_uid,
                pid=pid,
                ppid=ppid,
                executable=executable,
                command_line=ed.get("CommandLine"),
                parent_executable=ed.get("ParentImage"),
                parent_command_line=ed.get("ParentCommandLine"),
                working_directory=ed.get("CurrentDirectory"),
                sha256_hash=sha256_hash,
            ),
            network=network_ctx,
            file=file_ctx,
            integrity=IntegrityMetadata(
                ingested_at_utc=now_utc,
                raw_payload_sha256=raw_hash,
                clock_drift_seconds=drift,
                mitre_rule_tag=rule_tag,
            ),
        )

    @staticmethod
    def _extract_sha256(hashes_str: str) -> Optional[str]:
        if not hashes_str:
            return None
        for part in hashes_str.split(","):
            if part.strip().upper().startswith("SHA256="):
                candidate = part.split("=", 1)[1].strip().lower()
                if len(candidate) == 64:
                    return candidate
        return None


class AuditdNormalizer:
    def __init__(self, default_hostname: str = "linux-sovereign-node", asset_criticality: str = "standard") -> None:
        self.default_hostname = default_hostname
        self.asset_criticality = asset_criticality
        self._pid_uid_cache: Dict[Tuple[str, int], str] = {}
        self._pid_exe_cache: Dict[Tuple[str, int], str] = {}

    def parse_stream(
        self,
        lines: Iterable[str],
        ingested_at: Optional[datetime] = None,
    ) -> List[NormalizedTelemetryEvent]:
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            match = AUDIT_MSG_REGEX.match(line)
            if not match:
                continue
            node = (match.group("node") or self.default_hostname).strip().lower()
            epoch = match.group("epoch")
            serial = match.group("serial")
            rec_type = match.group("type")
            body_kv = match.group("body_kv")

            group_key = (node, f"{epoch}:{serial}")
            if group_key not in grouped:
                grouped[group_key] = {
                    "node": node,
                    "epoch": float(epoch),
                    "serial_id": f"{epoch}:{serial}",
                    "records": {},
                    "paths": [],
                    "raw_lines": [],
                }
            grouped[group_key]["raw_lines"].append(line)
            kv_dict = self._parse_kv_pairs(body_kv)
            if rec_type == "PATH":
                grouped[group_key]["paths"].append(kv_dict)
            else:
                grouped[group_key]["records"][rec_type] = kv_dict

        events: List[NormalizedTelemetryEvent] = []
        for group_data in grouped.values():
            if "SYSCALL" not in group_data["records"]:
                continue
            evt = self._build_event_from_group(group_data, ingested_at=ingested_at)
            if evt is not None:
                events.append(evt)
        return events

    def _build_event_from_group(
        self,
        group: Dict[str, Any],
        ingested_at: Optional[datetime] = None,
    ) -> Optional[NormalizedTelemetryEvent]:
        records = group["records"]
        syscall_rec = records["SYSCALL"]
        raw_syscall = str(syscall_rec.get("syscall", "")).strip()
        if raw_syscall not in SYSCALL_MAP:
            return None

        syscall_name, category = SYSCALL_MAP[raw_syscall]
        hostname = group["node"]
        pid = int(syscall_rec.get("pid", 0))
        ppid = int(syscall_rec["ppid"]) if "ppid" in syscall_rec else None
        exe = self._strip_or_decode(syscall_rec.get("exe", "unknown")) or "unknown"

        if category == EventCategory.PROCESS_CREATION or (hostname, pid) not in self._pid_uid_cache:
            entity_uid = NormalizedTelemetryEvent.build_synthetic_process_uid(
                hostname, pid, str(group["epoch"])
            )
            self._pid_uid_cache[(hostname, pid)] = entity_uid
            self._pid_exe_cache[(hostname, pid)] = exe
        else:
            entity_uid = self._pid_uid_cache[(hostname, pid)]

        parent_uid: Optional[str] = None
        parent_exe: Optional[str] = None
        if ppid is not None:
            parent_uid = self._pid_uid_cache.get(
                (hostname, ppid),
                NormalizedTelemetryEvent.build_synthetic_process_uid(hostname, ppid, "boot"),
            )
            parent_exe = self._pid_exe_cache.get((hostname, ppid))

        cmd_line = self._reconstruct_command_line(records)
        cwd = self._strip_or_decode(records.get("CWD", {}).get("cwd")) if "CWD" in records else None

        network_ctx: Optional[NetworkActivityContext] = None
        if category == EventCategory.NETWORK_CONNECTION:
            saddr_hex = records.get("SOCKADDR", {}).get("saddr", "")
            network_ctx = self._decode_sockaddr(saddr_hex)
            if network_ctx is None:
                return None

        file_ctx: Optional[FileActivityContext] = None
        if category == EventCategory.FILE_ACTIVITY:
            file_ctx = self._extract_file_context(syscall_name, group["paths"])
            if file_ctx is None:
                return None

        euid = int(syscall_rec.get("euid", syscall_rec.get("uid", 0)))
        effective_user = "root" if euid == 0 else f"uid_{euid}"
        outcome = (
            EventOutcome.SUCCESS
            if syscall_rec.get("success", "yes") == "yes"
            else EventOutcome.FAILURE
        )

        now_utc = ingested_at or datetime.now(timezone.utc)
        evt_ts = datetime.fromtimestamp(group["epoch"], tz=timezone.utc)
        drift = round((now_utc - evt_ts).total_seconds(), 3)
        raw_joined = "\n".join(group["raw_lines"])
        raw_hash = NormalizedTelemetryEvent.compute_raw_sha256(raw_joined)

        rule_key = self._strip_or_decode(syscall_rec.get("key"))
        if rule_key in ("(null)", "null", ""):
            rule_key = None

        return NormalizedTelemetryEvent(
            source_event_id=group["serial_id"],
            source_type=TelemetrySourceType.LINUX_AUDITD,
            category=category,
            outcome=outcome,
            timestamp_utc=evt_ts,
            host=HostContext(
                hostname=hostname,
                os_family="linux",
                asset_criticality=self.asset_criticality,
            ),
            user=UserIdentityContext(
                effective_user=effective_user,
                effective_uid=euid,
                login_uid=syscall_rec.get("auid"),
                session_id=syscall_rec.get("ses"),
                privilege_level="root" if euid == 0 else "user",
            ),
            process=ProcessLineageContext(
                entity_uid=entity_uid,
                parent_entity_uid=parent_uid,
                pid=pid,
                ppid=ppid,
                executable=exe,
                command_line=cmd_line,
                parent_executable=parent_exe,
                working_directory=cwd,
                syscall_name=syscall_name,
            ),
            network=network_ctx,
            file=file_ctx,
            integrity=IntegrityMetadata(
                ingested_at_utc=now_utc,
                raw_payload_sha256=raw_hash,
                clock_drift_seconds=drift,
                mitre_rule_tag=rule_key,
            ),
        )

    @classmethod
    def _reconstruct_command_line(cls, records: Dict[str, Dict[str, str]]) -> Optional[str]:
        if "EXECVE" in records:
            execve = records["EXECVE"]
            argc = int(execve.get("argc", 0))
            args: List[str] = []
            for i in range(argc):
                val = execve.get(f"a{i}")
                if val is not None:
                    args.append(cls._strip_or_decode(val) or "")
            if args:
                return " ".join(args)

        if "PROCTITLE" in records:
            raw_pt = records["PROCTITLE"].get("proctitle", "")
            return cls._strip_or_decode(raw_pt)
        return None

    @staticmethod
    def _strip_or_decode(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        val = value.strip()
        if val.startswith('"') and val.endswith('"'):
            return val[1:-1]
        if len(val) >= 4 and len(val) % 2 == 0 and HEX_STRING_REGEX.match(val):
            try:
                raw_bytes = binascii.unhexlify(val)
                decoded = raw_bytes.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                if all(32 <= ord(c) < 127 for c in decoded):
                    return decoded
            except (binascii.Error, ValueError):
                pass
        return val

    @staticmethod
    def _decode_sockaddr(saddr_hex: str) -> Optional[NetworkActivityContext]:
        cleaned = saddr_hex.strip().strip('"')
        if len(cleaned) < 16 or not HEX_STRING_REGEX.match(cleaned):
            return None
        try:
            raw = binascii.unhexlify(cleaned)
            family = struct.unpack("<H", raw[0:2])[0]
            if family == socket.AF_INET and len(raw) >= 8:
                port = struct.unpack(">H", raw[2:4])[0]
                ip_str = socket.inet_ntop(socket.AF_INET, raw[4:8])
                return NetworkActivityContext(
                    protocol="tcp",
                    destination_ip=ip_str,
                    destination_port=port,
                    initiated_outbound=True,
                )
            if family == socket.AF_INET6 and len(raw) >= 24:
                port = struct.unpack(">H", raw[2:4])[0]
                ip_str = socket.inet_ntop(socket.AF_INET6, raw[8:24])
                return NetworkActivityContext(
                    protocol="tcp",
                    destination_ip=ip_str,
                    destination_port=port,
                    initiated_outbound=True,
                )
        except (binascii.Error, struct.error, OSError, ValueError):
            return None
        return None

    @classmethod
    def _extract_file_context(
        cls, syscall_name: str, paths: List[Dict[str, str]]
    ) -> Optional[FileActivityContext]:
        if not paths:
            return None
        chosen = paths[-1]
        for p in paths:
            if p.get("nametype") in ("NORMAL", "CREATE", "DELETE"):
                chosen = p
                break
        filename = cls._strip_or_decode(chosen.get("name"))
        if not filename:
            return None
        op_map = {"unlink": "delete", "unlinkat": "delete", "chmod": "chmod"}
        op = op_map.get(syscall_name, "open")
        if chosen.get("nametype") == "CREATE":
            op = "create"
        inode = int(chosen["inode"]) if chosen.get("inode", "").isdigit() else None
        return FileActivityContext(
            target_filename=filename,
            operation=op,
            inode=inode,
            mode_octal=chosen.get("mode"),
        )

    @staticmethod
    def _parse_kv_pairs(body: str) -> Dict[str, str]:
        return {m.group(1): m.group(2) for m in KV_TOKEN_REGEX.finditer(body)}
