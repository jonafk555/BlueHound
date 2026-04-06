"""Log ingestion and normalization engine for BlueHound."""
import json, csv, re, hashlib, uuid
from pathlib import Path
from datetime import datetime
# VULN-10: use defusedxml to prevent XXE attacks in uploaded XML files
try:
    import defusedxml.ElementTree as ET
except ImportError:  # fallback (Python 3.8+ stdlib is partially defused)
    from xml.etree import ElementTree as ET
from typing import List, Dict, Any

# Canonical field names for the six-dimension schema
CANONICAL_FIELDS = {
    # Meta & Temporal
    "timestamp": ["Timestamp", "TimeCreated", "UtcTime", "@timestamp", "EventTime", "time", "date_time"],
    "event_id": ["EventID", "event_id", "EventCode", "event.code"],
    "provider": ["Provider", "ProviderName", "Channel", "source", "SourceName"],
    "hostname": ["HostName", "Computer", "ComputerName", "host", "host.name", "MachineName"],
    "host_ip": ["HostIP", "host.ip", "IpAddress"],
    # Process Execution
    "process_guid": ["ProcessGuid", "ProcessId", "process.entity_id", "EntityId"],
    "parent_process_guid": ["ParentProcessGuid", "ParentProcessId", "process.parent.entity_id"],
    "process_name": ["ProcessName", "Image", "process.name", "NewProcessName", "FileName"],
    "process_path": ["ProcessPath", "Image", "process.executable", "NewProcessName"],
    "parent_process_name": ["ParentImage", "ParentProcessName", "ParentCommandLine", "process.parent.name"],
    "commandline": ["CommandLine", "command_line", "process.command_line", "cmdline", "ProcessCommandLine"],
    "parent_commandline": ["ParentCommandLine", "parent_command_line", "process.parent.command_line"],
    "hashes": ["Hashes", "hash", "file.hash", "SHA256", "MD5"],
    "user_name": ["UserName", "User", "SubjectUserName", "TargetUserName", "user.name", "AccountName"],
    "user_sid": ["UserSID", "SubjectUserSid", "TargetUserSid", "user.id"],
    "logon_id": ["LogonId", "SubjectLogonId", "TargetLogonId", "LogonID"],
    "logon_type": ["LogonType", "logon_type"],
    # Network
    "source_ip": ["SourceIp", "SourceAddress", "IpAddress", "source.ip", "src_ip"],
    "source_port": ["SourcePort", "source.port", "src_port"],
    "destination_ip": ["DestinationIp", "DestinationAddress", "destination.ip", "dst_ip", "RemoteIP"],
    "destination_port": ["DestinationPort", "destination.port", "dst_port", "RemotePort"],
    "protocol": ["Protocol", "network.protocol", "TransportProtocol"],
    "initiating_process_guid": ["InitiatingProcessGuid", "ProcessGuid"],
    # File & Persistence
    "target_object": ["TargetObject", "TargetFilename", "ObjectName", "file.path"],
    "action_type": ["ActionType", "EventType", "event.action", "AccessMask"],
    "details": ["Details", "NewValue", "registry.value"],
    # Labels
    "label": ["Label", "label", "classification"],
    "mitre_technique_id": ["MITRE_TechniqueId", "mitre", "technique_id", "rule.mitre.id"],
    "attack_scenario": ["AttackScenario", "scenario", "campaign"],
    # Active Directory (EID 4662 / DCSync)
    "properties": ["Properties", "AccessProperties", "SubjectUserSid"],
    "object_guid": ["ObjectGuid", "ObjectName", "SubjectDomainName"],
    "access_mask": ["AccessMask", "access_mask"],
    "object_type": ["ObjectType", "object_type"],
}


class LogIngester:
    """Parses JSON, CSV, XML log files and normalizes to canonical schema."""

    def parse_file(self, filepath: str, fmt: str) -> List[Dict[str, Any]]:
        if fmt == ".json":
            return self._parse_json(filepath)
        elif fmt == ".csv":
            return self._parse_csv(filepath)
        elif fmt == ".xml":
            return self._parse_xml(filepath)
        elif fmt == ".log":
            return self._parse_log(filepath)
        return []

    def _parse_json(self, filepath: str) -> List[Dict]:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            raw = raw.get("Events", raw.get("events", raw.get("records", [raw])))
        return [self._normalize(ev) for ev in raw]

    def _parse_csv(self, filepath: str) -> List[Dict]:
        events = []
        with open(filepath, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(self._normalize(dict(row)))
        return events

    def _parse_xml(self, filepath: str) -> List[Dict]:
        events = []
        tree = ET.parse(filepath)
        root = tree.getroot()
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        for event_el in root.findall(".//ns:Event", ns) or root.findall(".//Event"):
            flat = {}
            for child in event_el.iter():
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child.text and child.text.strip():
                    flat[tag] = child.text.strip()
                for attr_k, attr_v in child.attrib.items():
                    flat[f"{tag}_{attr_k}"] = attr_v
            events.append(self._normalize(flat))
        if not events:
            flat = {}
            for child in root.iter():
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child.text and child.text.strip():
                    flat[tag] = child.text.strip()
                for attr_k, attr_v in child.attrib.items():
                    flat[f"{tag}_{attr_k}"] = attr_v
            if flat:
                events.append(self._normalize(flat))
        return events

    def _parse_log(self, filepath: str) -> List[Dict]:
        events = []
        with open(filepath, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    events.append(self._normalize(ev))
                except json.JSONDecodeError:
                    events.append(self._normalize({"raw": line, "Timestamp": datetime.utcnow().isoformat()}))
        return events

    def _normalize(self, raw: Dict) -> Dict:
        """Map raw fields to canonical schema."""
        norm = {"_raw": raw}
        for canon, aliases in CANONICAL_FIELDS.items():
            for alias in aliases:
                if alias in raw and raw[alias]:
                    val = raw[alias]
                    if canon == "event_id":
                        try:
                            val = int(val)
                        except (ValueError, TypeError):
                            pass
                    norm[canon] = val
                    break
        # Generate process_guid if missing
        if "process_guid" not in norm:
            seed = f"{norm.get('hostname','')}-{norm.get('process_name','')}-{norm.get('timestamp','')}-{norm.get('commandline','')}"
            norm["process_guid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
        if "parent_process_guid" not in norm and norm.get("parent_process_name"):
            seed = f"{norm.get('hostname','')}-{norm.get('parent_process_name','')}-parent"
            norm["parent_process_guid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
        # Extract process name from path — use ntpath for Windows paths on any OS
        import ntpath
        if "process_name" not in norm and "process_path" in norm:
            norm["process_name"] = ntpath.basename(norm["process_path"])
        if "parent_process_name" in norm and ("\\" in str(norm["parent_process_name"]) or "/" in str(norm["parent_process_name"])):
            full = norm["parent_process_name"]
            norm["parent_process_path"] = full
            norm["parent_process_name"] = ntpath.basename(full)
        if "process_name" in norm and ("\\" in str(norm["process_name"]) or "/" in str(norm["process_name"])):
            pn = norm["process_name"]
            norm["process_path"] = pn
            norm["process_name"] = ntpath.basename(pn)
        return norm

    def extract_facets(self, events: List[Dict]) -> Dict[str, List]:
        """Extract unique values for each filterable field (for dropdown selectors)."""
        facet_fields = ["source_ip", "destination_ip", "hostname", "process_name",
                        "parent_process_name", "user_name", "event_id", "provider",
                        "protocol", "logon_type"]
        facets = {f: set() for f in facet_fields}
        for ev in events:
            for f in facet_fields:
                v = ev.get(f)
                if v is not None and str(v).strip():
                    facets[f].add(str(v))
        return {k: sorted(list(v)) for k, v in facets.items()}
