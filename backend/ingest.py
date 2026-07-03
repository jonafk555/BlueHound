"""Log ingestion and normalization engine for BlueHound."""
import json, csv, re, hashlib, uuid, os, ntpath
from pathlib import Path
from datetime import datetime

from time_utils import parse_ts
# VULN-10: use defusedxml to prevent XXE attacks in uploaded XML files
try:
    import defusedxml.ElementTree as ET
except ImportError:  # fallback (Python 3.8+ stdlib is partially defused)
    from xml.etree import ElementTree as ET
from typing import List, Dict, Any
import logging

logger = logging.getLogger("bluehound.ingest")

# Large-file thresholds
LARGE_FILE_BYTES = 50 * 1024 * 1024  # 50 MB — switch to streaming mode above this
# Default aligned with main.MAX_PARSED_EVENTS. Two different defaults for the
# same env var used to be a latent trap — when main didn't pass max_events the
# ingester silently accepted 3× more events than the API caller expected.
DEFAULT_MAX_EVENTS = int(os.getenv("BLUEHOUND_MAX_PARSED_EVENTS", "50000"))
JSON_READ_CHUNK = 1024 * 1024

# Increase CSV field size limit for large log exports (default 128KB is too small)
csv.field_size_limit(10 * 1024 * 1024)  # 10 MB per field

# Canonical field names for the six-dimension schema
CANONICAL_FIELDS = {
    # Meta & Temporal
    "timestamp": ["Timestamp", "timestamp", "TimeCreated", "UtcTime", "@timestamp", "EventTime", "time", "date_time", "event.created"],
    "event_id": ["EventID", "event_id", "EventCode", "event.code"],
    "provider": ["Provider", "ProviderName", "Channel", "source", "SourceName", "data_stream.dataset", "event.dataset", "event.module"],
    "hostname": ["HostName", "hostname", "Computer", "ComputerName", "agent.hostname", "agent.name", "host.hostname", "host.name", "host", "MachineName"],
    "host_ip": ["HostIP", "host.ip", "IpAddress", "source.address"],
    # Process Execution
    # NOTE: SourceProcessGUID / SourceImage are last-priority aliases so they only
    # populate for Sysmon EID 10/8 (ProcessAccess / CreateRemoteThread) events,
    # where the *source* (accessing/injecting) process is the actor of interest.
    "process_guid": ["ProcessGuid", "ProcessId", "process.entity_id", "EntityId", "process.pid", "SourceProcessGUID", "SourceProcessGuid"],
    "parent_process_guid": ["ParentProcessGuid", "ParentProcessId", "process.parent.entity_id"],
    "process_name": ["ProcessName", "process_name", "Image", "process.name", "NewProcessName", "FileName", "SourceImage"],
    "process_path": ["ProcessPath", "Image", "process.executable", "NewProcessName", "SourceImage"],
    "parent_process_name": ["ParentImage", "ParentProcessName", "parent_process", "ParentCommandLine", "process.parent.name"],
    "commandline": ["CommandLine", "command_line", "process.command_line", "cmdline", "ProcessCommandLine"],
    "parent_commandline": ["ParentCommandLine", "parent_command_line", "process.parent.command_line"],
    "hashes": ["Hashes", "hash", "file.hash", "SHA256", "MD5"],
    "user_name": ["UserName", "User", "user", "account", "SubjectUserName", "TargetUserName", "user.name", "AccountName", "user.name.text"],
    "user_sid": ["UserSID", "SubjectUserSid", "TargetUserSid", "user.id"],
    "logon_id": ["LogonId", "SubjectLogonId", "TargetLogonId", "LogonID"],
    "logon_type": ["LogonType", "logon_type"],
    # Network
    "source_ip": ["SourceIp", "SourceAddress", "source_ip", "IpAddress", "source.ip", "src_ip"],
    "source_port": ["SourcePort", "source.port", "src_port"],
    "destination_ip": ["DestinationIp", "DestinationAddress", "destination_ip", "destination.ip", "dst_ip", "RemoteIP"],
    "destination_port": ["DestinationPort", "destination.port", "destination_port", "dst_port", "RemotePort", "port"],
    "protocol": ["Protocol", "protocol", "network.protocol", "TransportProtocol"],
    "initiating_process_guid": ["InitiatingProcessGuid", "ProcessGuid"],
    # File & Persistence
    "target_object": ["TargetObject", "TargetFilename", "ObjectName", "file.path", "file_path"],
    "action_type": ["ActionType", "EventType", "event.action", "AccessMask"],
    "event_outcome": ["event.outcome", "EventOutcome", "Outcome", "success"],
    "event_category": ["event.category", "EventCategory", "event_type"],
    "details": ["Details", "NewValue", "registry.value"],
    # Environment context
    "department": ["department", "Department"],
    "location": ["location", "Location", "site"],
    "device_type": ["device_type", "DeviceType"],
    # Labels
    "label": ["Label", "label", "classification"],
    "mitre_technique_id": ["MITRE_TechniqueId", "mitre", "technique_id", "rule.mitre.id"],
    "attack_scenario": ["AttackScenario", "scenario", "campaign"],
    # Active Directory (EID 4662 / DCSync)
    "properties": ["Properties", "AccessProperties", "SubjectUserSid"],
    "object_guid": ["ObjectGuid", "ObjectName", "SubjectDomainName"],
    "access_mask": ["AccessMask", "access_mask"],
    "object_type": ["ObjectType", "object_type"],
    # Process Access (Sysmon EID 10) — credential-dumping detection. These were
    # previously dropped during normalization, hiding LSASS access from the rules.
    "target_image": ["TargetImage"],
    "granted_access": ["GrantedAccess"],
    "call_trace": ["CallTrace"],
    # Log message content (Elastic / syslog)
    "message": ["message", "Message", "msg", "log.message"],
}


class LogIngester:
    """Parses JSON, CSV, XML, LOG, and EVTX files into the canonical schema."""

    def parse_file(self, filepath: str, fmt: str, max_events: int | None = None) -> List[Dict[str, Any]]:
        max_events = max_events or DEFAULT_MAX_EVENTS
        file_size = os.path.getsize(filepath)
        if file_size > LARGE_FILE_BYTES:
            logger.info("Large file detected: %.1f MB — using streaming mode", file_size / 1024 / 1024)
        if fmt == ".json":
            return self._parse_json(filepath, file_size, max_events)
        elif fmt == ".csv":
            return self._parse_csv(filepath, max_events)
        elif fmt == ".xml":
            return self._parse_xml(filepath, max_events)
        elif fmt == ".log":
            return self._parse_log(filepath, max_events)
        elif fmt == ".evtx":
            return self._parse_evtx(filepath, max_events)
        return []

    def _parse_json(self, filepath: str, file_size: int = 0, max_events: int = DEFAULT_MAX_EVENTS) -> List[Dict]:
        # For large files, avoid loading everything into memory at once.
        # Try lightweight probes first, then fall back to streaming.
        if file_size > LARGE_FILE_BYTES:
            # Probe: check if it's NDJSON (one JSON object per line)
            ndjson_events = self._try_parse_ndjson(filepath, max_events)
            if ndjson_events is not None:
                return ndjson_events
            # Probe: peek at first non-blank char to decide format
            first_char = ""
            with open(filepath, "r", encoding="utf-8-sig") as f:
                for line in f:
                    first_char = line.strip()[:1]
                    if first_char:
                        break
            if first_char == "{":
                # Concatenated JSON objects — stream parse without loading whole file
                logger.info("Large concatenated JSON detected — streaming parser")
                return self._parse_concat_json(filepath, max_events)
            if first_char == "[":
                logger.info("Large JSON array detected — streaming array parser")
                return self._parse_json_array_stream(filepath, max_events)
            logger.info("Large JSON document detected — bounded object parser")

        # Small files: try standard json.load, fall back to concat parser
        try:
            with open(filepath, "r", encoding="utf-8-sig") as f:
                raw = json.load(f)
        except json.JSONDecodeError as e:
            if "Extra data" in str(e):
                logger.info("Detected concatenated JSON objects — using streaming decoder")
                return self._parse_concat_json(filepath, max_events)
            raise
        if isinstance(raw, dict):
            raw = raw.get("Events", raw.get("events", raw.get("records", [raw])))
        events = []
        for ev in raw:
            events.append(self._normalize(ev))
            if len(events) >= max_events:
                logger.warning("Event parse cap reached: %d", max_events)
                break
        return events

    def _try_parse_ndjson(self, filepath: str, max_events: int):
        """Try parsing as newline-delimited JSON (one complete object per line)."""
        events = []
        try:
            with open(filepath, "r", encoding="utf-8-sig") as f:
                first_line = f.readline().strip()
                if not first_line or first_line.startswith("["):
                    return None  # not NDJSON — it's a JSON array
                obj = json.loads(first_line)
                if not isinstance(obj, dict):
                    return None
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    events.append(self._normalize(json.loads(line)))
                    if len(events) >= max_events:
                        logger.warning("Event parse cap reached: %d", max_events)
                        break
            logger.info("Parsed as NDJSON: %d events", len(events))
            return events
        except (json.JSONDecodeError, ValueError):
            return None

    def _parse_json_array_stream(self, filepath: str, max_events: int) -> List[Dict]:
        """Stream JSON arrays without loading the full upload into memory."""
        events = []
        decoder = json.JSONDecoder()
        buf = ""
        started = False
        eof = False

        with open(filepath, "r", encoding="utf-8-sig") as f:
            while not eof and len(events) < max_events:
                chunk = f.read(JSON_READ_CHUNK)
                if not chunk:
                    eof = True
                buf += chunk
                while len(events) < max_events:
                    buf = buf.lstrip()
                    if not started:
                        if not buf:
                            break
                        if buf[0] != "[":
                            return []
                        started = True
                        buf = buf[1:]
                        continue
                    buf = buf.lstrip()
                    if not buf:
                        break
                    if buf[0] == "]":
                        logger.info("Parsed JSON array (streaming): %d events", len(events))
                        return events
                    if buf[0] == ",":
                        buf = buf[1:]
                        continue
                    try:
                        obj, idx = decoder.raw_decode(buf)
                    except json.JSONDecodeError:
                        if eof:
                            raise
                        break
                    if isinstance(obj, dict):
                        events.append(self._normalize(obj))
                    buf = buf[idx:]
                    if len(events) % 50_000 == 0 and events:
                        logger.info("Streaming JSON array progress: %d events parsed", len(events))
        if len(events) >= max_events:
            logger.warning("Event parse cap reached: %d", max_events)
        return events

    def _parse_concat_json(self, filepath: str, max_events: int) -> List[Dict]:
        """Stream-parse concatenated multi-line JSON objects without loading
        the entire file into memory.

        Accumulates lines in a buffer; whenever the buffer forms a complete
        JSON object, it is decoded, normalized, and the buffer is reset.
        Memory usage stays proportional to one JSON object, not the whole file.
        """
        events = []
        buf = ""
        depth = 0          # brace nesting depth
        in_string = False   # inside a JSON string literal
        escape = False      # previous char was backslash

        with open(filepath, "r", encoding="utf-8-sig") as f:
            for line in f:
                if len(events) >= max_events:
                    logger.warning("Event parse cap reached: %d", max_events)
                    break
                for ch in line:
                    if escape:
                        escape = False
                        buf += ch
                        continue
                    if ch == '\\' and in_string:
                        escape = True
                        buf += ch
                        continue
                    if ch == '"' and not escape:
                        in_string = not in_string
                        buf += ch
                        continue
                    if in_string:
                        buf += ch
                        continue
                    # Outside of strings — track brace depth
                    if ch == '{':
                        if depth == 0:
                            buf = ""   # start fresh object
                        depth += 1
                        buf += ch
                    elif ch == '}':
                        depth -= 1
                        buf += ch
                        if depth == 0:
                            # Complete object — decode it
                            try:
                                obj = json.loads(buf)
                                events.append(self._normalize(obj))
                            except json.JSONDecodeError:
                                pass  # skip malformed object
                            buf = ""
                    elif depth > 0:
                        buf += ch
                    # else: whitespace between objects — ignore

                if len(events) % 50_000 == 0 and len(events) > 0:
                    logger.info("Streaming concat-JSON progress: %d events parsed", len(events))

        logger.info("Parsed concatenated JSON (streaming): %d events", len(events))
        return events

    def _parse_csv(self, filepath: str, max_events: int) -> List[Dict]:
        events = []
        with open(filepath, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader)
            expected = len(header)

            # Pre-detect the first multi-value column that Kibana fails to quote.
            # In ECS exports, host.ip and host.mac are the usual culprits.
            _split_col = None
            for candidate in ("host.ip", "host.mac", "source.ip"):
                if candidate in header:
                    _split_col = header.index(candidate)
                    break

            for row in reader:
                if len(events) >= max_events:
                    logger.warning("Event parse cap reached: %d", max_events)
                    break
                actual = len(row)
                if actual == expected:
                    rec = dict(zip(header, row))
                else:
                    # Row has wrong number of fields due to Kibana export bugs:
                    #  - Unquoted commas in multi-value fields (host.ip, host.mac)
                    #    cause extra columns (actual > expected)
                    #  - Missing trailing monitoring.* columns cause fewer columns
                    #    (actual < expected)
                    #  - BOTH can happen in the same row.
                    #
                    # Strategy: reverse-anchor.  The columns BEFORE the first
                    # multi-value field and the columns AFTER the last multi-value
                    # field are always correctly aligned.  We anchor those and
                    # merge everything in between.
                    if _split_col is not None and _split_col < actual:
                        head = row[:_split_col]  # columns before the split point
                        # Anchor from the end: figure out how many tail columns
                        # are present.  In a correct row, tail starts after
                        # host.name (split_col + 2: host.ip, host.mac, host.name).
                        # The tail anchor column is host.name which should contain
                        # a hostname string (not an IP, not "-").
                        # We find the anchor by scanning backwards for the
                        # host.name column position in the HEADER.
                        host_name_idx = header.index("host.name") if "host.name" in header else _split_col + 2
                        tail_len = expected - host_name_idx
                        if tail_len > 0 and tail_len <= actual:
                            tail = row[-tail_len:]
                            mid_cells = row[_split_col : actual - tail_len]
                        else:
                            # Can't anchor — merge all overflow into one field
                            mid_cells = row[_split_col:]
                            tail = []
                        merged = ", ".join(mid_cells)
                        realigned = head + [merged] + tail
                    else:
                        # No known overflow column — just pad/truncate
                        realigned = list(row)

                    # Pad or truncate to exact header length
                    if len(realigned) < expected:
                        realigned += [""] * (expected - len(realigned))
                    elif len(realigned) > expected:
                        realigned = realigned[:expected]
                    rec = dict(zip(header, realigned))
                events.append(self._normalize(rec))
        return events

    def _parse_xml(self, filepath: str, max_events: int) -> List[Dict]:
        events = []
        tree = ET.iterparse(filepath, events=("end",))
        for _, event_el in tree:
            tag = event_el.tag.split("}")[-1] if "}" in event_el.tag else event_el.tag
            if tag != "Event":
                continue
            flat = {}
            for child in event_el.iter():
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child.text and child.text.strip():
                    flat[child_tag] = child.text.strip()
                for attr_k, attr_v in child.attrib.items():
                    flat[f"{child_tag}_{attr_k}"] = attr_v
            events.append(self._normalize(flat))
            event_el.clear()
            if len(events) >= max_events:
                logger.warning("Event parse cap reached: %d", max_events)
                break
        return events

    def _parse_log(self, filepath: str, max_events: int) -> List[Dict]:
        events = []
        with open(filepath, "r", encoding="utf-8-sig") as f:
            for line in f:
                if len(events) >= max_events:
                    logger.warning("Event parse cap reached: %d", max_events)
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    events.append(self._normalize(ev))
                except json.JSONDecodeError:
                    events.append(self._normalize({"raw": line, "Timestamp": datetime.utcnow().isoformat()}))
        return events

    def _parse_evtx(self, filepath: str, max_events: int) -> List[Dict]:
        """Parse native Windows .evtx files record-by-record."""
        with open(filepath, "rb") as f:
            if f.read(8) != b"ElfFile\x00":
                raise ValueError("Invalid EVTX file header")

        try:
            from Evtx.Evtx import Evtx
        except ImportError as exc:
            raise RuntimeError("EVTX support requires the python-evtx package") from exc

        events = []
        parse_errors = 0
        with Evtx(filepath) as log:
            for record in log.records():
                if len(events) >= max_events:
                    logger.warning("Event parse cap reached: %d", max_events)
                    break
                try:
                    flat = self._flatten_evtx_record(record.xml())
                    flat["RecordNumber"] = record.record_num()
                    events.append(self._normalize(flat))
                except Exception as exc:
                    parse_errors += 1
                    if parse_errors <= 5:
                        logger.warning("Skipping malformed EVTX record: %r", exc)
        if parse_errors:
            logger.warning("EVTX parse completed with %d skipped record(s)", parse_errors)
        return events

    def _flatten_evtx_record(self, xml_text: str) -> Dict[str, Any]:
        root = ET.fromstring(xml_text)
        flat: Dict[str, Any] = {}

        def local(tag: str) -> str:
            return tag.split("}")[-1] if "}" in tag else tag

        system = next((child for child in root if local(child.tag) == "System"), None)
        if system is not None:
            for child in system:
                tag = local(child.tag)
                text = (child.text or "").strip()
                if text:
                    flat[tag] = text
                for attr_k, attr_v in child.attrib.items():
                    key = f"{tag}_{attr_k}"
                    flat[key] = attr_v
                    if tag == "Provider" and attr_k == "Name":
                        flat["ProviderName"] = attr_v
                    elif tag == "TimeCreated" and attr_k == "SystemTime":
                        flat["TimeCreated"] = attr_v
                    elif tag == "Security" and attr_k == "UserID":
                        flat["UserSID"] = attr_v

        for section_name in ("EventData", "UserData", "DebugData", "RenderingInfo"):
            section = next((child for child in root if local(child.tag) == section_name), None)
            if section is None:
                continue
            for child in section.iter():
                tag = local(child.tag)
                if tag == section_name:
                    continue
                name = child.attrib.get("Name") or child.attrib.get("name") or tag
                value = (child.text or "").strip()
                if value:
                    flat[name] = value
                    flat[f"{section_name}_{name}"] = value

        if "EventID" in flat:
            flat["EventCode"] = flat["EventID"]
        if "Computer" in flat:
            flat["ComputerName"] = flat["Computer"]
        return flat

    def _normalize(self, raw: Dict) -> Dict:
        """Map raw fields to canonical schema."""
        norm = {}
        for canon, aliases in CANONICAL_FIELDS.items():
            for alias in aliases:
                if alias in raw and raw[alias]:
                    val = raw[alias]
                    # Kibana exports use "-" as null placeholder — skip these
                    if isinstance(val, str) and val.strip() == "-":
                        continue
                    if canon == "event_id":
                        try:
                            val = int(val)
                        except (ValueError, TypeError):
                            pass
                    norm[canon] = val
                    break
        # Kibana Discover export timestamp: "Apr 4, 2025 @ 22:00:00.000" → "Apr 4, 2025 22:00:00.000"
        if "timestamp" in norm:
            ts = norm["timestamp"]
            if isinstance(ts, str) and " @ " in ts:
                norm["timestamp"] = ts.replace(" @ ", " ")
        # Clean event_outcome: strip control chars and trailing junk from auditd
        if "event_outcome" in norm:
            outcome = norm["event_outcome"]
            if isinstance(outcome, str):
                # Extract the first word (e.g., "failed" from "failed'\x1dUID=\"root")
                clean = outcome.split("'")[0].split("\x1d")[0].strip().lower()
                norm["event_outcome"] = clean if clean else outcome
        # Fallback: use message as commandline for display & analysis when commandline is missing
        if "commandline" not in norm and "message" in norm:
            norm["commandline"] = norm["message"]
        # Sanitize process_name: reject pure-numeric values (Kibana export metric leakage)
        if "process_name" in norm:
            pn = str(norm["process_name"]).strip()
            try:
                float(pn)
                del norm["process_name"]  # remove metric-leaked numeric values
            except ValueError:
                pass
        # Generate process_guid if missing
        if "process_guid" not in norm:
            seed = f"{norm.get('hostname','')}-{norm.get('process_name','')}-{norm.get('timestamp','')}-{norm.get('commandline','')}"
            norm["process_guid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
        if "parent_process_guid" not in norm and norm.get("parent_process_name"):
            seed = f"{norm.get('hostname','')}-{norm.get('parent_process_name','')}-parent"
            norm["parent_process_guid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))
        # Extract process name from path — use ntpath for Windows paths on any OS
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
        # Normalize the timestamp to epoch seconds ONCE here (see time_utils.py).
        # Downstream code must sort/compare on `_ts`, never on the raw string —
        # mixed-format inputs (ISO + Kibana + epoch) misorder as strings.
        norm["_ts"] = parse_ts(norm.get("timestamp"))
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
