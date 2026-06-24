"""KQL / SPL / Sigma query builder for BlueHound."""
import re
from typing import Dict, Any
import yaml


def _esc_kql(value: str) -> str:
    """VULN-06: Escape KQL string literal — escape backslash and double-quote."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def _esc_spl(value: str) -> str:
    """VULN-06: Escape SPL string literal — escape backslash, quote, wildcard."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("*", "\\*")
        .replace("?", "\\?")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _safe_int(value: Any) -> str:
    """Validate event_id is a plain integer string."""
    s = str(value).strip()
    if re.fullmatch(r"\d{1,6}", s):
        return s
    raise ValueError(f"Invalid event_id: {value!r}")


def _safe_timerange(value: str) -> str:
    """Validate time range like '7d', '24h', '30m'."""
    s = str(value).strip()
    if re.fullmatch(r"\d{1,4}[mhdwMy]", s):
        return s
    raise ValueError(f"Invalid time_range: {value!r}")


# ── Allowlists for query structure positions (VULN fix) ──────
ALLOWED_TABLES = {
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
    "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceImageLoadEvents",
    "DeviceEvents", "SecurityEvent", "Syslog", "CommonSecurityLog",
}

ALLOWED_INDEXES = {
    "wineventlog", "sysmon", "main", "security", "forwarders",
    "os", "oswin", "linux",
}


def _safe_table(value: str, default: str = "DeviceProcessEvents") -> str:
    """Validate table name against allowlist."""
    s = str(value).strip()
    if s in ALLOWED_TABLES:
        return s
    return default


def _safe_index(value: str, default: str = "wineventlog") -> str:
    """Validate index name against allowlist."""
    s = str(value).strip()
    if s in ALLOWED_INDEXES:
        return s
    return default


class QueryBuilder:
    """Generates hunting queries from structured filters."""

    def generate(self, filters: Dict[str, Any], fmt: str = "kql") -> str:
        if fmt == "kql":
            return self._build_kql(filters)
        elif fmt == "spl":
            return self._build_spl(filters)
        elif fmt == "sigma":
            return self._build_sigma(filters)
        return ""

    def _build_kql(self, f: Dict) -> str:
        """Generate Kusto Query Language for Microsoft Sentinel / Defender."""
        table = _safe_table(f.get("table", "DeviceProcessEvents"))
        clauses = []

        if f.get("source_ip"):
            clauses.append(f'| where SourceIP == "{_esc_kql(f["source_ip"])}"')
        if f.get("destination_ip"):
            clauses.append(f'| where RemoteIP == "{_esc_kql(f["destination_ip"])}"')
        if f.get("process_name"):
            if isinstance(f["process_name"], list):
                names = ", ".join(f'"{_esc_kql(n)}"' for n in f["process_name"])
                clauses.append(f'| where FileName in~ ({names})')
            else:
                clauses.append(f'| where FileName =~ "{_esc_kql(f["process_name"])}"')
        if f.get("commandline_contains"):
            clauses.append(f'| where ProcessCommandLine contains "{_esc_kql(f["commandline_contains"])}"')
        if f.get("commandline_regex"):
            # Regex values are display-only queries; still escape for output safety
            clauses.append(f'| where ProcessCommandLine matches regex @"{_esc_kql(f["commandline_regex"])}"')
        if f.get("event_id"):
            try:
                clauses.append(f'| where EventId == {_safe_int(f["event_id"])}')
            except ValueError:
                pass
        if f.get("hostname"):
            clauses.append(f'| where DeviceName =~ "{_esc_kql(f["hostname"])}"')
        if f.get("user_name"):
            clauses.append(f'| where AccountName =~ "{_esc_kql(f["user_name"])}"')
        if f.get("time_range"):
            try:
                clauses.append(f'| where Timestamp >= ago({_safe_timerange(f["time_range"])})')
            except ValueError:
                pass

        project = "Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName"
        clauses.append(f"| project {project}")
        clauses.append("| sort by Timestamp desc")
        clauses.append("| take 100")

        return f"{table}\n" + "\n".join(clauses)

    def _build_spl(self, f: Dict) -> str:
        """Generate Splunk SPL query."""
        index = _safe_index(f.get("index", "wineventlog"))
        clauses = [f'index={index}']

        if f.get("source_ip"):
            clauses.append(f'src_ip="{_esc_spl(f["source_ip"])}"')
        if f.get("destination_ip"):
            clauses.append(f'dest_ip="{_esc_spl(f["destination_ip"])}"')
        if f.get("process_name"):
            if isinstance(f["process_name"], list):
                names = " OR ".join(f'process_name="{_esc_spl(n)}"' for n in f["process_name"])
                clauses.append(f"({names})")
            else:
                clauses.append(f'process_name="{_esc_spl(f["process_name"])}"')
        if f.get("commandline_contains"):
            clauses.append(f'CommandLine="*{_esc_spl(f["commandline_contains"])}*"')
        if f.get("event_id"):
            try:
                clauses.append(f'EventCode={_safe_int(f["event_id"])}')
            except ValueError:
                pass
        if f.get("hostname"):
            clauses.append(f'host="{_esc_spl(f["hostname"])}"')
        if f.get("user_name"):
            clauses.append(f'user="{_esc_spl(f["user_name"])}"')
        if f.get("time_range"):
            try:
                clauses.append(f'earliest=-{_safe_timerange(f["time_range"])}')
            except ValueError:
                pass

        base = " ".join(clauses)
        return f'{base}\n| table _time, host, process_name, CommandLine, user, src_ip, dest_ip\n| sort -_time\n| head 100'

    def _build_sigma(self, f: Dict) -> str:
        """Generate Sigma rule YAML through a serializer, never string concatenation."""
        selection: Dict[str, Any] = {}
        if f.get("process_name"):
            pn = f["process_name"]
            if isinstance(pn, list):
                selection["Image|endswith"] = [f"\\{str(n)}" for n in pn]
            else:
                selection["Image|endswith"] = f"\\{str(pn)}"
        if f.get("commandline_contains"):
            selection["CommandLine|contains"] = str(f["commandline_contains"])
        if f.get("commandline_regex"):
            selection["CommandLine|re"] = str(f["commandline_regex"])
        if f.get("user_name"):
            selection["User|contains"] = str(f["user_name"])

        rule = {
            "title": "BlueHound Generated Hunt",
            "status": "experimental",
            "description": "Auto-generated by BlueHound query builder",
            "logsource": {
                "category": "process_creation",
                "product": "windows",
            },
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "falsepositives": ["Legitimate administrative activity"],
            "level": "medium",
        }
        return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True).rstrip()

    def suggest_queries(self, facets: Dict, findings: list) -> list:
        """Generate suggested queries based on loaded data."""
        suggestions = []
        
        # Suggest IP-based queries
        for ip in facets.get("destination_ip", [])[:5]:
            suggestions.append({
                "label": f"Hunt connections to {ip}",
                "filters": {"destination_ip": ip, "table": "DeviceNetworkEvents"},
                "format": "kql"
            })

        # Suggest process-based queries from findings
        seen = set()
        for finding in findings[:10]:
            pn = finding.get("process_name", "")
            if pn and pn not in seen:
                seen.add(pn)
                suggestions.append({
                    "label": f"Hunt {pn} executions ({finding.get('rule_name', '')})",
                    "filters": {"process_name": pn},
                    "format": "kql"
                })

        return suggestions
