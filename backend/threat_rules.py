"""Threat rule engine — loads YAML playbooks and evaluates events."""
import re, yaml, logging
from pathlib import Path
from typing import List, Dict, Any
import threading

logger = logging.getLogger(__name__)


def _safe_search(pattern: str, text: str, timeout: float = 1.0) -> bool:
    """VULN-02: ReDoS-resistant regex search with threading timeout.
    Uses a daemon thread — works on all Python 3.x versions.
    """
    if not text:
        return False
    result = [False]
    exc_box = [None]

    def _run():
        try:
            result[0] = bool(re.search(pattern, text))
        except re.error as exc:
            exc_box[0] = exc

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        logger.warning("Regex timeout (%.1fs) on pattern=%r (ReDoS protection)", timeout, pattern[:60])
        return False
    if exc_box[0]:
        logger.error("Invalid regex pattern %r: %s", pattern[:60], exc_box[0])
        return False
    return result[0]

class ThreatRuleEngine:
    """Loads hunting playbook YAML and evaluates events against rules."""

    def __init__(self, playbook_path: str = None):
        self.rules = []
        if playbook_path and Path(playbook_path).exists():
            self._load_playbook(playbook_path)

    def _load_playbook(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.rules = data.get("rules", [])

    def evaluate_all(self, events: List[Dict]) -> List[Dict]:
        """Evaluate all events against all rules. Returns list of findings."""
        findings = []
        for ev in events:
            for rule in self.rules:
                if self._matches(ev, rule):
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "mitre": rule.get("mitre", ""),
                        "tactic": rule.get("tactic", ""),
                        "severity": rule.get("severity", "LOW"),
                        "description": rule.get("description", ""),
                        "hunt_guidance": rule.get("hunt_guidance", ""),
                        "process_guid": ev.get("process_guid", ""),
                        "process_name": ev.get("process_name", ""),
                        "commandline": ev.get("commandline", ""),
                        "hostname": ev.get("hostname", ""),
                        "timestamp": ev.get("timestamp", ""),
                        "user_name": ev.get("user_name", ""),
                        "event_id": ev.get("event_id", ""),
                    })
        return findings

    def _matches(self, event: Dict, rule: Dict) -> bool:
        """Check if an event matches a rule's conditions."""
        match = rule.get("match", {})
        if not match:
            return False

        # Process name match
        pn = match.get("process_name")
        if pn:
            ev_pn = (event.get("process_name") or "").lower()
            if isinstance(pn, list):
                if not any(p.lower() == ev_pn for p in pn):
                    return False
            elif pn.lower() != ev_pn:
                return False

        # Event ID match
        eid = match.get("event_id")
        if eid:
            ev_eid = event.get("event_id")
            if isinstance(eid, list):
                if ev_eid not in eid and str(ev_eid) not in [str(e) for e in eid]:
                    return False
            elif str(ev_eid) != str(eid):
                return False

        # CommandLine regex
        cmd_regex = match.get("commandline_regex")
        if cmd_regex:
            cmdline = event.get("commandline", "") or ""
            if not _safe_search(cmd_regex, cmdline):
                return False

        # Process path regex
        path_regex = match.get("process_path_regex")
        if path_regex:
            ppath = event.get("process_path", "") or event.get("process_name", "") or ""
            if not _safe_search(path_regex, ppath):
                return False

        # Parent-child anomaly check
        if match.get("parent_child_anomaly"):
            suspicious = match.get("suspicious_parents", {})
            ev_pn = (event.get("process_name") or "").lower()
            ev_ppn = (event.get("parent_process_name") or "").lower()
            if ev_pn in [k.lower() for k in suspicious]:
                expected_parents = [p.lower() for p in suspicious.get(ev_pn, suspicious.get(event.get("process_name",""), []))]
                if ev_ppn in expected_parents:
                    return True
            return False

        # Properties/ObjectGuid regex — for EID 4662 (DCSync) and AD object access
        props_regex = match.get("properties_regex") or match.get("object_guid_regex")
        if props_regex:
            props_val  = event.get("properties",  "") or ""
            guid_val   = event.get("object_guid", "") or ""
            access_val = event.get("access_mask", "") or ""
            combined   = f"{props_val} {guid_val} {access_val}"
            if not _safe_search(props_regex, combined):
                return False

        # If we have process_name or event_id or commandline_regex constraints and got here, it matched
        if any(k in match for k in ("process_name", "event_id", "commandline_regex",
                                    "process_path_regex", "properties_regex", "object_guid_regex")):
            return True

        return False

    def get_rules_summary(self) -> List[Dict]:
        """Return simplified rules list for frontend display."""
        return [{
            "id": r["id"],
            "name": r["name"],
            "mitre": r.get("mitre", ""),
            "tactic": r.get("tactic", ""),
            "severity": r.get("severity", ""),
            "description": r.get("description", ""),
        } for r in self.rules]
