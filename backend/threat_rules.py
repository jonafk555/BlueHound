"""Threat rule engine — loads YAML playbooks and evaluates events."""
import re, yaml, logging
from functools import lru_cache
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

MAX_REGEX_TEXT = 16_384

@lru_cache(maxsize=256)
def _compile_rule_regex(pattern: str):
    return re.compile(pattern)


def _safe_search(pattern: str, text: str) -> bool:
    """Bounded regex search for trusted playbook patterns against untrusted logs."""
    if not text:
        return False
    try:
        return bool(_compile_rule_regex(pattern).search(str(text)[:MAX_REGEX_TEXT]))
    except re.error as exc:
        logger.error("Invalid regex pattern %r: %s", pattern[:60], exc)
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
        self._validate_regexes()

    def _validate_regexes(self):
        """Fail closed for invalid playbook regexes during startup."""
        regex_keys = ("commandline_regex", "process_path_regex", "properties_regex", "object_guid_regex")
        valid_rules = []
        for rule in self.rules:
            match = rule.get("match", {})
            try:
                for key in regex_keys:
                    if match.get(key):
                        _compile_rule_regex(match[key])
                valid_rules.append(rule)
            except re.error as exc:
                logger.error("Skipping rule %s due to invalid regex: %s", rule.get("id", "?"), exc)
        self.rules = valid_rules

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
                        "source_ip": ev.get("source_ip", ""),
                        "event_outcome": ev.get("event_outcome", ""),
                        "action_type": ev.get("action_type", ""),
                    })
        # Correlation-based detection (cross-event patterns)
        findings.extend(self._correlate_ssh_bruteforce(events))
        return findings

    # Invalid/unknown user patterns in auditd/syslog
    _INVALID_USER_PATTERNS = frozenset([
        "(invalid user)", "(unknown user)", "(unknown)",
        "invalid user", "unknown user", "unknown",
    ])

    def _is_invalid_user(self, username: str) -> bool:
        """Check if a username represents an invalid/unknown user from auditd."""
        return (username or "").strip().lower() in self._INVALID_USER_PATTERNS

    def _correlate_ssh_bruteforce(self, events: List[Dict]) -> List[Dict]:
        """Detect SSH brute force by correlating auth events per source IP.

        Pattern detected:
          1. Multiple failed logins with invalid/unknown usernames (enumeration)
          2. Followed by login attempts (failed or success) using a REAL username
             → This indicates the attacker discovered a valid account.
          3. If a successful login follows the failures → confirmed compromise.

        Returns CRITICAL/HIGH findings with the targeted account name.
        """
        # Group SSH auth events by source_ip
        from collections import defaultdict
        ssh_by_src: Dict[str, List[Dict]] = defaultdict(list)
        for ev in events:
            proc = (ev.get("process_name") or "").lower()
            cat = (ev.get("event_category") or "").lower()
            if proc == "sshd" or cat == "authentication":
                src = ev.get("source_ip", "")
                if src:
                    ssh_by_src[src].append(ev)

        findings = []
        for src_ip, src_events in ssh_by_src.items():
            # Sort by timestamp
            sorted_evs = sorted(src_events, key=lambda e: e.get("timestamp", ""))

            # Separate into phases
            invalid_failures = []   # failures with invalid/unknown users
            real_failures = []      # failures with real usernames
            successes = []          # successful logins

            for ev in sorted_evs:
                outcome = (ev.get("event_outcome") or "").lower()
                username = ev.get("user_name", "")

                if outcome == "failed":
                    if self._is_invalid_user(username):
                        invalid_failures.append(ev)
                    else:
                        real_failures.append(ev)
                elif outcome == "success":
                    successes.append(ev)

            # Require meaningful enumeration phase (≥5 invalid user attempts)
            if len(invalid_failures) < 5:
                continue

            # Collect targeted hosts
            targeted_hosts = sorted(set(
                ev.get("hostname", "") for ev in invalid_failures + real_failures + successes
                if ev.get("hostname")
            ))

            # Case 1: Successful login after brute force → CRITICAL (confirmed compromise)
            if successes:
                compromised_accounts = sorted(set(
                    ev.get("user_name", "") for ev in successes if ev.get("user_name")
                ))
                first_fail = invalid_failures[0]
                last_success = successes[-1]
                findings.append({
                    "rule_id": "TH-CORR-001",
                    "rule_name": "SSH Brute Force — Account Compromised",
                    "mitre": "T1110.001",
                    "tactic": "Credential Access",
                    "severity": "CRITICAL",
                    "description": (
                        f"SSH brute force attack SUCCEEDED. "
                        f"Source {src_ip} performed {len(invalid_failures)} failed login attempts "
                        f"with invalid/unknown usernames, then successfully logged in as: "
                        f"{', '.join(compromised_accounts)}. "
                        f"Targeted hosts: {', '.join(targeted_hosts)}. "
                        f"Attack window: {first_fail.get('timestamp','')} → {last_success.get('timestamp','')}."
                    ),
                    "hunt_guidance": (
                        f"IMMEDIATE ACTION REQUIRED: Account(s) {', '.join(compromised_accounts)} "
                        f"likely compromised via brute force from {src_ip}. "
                        f"1) Disable/reset password for {', '.join(compromised_accounts)}. "
                        f"2) Check for lateral movement from {', '.join(targeted_hosts)}. "
                        f"3) Review all commands executed in the SSH session. "
                        f"4) Block source IP {src_ip} at firewall."
                    ),
                    "process_guid": last_success.get("process_guid", ""),
                    "process_name": "sshd",
                    "commandline": f"Brute force: {len(invalid_failures)} enumeration attempts → successful login as {', '.join(compromised_accounts)}",
                    "hostname": ", ".join(targeted_hosts),
                    "timestamp": last_success.get("timestamp", ""),
                    "user_name": ", ".join(compromised_accounts),
                    "event_id": "",
                    "source_ip": src_ip,
                    "event_outcome": "success",
                    "action_type": "logged-in",
                })

            # Case 2: Real username targeted after enumeration (no success yet) → HIGH
            if real_failures:
                targeted_accounts = sorted(set(
                    ev.get("user_name", "") for ev in real_failures if ev.get("user_name")
                ))
                first_fail = invalid_failures[0]
                last_real = real_failures[-1]
                findings.append({
                    "rule_id": "TH-CORR-002",
                    "rule_name": "SSH Brute Force — Valid Account Targeted",
                    "mitre": "T1110.001",
                    "tactic": "Credential Access",
                    "severity": "HIGH",
                    "description": (
                        f"SSH brute force attack detected. "
                        f"Source {src_ip} performed {len(invalid_failures)} failed login attempts "
                        f"with invalid/unknown usernames (user enumeration), then targeted "
                        f"valid account(s): {', '.join(targeted_accounts)} "
                        f"({len(real_failures)} attempts). "
                        f"Targeted hosts: {', '.join(targeted_hosts)}. "
                        f"Attack window: {first_fail.get('timestamp','')} → {last_real.get('timestamp','')}."
                    ),
                    "hunt_guidance": (
                        f"Account(s) {', '.join(targeted_accounts)} discovered via brute force "
                        f"enumeration from {src_ip}. "
                        f"1) Force password reset for {', '.join(targeted_accounts)}. "
                        f"2) Check if any successful login from {src_ip} exists in a wider time window. "
                        f"3) Enable account lockout policies. "
                        f"4) Block source IP {src_ip}."
                    ),
                    "process_guid": last_real.get("process_guid", ""),
                    "process_name": "sshd",
                    "commandline": f"Brute force: {len(invalid_failures)} enumeration → {len(real_failures)} attempts on {', '.join(targeted_accounts)}",
                    "hostname": ", ".join(targeted_hosts),
                    "timestamp": last_real.get("timestamp", ""),
                    "user_name": ", ".join(targeted_accounts),
                    "event_id": "",
                    "source_ip": src_ip,
                    "event_outcome": "failed",
                    "action_type": "logged-in",
                })

            # Case 3: Only invalid user failures (pure enumeration, no real user found) → MEDIUM
            if not real_failures and not successes:
                first_fail = invalid_failures[0]
                last_fail = invalid_failures[-1]
                findings.append({
                    "rule_id": "TH-CORR-003",
                    "rule_name": "SSH User Enumeration Detected",
                    "mitre": "T1110.001",
                    "tactic": "Credential Access",
                    "severity": "MEDIUM",
                    "description": (
                        f"SSH user enumeration detected. "
                        f"Source {src_ip} performed {len(invalid_failures)} login attempts "
                        f"with invalid/unknown usernames across {', '.join(targeted_hosts)}. "
                        f"No valid account was identified yet. "
                        f"Window: {first_fail.get('timestamp','')} → {last_fail.get('timestamp','')}."
                    ),
                    "hunt_guidance": (
                        f"Attacker at {src_ip} is probing for valid usernames. "
                        f"1) Monitor for follow-up attacks from this IP. "
                        f"2) Consider blocking {src_ip} preemptively. "
                        f"3) Review if any valid usernames were exposed in error messages."
                    ),
                    "process_guid": last_fail.get("process_guid", ""),
                    "process_name": "sshd",
                    "commandline": f"User enumeration: {len(invalid_failures)} attempts with invalid usernames",
                    "hostname": ", ".join(targeted_hosts),
                    "timestamp": last_fail.get("timestamp", ""),
                    "user_name": "",
                    "event_id": "",
                    "source_ip": src_ip,
                    "event_outcome": "failed",
                    "action_type": "logged-in",
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

        # Event outcome match (e.g., "failed", "success")
        outcome = match.get("event_outcome")
        if outcome:
            ev_outcome = (event.get("event_outcome") or "").lower()
            if isinstance(outcome, list):
                if ev_outcome not in [o.lower() for o in outcome]:
                    return False
            elif outcome.lower() != ev_outcome:
                return False

        # Action type match (e.g., "logged-in", "logged-out")
        action = match.get("action_type")
        if action:
            ev_action = (event.get("action_type") or "").lower()
            if isinstance(action, list):
                if ev_action not in [a.lower() for a in action]:
                    return False
            elif action.lower() != ev_action:
                return False

        # Event category match (e.g., "authentication")
        category = match.get("event_category")
        if category:
            ev_cat = (event.get("event_category") or "").lower()
            if isinstance(category, list):
                if ev_cat not in [c.lower() for c in category]:
                    return False
            elif category.lower() != ev_cat:
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

        # If we have any matching constraint and got here, it matched
        if any(k in match for k in ("process_name", "event_id", "commandline_regex",
                                    "process_path_regex", "properties_regex", "object_guid_regex",
                                    "event_outcome", "action_type", "event_category")):
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
