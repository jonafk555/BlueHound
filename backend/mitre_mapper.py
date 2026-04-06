"""MITRE ATT&CK technique mapper — offline lookup table."""

MITRE_DB = {
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/",
                  "description": "Adversaries may abuse PowerShell commands and scripts for execution."},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1562/001/",
                  "description": "Adversaries may modify and/or disable security tools to avoid detection."},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1218/005/",
                  "description": "Adversaries may abuse mshta.exe to proxy execution of malicious code."},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1218/011/",
                  "description": "Adversaries may abuse rundll32.exe to proxy execution."},
    "T1218.010": {"name": "Regsvr32", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1218/010/",
                  "description": "Adversaries may abuse Regsvr32 to proxy execution of malicious code."},
    "T1140": {"name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1140/",
              "description": "Adversaries may use obfuscated files or information to hide artifacts."},
    "T1197": {"name": "BITS Jobs", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1197/",
              "description": "Adversaries may abuse BITS jobs to download, execute, and clean up."},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1003/001/",
                  "description": "Adversaries may attempt to access credential material stored in LSASS memory."},
    "T1003.006": {"name": "DCSync", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1003/006/",
                  "description": "Adversaries may attempt to access credentials by abusing Active Directory replication."},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1021/002/",
                  "description": "Adversaries may use SMB to interact with remote systems."},
    "T1047": {"name": "WMI", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1047/",
              "description": "Adversaries may abuse WMI to execute malicious commands."},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1543/003/",
                  "description": "Adversaries may create or modify Windows services for persistence."},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1053/005/",
                  "description": "Adversaries may abuse scheduled tasks for execution or persistence."},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1547/001/",
                  "description": "Adversaries may achieve persistence by adding entries to Run keys."},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1018/",
              "description": "Adversaries may attempt to get a listing of other systems on the network."},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1082/",
              "description": "Adversaries may attempt to get detailed information about the operating system."},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/004/",
                  "description": "Adversaries may communicate using the DNS application layer protocol."},
    "T1134.001": {"name": "Token Impersonation", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1134/001/",
                  "description": "Adversaries may duplicate and impersonate another user's token."},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1055/",
              "description": "Adversaries may inject code into processes to evade defenses."},
    "T1055.012": {"name": "Process Hollowing", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1055/012/",
                  "description": "Adversaries may inject malicious code into suspended processes."},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1204/002/",
                  "description": "Adversaries may rely on a user opening a malicious file to gain execution."},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1218/",
              "description": "Adversaries may bypass defenses by proxying execution through trusted system binaries."},
}


class MitreMapper:
    """Lookup MITRE ATT&CK technique details."""

    def lookup(self, technique_id: str) -> dict:
        t = MITRE_DB.get(technique_id)
        if t:
            return {"technique_id": technique_id, **t}
        return {"technique_id": technique_id, "name": "Unknown", "tactic": "Unknown",
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.','/')}/",
                "description": "Technique not in local database."}

    def enrich_findings(self, findings: list) -> list:
        for f in findings:
            tid = f.get("mitre", "")
            if tid:
                info = self.lookup(tid)
                f["mitre_name"] = info["name"]
                f["mitre_url"] = info["url"]
        return findings
