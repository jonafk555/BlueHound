"""Graph engine — builds process tree and network topology using NetworkX."""
import networkx as nx
from typing import List, Dict, Any


class GraphEngine:
    """Converts normalized events into a directed graph for D3.js visualization."""

    def build_graph(self, events: List[Dict], findings: List[Dict] = None) -> Dict:
        findings = findings or []
        finding_guids = {}
        for f in findings:
            guid = f.get("process_guid", "")
            if guid:
                if guid not in finding_guids:
                    finding_guids[guid] = []
                finding_guids[guid].append(f)

        G = nx.DiGraph()
        nodes_map = {}
        edges = []

        for ev in events:
            pguid = ev.get("process_guid")
            ppguid = ev.get("parent_process_guid")
            if not pguid:
                continue

            # Determine severity from findings
            sev = "benign"
            matched_rules = []
            if pguid in finding_guids:
                for fi in finding_guids[pguid]:
                    matched_rules.append(fi)
                    s = fi.get("severity", "LOW")
                    if s == "CRITICAL":
                        sev = "critical"
                    elif s == "HIGH" and sev not in ("critical",):
                        sev = "high"
                    elif s == "MEDIUM" and sev not in ("critical", "high"):
                        sev = "medium"
                    elif s == "LOW" and sev == "benign":
                        sev = "low"

            node_type = "process"
            if ev.get("destination_ip") and ev.get("event_id") in (3, "3"):
                node_type = "network"

            if pguid not in nodes_map:
                nodes_map[pguid] = {
                    "id": pguid,
                    "label": ev.get("process_name", "unknown"),
                    "type": node_type,
                    "severity": sev,
                    "process_name": ev.get("process_name", ""),
                    "process_path": ev.get("process_path", ""),
                    "commandline": ev.get("commandline", ""),
                    "hostname": ev.get("hostname", ""),
                    "user_name": ev.get("user_name", ""),
                    "timestamp": ev.get("timestamp", ""),
                    "event_id": ev.get("event_id", ""),
                    "hashes": ev.get("hashes", ""),
                    "source_ip": ev.get("source_ip", ""),
                    "destination_ip": ev.get("destination_ip", ""),
                    "destination_port": ev.get("destination_port", ""),
                    "mitre": [r.get("mitre", "") for r in matched_rules],
                    "rules": [{"id": r["rule_id"], "name": r["rule_name"], "severity": r["severity"]} for r in matched_rules],
                }
            else:
                existing = nodes_map[pguid]
                if sev != "benign" and self._sev_rank(sev) > self._sev_rank(existing["severity"]):
                    existing["severity"] = sev
                if matched_rules:
                    existing["mitre"] = list(set(existing.get("mitre", []) + [r.get("mitre", "") for r in matched_rules]))
                    existing["rules"] = existing.get("rules", []) + [{"id": r["rule_id"], "name": r["rule_name"], "severity": r["severity"]} for r in matched_rules]

            # Parent → Child edge
            if ppguid and ppguid != pguid:
                if ppguid not in nodes_map:
                    nodes_map[ppguid] = {
                        "id": ppguid,
                        "label": ev.get("parent_process_name", "unknown"),
                        "type": "process",
                        "severity": "benign",
                        "process_name": ev.get("parent_process_name", ""),
                        "commandline": ev.get("parent_commandline", ""),
                        "hostname": ev.get("hostname", ""),
                        "timestamp": "",
                        "event_id": "",
                        "mitre": [],
                        "rules": [],
                    }
                edge_key = f"{ppguid}->{pguid}"
                edges.append({
                    "source": ppguid,
                    "target": pguid,
                    "type": "SPAWNED",
                    "label": "spawned",
                })

            # Network edge: process → destination
            dst_ip = ev.get("destination_ip")
            if dst_ip and ev.get("event_id") in (3, "3"):
                net_id = f"net-{dst_ip}:{ev.get('destination_port', '')}"
                if net_id not in nodes_map:
                    nodes_map[net_id] = {
                        "id": net_id,
                        "label": f"{dst_ip}:{ev.get('destination_port', '')}",
                        "type": "network",
                        "severity": "benign",
                        "destination_ip": dst_ip,
                        "destination_port": ev.get("destination_port", ""),
                        "protocol": ev.get("protocol", ""),
                        "mitre": [],
                        "rules": [],
                    }
                edges.append({
                    "source": pguid,
                    "target": net_id,
                    "type": "CONNECTED",
                    "label": f"{ev.get('protocol', 'tcp')}",
                })

        # Deduplicate edges
        seen_edges = set()
        unique_edges = []
        for e in edges:
            key = f"{e['source']}->{e['target']}-{e['type']}"
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        return {
            "nodes": list(nodes_map.values()),
            "edges": unique_edges,
            "stats": {
                "total_nodes": len(nodes_map),
                "total_edges": len(unique_edges),
                "critical": sum(1 for n in nodes_map.values() if n.get("severity") == "critical"),
                "high": sum(1 for n in nodes_map.values() if n.get("severity") == "high"),
                "medium": sum(1 for n in nodes_map.values() if n.get("severity") == "medium"),
            }
        }

    @staticmethod
    def _sev_rank(s):
        return {"benign": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)

    def build_process_tree(self, events: List[Dict], findings: List[Dict] = None) -> List[Dict]:
        """Build hierarchical tree structure for process tree view."""
        graph_data = self.build_graph(events, findings)
        nodes_by_id = {n["id"]: {**n, "children": []} for n in graph_data["nodes"]}
        child_ids = set()

        for edge in graph_data["edges"]:
            if edge["type"] == "SPAWNED":
                parent = nodes_by_id.get(edge["source"])
                child = nodes_by_id.get(edge["target"])
                if parent and child:
                    parent["children"].append(child)
                    child_ids.add(edge["target"])

        roots = [n for nid, n in nodes_by_id.items() if nid not in child_ids and n.get("type") == "process"]
        return roots if roots else list(nodes_by_id.values())[:1]
