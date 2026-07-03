"""Graph engine — builds process tree and network topology for D3.js."""
import os
from typing import List, Dict, Any


MAX_GRAPH_NODES = int(os.getenv('BLUEHOUND_MAX_GRAPH_NODES', '500'))
MAX_GRAPH_EDGES = int(os.getenv('BLUEHOUND_MAX_GRAPH_EDGES', '2000'))


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

        nodes_map = {}
        edges = []

        for ev in events:
            # Early exit: stop processing if we already have far more nodes than we can display
            if len(nodes_map) > MAX_GRAPH_NODES * 3:
                break
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
            is_network_event = (
                ev.get("event_id") in (3, "3", 5156, "5156")
                or ev.get("event_category") in ("network_connection",)
            )
            if ev.get("destination_ip") and is_network_event:
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

            # Parent → Child edge. Dedup happens below over the full edge set.
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
                edges.append({
                    "source": ppguid,
                    "target": pguid,
                    "type": "SPAWNED",
                    "label": "spawned",
                })

            # Network edge: process → destination
            dst_ip = ev.get("destination_ip")
            if dst_ip and is_network_event:
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

        # ── Truncate graph if too large (prioritize high-severity nodes) ──
        truncated = False
        all_nodes = list(nodes_map.values())
        if len(all_nodes) > MAX_GRAPH_NODES:
            truncated = True
            sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'benign': 0}
            all_nodes.sort(key=lambda n: sev_order.get(n.get('severity', 'benign'), 0), reverse=True)
            kept_nodes = all_nodes[:MAX_GRAPH_NODES]
            kept_ids = {n['id'] for n in kept_nodes}
            # Also keep parents of kept nodes to preserve tree structure
            for e in unique_edges:
                if e['target'] in kept_ids and e['source'] in nodes_map:
                    kept_ids.add(e['source'])
            kept_nodes = [n for n in nodes_map.values() if n['id'] in kept_ids]
            unique_edges = [e for e in unique_edges if e['source'] in kept_ids and e['target'] in kept_ids]
        else:
            kept_nodes = all_nodes

        if len(unique_edges) > MAX_GRAPH_EDGES:
            truncated = True
            unique_edges = unique_edges[:MAX_GRAPH_EDGES]

        return {
            "nodes": kept_nodes,
            "edges": unique_edges,
            "stats": {
                "total_nodes": len(nodes_map),
                "total_edges": len(unique_edges),
                "displayed_nodes": len(kept_nodes),
                "displayed_edges": len(unique_edges),
                "truncated": truncated,
                "critical": sum(1 for n in kept_nodes if n.get("severity") == "critical"),
                "high": sum(1 for n in kept_nodes if n.get("severity") == "high"),
                "medium": sum(1 for n in kept_nodes if n.get("severity") == "medium"),
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
