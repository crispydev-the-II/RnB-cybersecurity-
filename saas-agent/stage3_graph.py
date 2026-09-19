"""
Stage 3: Permission Graph Builder
Takes deviations.json, converts them into graph edges.
Output: permission_graph.json

Uses networkx for graph operations.
"""

import os
import json
import time
import networkx as nx
from dotenv import load_dotenv
from event_emitter import EventEmitter

emit = EventEmitter().emit

load_dotenv()

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")

# Permission levels (lowest to highest)
PERMISSION_LEVELS = ["guest", "user", "admin", "system"]


def level_index(level):
    try:
        return PERMISSION_LEVELS.index(level)
    except ValueError:
        return -1


def load_deviations():
    path = os.path.join(OUTPUT_DIR, "deviations.json")
    with open(path) as f:
        return json.load(f)


def build_graph(deviations):
    """
    Convert deviations into graph edges.
    Each deviation is an observation that something unexpected happened.
    We map it to a graph edge: current_permission -> new_permission
    """
    G = nx.DiGraph()

    # Add all permission nodes
    for level in PERMISSION_LEVELS:
        G.add_node(level, permission=level)

    # Track what we know about the current user
    current_level = "user"  # Agent starts as a registered user

    edges_added = []

    def add_edge(from_level, to_level, via_endpoint, via_method, reason, deviation_id):
        if level_index(to_level) > level_index(from_level):
            if not G.has_edge(from_level, to_level):
                G.add_edge(from_level, to_level,
                           endpoint=via_endpoint,
                           method=via_method,
                           reason=reason,
                           deviation_id=deviation_id)
                edges_added.append({
                    "from": from_level,
                    "to": to_level,
                    "endpoint": via_endpoint,
                    "method": via_method,
                    "reason": reason,
                    "deviation_id": deviation_id,
                })
                # Emit graph edge event for dashboard
                emit("graph_edge", {
                    "from_node": from_level,
                    "to_node": to_level,
                    "reason": reason,
                    "method": via_method,
                    "endpoint": via_endpoint,
                })

    for dev in deviations:
        dev_type = dev["type"]
        method = dev["method"]
        path = dev["path"]
        status = dev["status"]
        finding = dev["finding"]

        # -- CRITICAL: Admin/Internal endpoint accessible as user ----------
        if dev_type == "PRIVILEGE_ESCALATION":
            if "internal" in path:
                add_edge("user", "system", path, method,
                         "Internal endpoint accessible without system role", dev_type)
            elif "admin" in path:
                add_edge("user", "admin", path, method,
                         "Admin endpoint accessible without admin role", dev_type)

        # -- HIGH: Scope escalation ----------------------------------------
        elif dev_type == "SCOPE_ESCALATION":
            add_edge("user", "admin", path, method,
                     "API key scope can be escalated to admin level", dev_type)

        # -- HIGH: IDOR ----------------------------------------------------
        elif dev_type == "IDOR":
            # IDOR on users endpoint: can enumerate other users
            if "/users" in path and method == "GET":
                add_edge("user", "user+enum", path, method,
                         "Can enumerate other users' data via IDOR", dev_type)
            # IDOR on files: can download others' files
            elif "/files" in path:
                add_edge("user", "user+idor", path, method,
                         "Can access other users' files without ownership check", dev_type)
            # IDOR on jobs: can read others' job results
            elif "/jobs" in path:
                add_edge("user", "user+idor", path, method,
                         "Can access other users' job results via IDOR", dev_type)

        # -- CRITICAL: Webhook bypass --------------------------------------
        elif dev_type == "WEBHOOK_BYPASS":
            add_edge("user", "admin", path, method,
                     "Stripe webhook accepts forged events, enabling billing manipulation", dev_type)

        # -- HIGH: OAuth CSRF -> token theft ---------------------------------
        elif dev_type == "OAUTH_CSRF":
            add_edge("user", "user+oauth", path, method,
                     "OAuth flow vulnerable to CSRF, enabling token hijacking", dev_type)

        # -- MEDIUM: Secret exposure in responses ----------------------------
        elif dev_type == "SECRET_EXPOSURE":
            secret = dev.get("finding", "")
            if "stripe" in secret.lower() or "webhook_secret" in dev.get("evidence", "").lower():
                add_edge("user", "admin", path, method,
                         "Stripe webhook secret exposed, enabling event forgery", dev_type)
            elif "oauth" in secret.lower() or "client_secret" in dev.get("evidence", "").lower():
                add_edge("user", "user+oauth", path, method,
                         "OAuth client secret exposed in response", dev_type)
            elif "file_path" in dev.get("evidence", "").lower():
                add_edge("user", "user+idor", path, method,
                         "Internal file path exposed, revealing storage structure", dev_type)
            else:
                add_edge("user", "user+info", path, method,
                         f"Sensitive data exposed in response: {secret}", dev_type)

        # -- MEDIUM: Public data exposure -----------------------------------
        elif dev_type == "PUBLIC_DATA_EXPOSURE":
            add_edge("guest", "user+public", path, method,
                     "Public endpoint exposes user data without auth", dev_type)

        # -- HIGH: Auth bypass ----------------------------------------------
        elif dev_type == "AUTH_BYPASS":
            add_edge("guest", "user", path, method,
                     "Endpoint returned user data without proper auth", dev_type)

        # -- MEDIUM: Over-disclosure -----------------------------------------
        elif dev_type == "OVERDISCLOSURE":
            add_edge("user", "user+info", path, method,
                     "Endpoint discloses more data than expected", dev_type)

    return G, edges_added


def find_all_paths_to_target(G, start="user", target="system"):
    """
    Find all paths from start to target permission level.
    Uses BFS to find shortest paths.
    """
    paths = []

    if not G.has_node(target):
        return paths

    if not G.has_node(start):
        return paths

    try:
        # BFS for all simple paths (limited depth)
        all_paths = list(nx.all_simple_paths(G, start, target, cutoff=10))
        paths = all_paths
    except nx.NetworkXNoPath:
        pass

    return paths


def run():
    print("=" * 60)
    print("STAGE 3: Permission Graph Builder")
    print("=" * 60)
    print()

    print("[1/3] Loading deviations...")
    data = load_deviations()
    deviations = data["all_deviations"]
    print(f"      Loaded {len(deviations)} deviations")
    print()

    print("[2/3] Building permission graph...")
    G, edges_added = build_graph(deviations)

    print()
    print("  Graph Nodes:")
    for node in G.nodes():
        in_deg = G.in_degree(node)
        out_deg = G.out_degree(node)
        print(f"    {node:20s}  (in: {in_deg}, out: {out_deg})")

    print()
    print("  Graph Edges (Permission Escalations):")
    if edges_added:
        for e in edges_added:
            print(f"    {e['from']:10s} -> {e['to']:15s} via {e['method']:6s} {e['endpoint']}")
            print(f"             Reason: {e['reason']}")
    else:
        print("    No escalation edges found!")
    print()

    print("[3/3] Searching for paths to target (system)...")

    # Check if system is reachable from user
    if not G.has_edge("user", "system") and not nx.has_path(G, "user", "system"):
        print("  WARNING: Cannot reach 'system' level from current position.")
        print("  Attempting to find path through intermediate nodes...")

    paths = find_all_paths_to_target(G, "user", "system")

    if paths:
        print(f"  Found {len(paths)} path(s) to system access:")
        for i, path in enumerate(paths):
            print(f"    Path {i+1}: {' -> '.join(path)}")
    else:
        print("  No complete path to 'system' found yet.")
        print("  Checking intermediate reachability...")

        for target in ["admin", "user+enum", "user+idor", "user+oauth", "user+info"]:
            if G.has_node(target):
                if nx.has_path(G, "user", target):
                    print(f"    user -> {target}: YES (via existing edges)")
                else:
                    print(f"    user -> {target}: NO")

    # Save graph data
    graph_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "nodes": [{"id": n, "permission": G.nodes[n].get("permission", n)} for n in G.nodes()],
        "edges": [
            {
                "from": u,
                "to": v,
                "endpoint": G.edges[u, v].get("endpoint"),
                "method": G.edges[u, v].get("method"),
                "reason": G.edges[u, v].get("reason"),
                "deviation_id": G.edges[u, v].get("deviation_id"),
            }
            for u, v in G.edges()
        ],
        "paths_to_system": [
            {"path": p, "length": len(p) - 1}
            for p in paths
        ],
        "graph_stats": {
            "total_nodes": G.number_of_nodes(),
            "total_edges": G.number_of_edges(),
            "paths_to_system": len(paths),
        }
    }

    out_path = os.path.join(OUTPUT_DIR, "permission_graph.json")
    with open(out_path, "w") as f:
        json.dump(graph_data, f, indent=2, default=str)

    print()
    print(f"  Saved: {out_path}")
    print()
    print("=" * 60)
    print("STAGE 3 COMPLETE")
    print("=" * 60)

    return {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "edges": edges_added,
        "paths_to_system": len(paths),
    }


if __name__ == "__main__":
    run()
