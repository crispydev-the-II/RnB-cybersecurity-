"""
run_agent.py -- Main orchestrator
Runs all 4 stages in sequence, produces the final attack report.
Usage: python run_agent.py
"""

import os
import sys
import json
import time
import importlib.util
from dotenv import load_dotenv

load_dotenv()

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def print_header(title):
    width = 70
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def print_stage(num, name):
    print()
    print(f"[STAGE {num}] {name}")
    print("-" * 50)


def run_stage(stage_num, stage_name, module_path):
    """Load and run a stage module."""
    print_stage(stage_num, stage_name)
    spec = importlib.util.spec_from_file_location(f"stage{stage_num}", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run()


def print_summary(data):
    """Print a formatted summary of attack results."""
    print()
    print_header("ATTACK RESULTS")

    # Support both 'attack_chain' (legacy) and 'steps' (current format)
    steps = data.get("steps") or data.get("attack_chain") or []
    if not steps:
        print("  No attack steps recorded.")
        return

    print()
    print(f"  Target: {data.get('target', 'Unknown')}")
    print(f"  Steps: {len(steps)}")
    print()

    for step in steps:
        status_icon = "[+]" if step.get("success") else "[X]"
        print(f"  {status_icon} {step.get('title', 'Unknown Step')}")
        if step.get('method'):
            print(f"    {step['method']}")
        result = step.get('result') or step.get('description') or "Completed"
        print(f"    {result}")
        print()

    if data.get("success"):
        target_data = data.get("target_data", {})
        keys = target_data.get("internal_api_keys", [])
        print("  *** TARGET REACHED ***")
        print(f"  Internal API keys exposed: {len(keys)}")
        for k in keys[:3]:
            print(f"    - {k.get('name','?')} | {k.get('email','?')} | scopes: {k.get('scopes','?')}")
        if len(keys) > 3:
            print(f"    ... and {len(keys)-3} more")
    else:
        print("  Target not yet reached.")


def main():
    # Start the live dashboard in a background thread
    import threading
    from dashboard import run_dashboard
    dash_thread = threading.Thread(target=run_dashboard, daemon=True)
    dash_thread.start()

    print()
    print()
    print("+============================================================+")
    print("|            NEXUS RED AGENT -- AUTONOMOUS ATTACKER          |")
    print("+============================================================+")
    print(f"  Target: {os.getenv('TARGET_ENDPOINT', '/internal/api-keys')}")
    print(f"  Base:   {os.getenv('BASE_URL', 'http://localhost:8000')}")
    print(f"  Output: {OUTPUT_DIR}/")
    print()
    print("  [Live dashboard active -- see separate panel]")
    print()

    start_time = time.time()

    # -- Stage 1: Scanner
    s1 = run_stage(1, "API Scanner -- Map the territory", "stage1_scanner.py")
    print(f"  Registered user: {s1.get('user_email', 'unknown')}")
    print(f"  Endpoints probed: {s1.get('total_probed', 0)}")
    print(f"  Accessible: {s1.get('accessible_count', 0)}")
    print(f"  Denied: {s1.get('denied_count', 0)}")

    # -- Stage 2: Deviation Engine
    s2 = run_stage(2, "Deviation Engine -- Find anomalies", "stage2_deviation.py")
    print(f"  Total deviations found: {s2.get('total_deviations', 0)}")
    for dev in s2.get("all_deviations", [])[:5]:
        print(f"    [{dev.get('severity', '?')}] {dev.get('type', 'unknown')} at {dev.get('method', '?')} {dev.get('path', '?')}")

    # -- Stage 3: Graph Builder
    s3 = run_stage(3, "Graph Builder -- Map permissions", "stage3_graph.py")
    print(f"  Nodes in graph: {s3.get('node_count', 0)}")
    print(f"  Edges in graph: {s3.get('edge_count', 0)}")
    for edge in s3.get("edges", []):
        print(f"    {edge['from']} -> {edge['to']} via {edge['method']} {edge['endpoint']}")

    # -- Stage 4: Chain Builder
    s4 = run_stage(4, "Chain Builder -- Validate attack path", "stage4_chain.py")
    print_summary(s4)

    elapsed = time.time() - start_time
    print()
    print("=" * 70)
    print(f"  Total time: {elapsed:.1f}s")
    print(f"  Output files written to: {OUTPUT_DIR}/")
    print("=" * 70)

    # Write final report
    report_path = os.path.join(OUTPUT_DIR, "final_report.json")
    with open(report_path, "w") as f:
        json.dump(s4, f, indent=2)
    print(f"\n  Final report: {report_path}")


if __name__ == "__main__":
    main()
