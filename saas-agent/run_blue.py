"""
run_blue.py — Entry point for the blue agent.
Usage:
  python run_blue.py                    # daemon mode (continuous monitoring)
  python run_blue.py --patch-all        # apply all patches immediately
  python run_blue.py --audit            # one-shot audit and exit
  python run_blue.py --red-blue         # run both red and blue agents together
"""

import os
import sys
import argparse
import threading
import time

from blue import BlueAgent
from event_emitter import EventEmitter

emit = EventEmitter().emit

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _print_banner():
    print()
    print("=" * 60)
    print("  BLUE AGENT — Autonomous Security Defender")
    print("=" * 60)
    print()


def _print_status(agent: BlueAgent):
    """Print current vulnerability status."""
    status = agent.get_status()
    print()
    print(f"  Running: {status['running']}")
    print(f"  Breach Detected: {status['breach_detected']}")
    print(f"  Patched: {status['patched_count']}/{status['total_vulns']}")
    print()
    print("  Vulnerability Status:")
    for vuln, state in status["vuln_status"].items():
        icon = "✓" if state in ("applied", "already_patched") else "✗"
        print(f"    [{icon}] {vuln}: {state}")
    print()


def run_daemon(blue: BlueAgent):
    """Run blue agent in continuous monitoring mode."""
    _print_banner()
    print("  Mode: DAEMON (continuous monitoring)")
    print("  Auto-patch: ENABLED")
    print()
    print("  Subscribing to red agent events...")
    print("  Press Ctrl+C to stop.")
    print()

    blue.start()

    try:
        while True:
            time.sleep(5)
            # Periodic status output
            status = blue.get_status()
            patched = status["patched_count"]
            total = status["total_vulns"]
            breach = status["breach_detected"]
            marker = " [BREACH]" if breach else ""
            print(f"\r  [{time.strftime('%H:%M:%S')}] Patched: {patched}/{total} | Breach: {breach}{marker}", end="", flush=True)
    except KeyboardInterrupt:
        print()
        print("\n  Stopping blue agent...")
        blue.stop()
        print("  Stopped.")


def run_patch_all(blue: BlueAgent):
    """Apply all patches and exit."""
    _print_banner()
    print("  Mode: PATCH ALL")
    print()
    print("  Applying patches...")

    results = blue.patcher.apply_all()

    print()
    print("  Results:")
    for vuln_id, result in results.items():
        status = result.get("status", "unknown")
        icon = "✓" if status in ("applied", "already_patched") else "✗"
        desc = result.get("description", "")
        print(f"    [{icon}] {vuln_id}: {status} — {desc}")

    applied = sum(1 for r in results.values() if r.get("status") == "applied")
    already = sum(1 for r in results.values() if r.get("status") == "already_patched")
    print()
    print(f"  Applied: {applied}  |  Already patched: {already}")


def run_audit(blue: BlueAgent):
    """One-shot audit and exit."""
    _print_banner()
    print("  Mode: AUDIT (one-shot)")
    print()
    print("  Scanning vulnerabilities...")

    results = blue.snapshot()

    print()
    print("  Scan Results:")
    for vuln_id, result in sorted(results.items()):
        status = result.get("status", "unknown")
        icon = "✓" if status in ("applied", "already_patched") else "✗"
        desc = result.get("description", "")
        print(f"    [{icon}] {vuln_id}: {status}")
        if status == "applied":
            print(f"         → {desc}")

    applied = sum(1 for r in results.values() if r.get("status") == "applied")
    already = sum(1 for r in results.values() if r.get("status") == "already_patched")
    print()
    print(f"  Patches needed: {applied}  |  Already secure: {already}  |  Total: {len(results)}")


def run_red_blue():
    """Run red agent and blue agent simultaneously."""
    _print_banner()
    print("  Mode: RED vs BLUE (both agents running)")
    print()

    import run_agent

    # Start blue agent in daemon mode first (so it can catch red agent events)
    blue = BlueAgent(auto_patch=True, audit_interval=5)

    def run_red():
        run_agent.main()

    # Launch red agent in background thread
    red_thread = threading.Thread(target=run_red, daemon=True)
    red_thread.start()

    # Start blue agent (blocks)
    run_daemon(blue)


def main():
    parser = argparse.ArgumentParser(description="Blue Agent — Autonomous Security Defender")
    parser.add_argument("--mode", choices=["daemon", "patch-all", "audit", "red-blue"], default="daemon")
    parser.add_argument("--no-auto-patch", action="store_true", help="Disable automatic patching")
    args = parser.parse_args()

    blue = BlueAgent(auto_patch=not args.no_auto_patch)

    if args.mode == "daemon":
        run_daemon(blue)
    elif args.mode == "patch-all":
        run_patch_all(blue)
    elif args.mode == "audit":
        run_audit(blue)
    elif args.mode == "red-blue":
        run_red_blue()


if __name__ == "__main__":
    main()
