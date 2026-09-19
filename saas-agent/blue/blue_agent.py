"""
blue_agent.py — Main blue agent: monitors red agent events, detects exploitation, auto-patches.
Runs in daemon mode (continuous monitoring) or snapshot mode (one-shot audit).
"""

import os
import sys
import time
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_emitter import EventEmitter
from .detector import AnomalyDetector
from .patcher import VulnerabilityPatcher, ALL_PATCHES

emit = EventEmitter().emit


class BlueAgent:
    """
    Autonomous defender agent.
    Subscribes to red agent events via EventEmitter.
    On anomaly detection: auto-apply the matching patch.
    """

    def __init__(self, auto_patch: bool = True, audit_interval: int = 10):
        """
        auto_patch: if True, automatically apply patches when vulns are detected.
        audit_interval: seconds between periodic config audits.
        """
        self.auto_patch = auto_patch
        self.audit_interval = audit_interval

        self.emitter = EventEmitter()
        self.detector = AnomalyDetector()
        self.patcher = VulnerabilityPatcher()

        self.running = False
        self._audit_thread = None

        # Track state
        self.vuln_status = {v: "unpatched" for v in ALL_PATCHES}
        self.breach_detected = False
        self.attack_chain = []

    # ─── Event Handlers ──────────────────────────────────────────────────────

    def _on_any_event(self, event_type: str, data: dict):
        """Catch-all handler for all red agent events."""
        # Check for target breach
        if event_type == "target_reached":
            self._handle_breach(data)
            return

        # Check for escalation steps (attack chain progression)
        if event_type == "escalation_step":
            self._handle_escalation(data)
            return

        # Pass through anomaly detector
        detections = self.detector.check(event_type, data)
        for detection in detections:
            self._handle_detection(detection)

    def _handle_breach(self, data: dict):
        """Red agent successfully reached the target — full incident response."""
        self.breach_detected = True
        self.attack_chain = data.get("attack_chain", [])

        breach_event = {
            "timestamp": datetime.now().isoformat(),
            "severity": "critical",
            "exposed_keys": data.get("exposed_keys", []),
            "attack_chain": self.attack_chain,
        }

        emit("breach_detected", breach_event)

        # Emergency: patch all remaining vulnerabilities
        if self.auto_patch:
            self._emergency_patch_all()

    def _handle_escalation(self, data: dict):
        """Red agent made an escalation step — patch the exploited vuln immediately."""
        step = data.get("step", "")
        vuln_id = self._map_step_to_vuln(step)

        if vuln_id and self.vuln_status.get(vuln_id) == "unpatched":
            if self.auto_patch:
                self._apply_patch_async(vuln_id)

    def _handle_detection(self, detection: dict):
        """Anomaly detector found a vulnerability exploitation pattern."""
        vuln_id = detection["vuln"]

        emit("anomaly_detected", {
            "rule_id": detection["rule_id"],
            "vuln": vuln_id,
            "description": detection["description"],
            "severity": detection["severity"],
            "event_type": detection["event_type"],
        })

        if self.vuln_status.get(vuln_id) == "unpatched" and self.auto_patch:
            self._apply_patch_async(vuln_id)

    # ─── Patch Application ───────────────────────────────────────────────────

    def _apply_patch_async(self, vuln_id: str):
        """Apply a patch in a background thread to avoid blocking the event loop."""
        def apply():
            if self.vuln_status.get(vuln_id) != "unpatched":
                return

            emit("patch_attempt", {"vuln": vuln_id, "timestamp": datetime.now().isoformat()})

            result = self.patcher.apply(vuln_id)
            self.vuln_status[vuln_id] = result.get("status", "unknown")

            emit("patch_applied", {
                "vuln": vuln_id,
                "status": result.get("status"),
                "description": result.get("description", ""),
                "timestamp": datetime.now().isoformat(),
            })

        thread = threading.Thread(target=apply, daemon=True)
        thread.start()

    def _emergency_patch_all(self):
        """Called on breach — patch everything that's not yet patched."""
        emit("patch_all_start", {"timestamp": datetime.now().isoformat()})

        results = {}
        for vuln_id in sorted(ALL_PATCHES.keys()):
            if self.vuln_status.get(vuln_id) == "unpatched":
                result = self.patcher.apply(vuln_id)
                self.vuln_status[vuln_id] = result.get("status", "unknown")
                results[vuln_id] = result

        emit("patch_all_complete", {
            "patched": [v for v, r in results.items() if r.get("status") == "applied"],
            "already_patched": [v for v, r in results.items() if r.get("status") == "already_patched"],
            "failed": [v for v, r in results.items() if r.get("status") not in ("applied", "already_patched")],
            "timestamp": datetime.now().isoformat(),
        })

    # ─── Utility ─────────────────────────────────────────────────────────────

    def _map_step_to_vuln(self, step: str) -> str | None:
        """Map an escalation step description to a vulnerability ID."""
        step_lower = step.lower()
        mapping = {
            "stripe": "V6",
            "webhook": "V6",
            "api-key": "V3",
            "scope": "V3",
            "role": "V10",
            "admin": "V10",
            "file": "V2",
            "idor": "V2",
            "job": "V4",
            "oauth": "V1",
            "token": "V1",
            "upload": "V7",
            "traversal": "V7",
            "path": "V7",
            "email": "V8",
            "tracking": "V8",
            "pixel": "V8",
            "csrf": "V9",
            "oauth": "V9",
        }
        for keyword, vuln_id in mapping.items():
            if keyword in step_lower:
                return vuln_id
        return None

    # ─── Lifecycle ───────────────────────────────────────────────────────────

    def start(self):
        """Start monitoring red agent events."""
        self.running = True
        emit("blue_start", {"mode": "daemon", "auto_patch": self.auto_patch})

        # Subscribe to all events via wildcard
        self.emitter.on("*", self._on_any_event)

        # Start periodic config audit
        self._audit_thread = threading.Thread(target=self._audit_loop, daemon=True)
        self._audit_thread.start()

    def stop(self):
        """Stop monitoring."""
        self.running = False
        emit("blue_stop", {"timestamp": datetime.now().isoformat()})

    def _audit_loop(self):
        """Periodic audit: check config for residual vulnerabilities."""
        while self.running:
            time.sleep(self.audit_interval)
            self._do_audit()

    def _do_audit(self):
        """Perform a configuration audit scan."""
        # Check each vulnerability's current state
        for vuln_id in sorted(ALL_PATCHES.keys()):
            if self.vuln_status[vuln_id] == "unpatched":
                emit("audit_item", {
                    "vuln": vuln_id,
                    "status": "vulnerable",
                    "timestamp": datetime.now().isoformat(),
                })

    def snapshot(self) -> dict:
        """
        Run a one-shot audit: scan all vulnerabilities and report status.
        Does not start monitoring.
        """
        emit("blue_snapshot_start", {"timestamp": datetime.now().isoformat()})

        results = {}
        for vuln_id in sorted(ALL_PATCHES.keys()):
            result = self.patcher.apply(vuln_id)
            status = result.get("status", "unknown")
            self.vuln_status[vuln_id] = status
            results[vuln_id] = result

        emit("blue_snapshot_complete", {
            "results": results,
            "timestamp": datetime.now().isoformat(),
        })

        return results

    def get_status(self) -> dict:
        """Return current blue agent status."""
        return {
            "running": self.running,
            "breach_detected": self.breach_detected,
            "vuln_status": dict(self.vuln_status),
            "detections": self.detector.get_summary(),
            "patched_count": sum(1 for v in self.vuln_status.values() if v in ("applied", "already_patched")),
            "total_vulns": len(self.vuln_status),
        }
