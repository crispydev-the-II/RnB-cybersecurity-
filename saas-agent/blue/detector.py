"""
detector.py — Anomaly detection rules that map red agent events to vulnerability flags.
Uses the EventEmitter singleton to receive red agent events in real time.
"""

from .patcher import ALL_PATCHES


# ─── Detection Rules ────────────────────────────────────────────────────────

ANOMALY_RULES = [
    {
        "id": "V3-api-key-escalation",
        "vuln": "V3",
        "description": "User attempted to escalate API key scope",
        "trigger_on": ["escalation_step"],
        "condition": lambda e: (
            "api-key" in e.get("step", "").lower()
            or "scope" in e.get("step", "").lower()
        ),
    },
    {
        "id": "V6-stripe-bypass",
        "vuln": "V6",
        "description": "Stripe webhook bypass attempted",
        "trigger_on": ["escalation_step"],
        "condition": lambda e: "stripe" in e.get("step", "").lower() or "webhook" in e.get("step", "").lower(),
    },
    {
        "id": "V10-admin-role-escalation",
        "vuln": "V10",
        "description": "Admin role manipulation detected",
        "trigger_on": ["escalation_step"],
        "condition": lambda e: "role" in e.get("step", "").lower() or "admin" in e.get("step", "").lower(),
    },
    {
        "id": "V2-idor-enumeration",
        "vuln": "V2",
        "description": "File IDOR enumeration pattern detected",
        "trigger_on": ["endpoint_probed"],
        "condition": lambda e: e.get("path", "").startswith("/files/") and e.get("status") == 200,
        "severity": "medium",
    },
    {
        "id": "V1-token-leakage",
        "vuln": "V1",
        "description": "OAuth token in webhook payload triggered",
        "trigger_on": ["webhook_triggered"],
        "condition": lambda e: True,
    },
    {
        "id": "V4-job-enumeration",
        "vuln": "V4",
        "description": "Job result enumeration detected",
        "trigger_on": ["endpoint_probed"],
        "condition": lambda e: "/jobs" in e.get("path", "") and e.get("status") == 200,
    },
    {
        "id": "V7-path-traversal",
        "vuln": "V7",
        "description": "File upload path traversal probe detected",
        "trigger_on": ["endpoint_probed"],
        "condition": lambda e: ".." in e.get("path", "") or "passwd" in e.get("path", ""),
    },
]


class AnomalyDetector:
    """Monitors red agent events and detects vulnerability exploitation patterns."""

    def __init__(self):
        self.rules = ANOMALY_RULES
        self.detections = []  # history of all detections
        self._subscribed = {}  # rule_id -> list of matched events

    def check(self, event_type: str, data: dict) -> list[dict]:
        """
        Check an incoming event against all rules.
        Returns list of matched detection objects.
        """
        matched = []

        for rule in self.rules:
            if event_type not in rule["trigger_on"]:
                continue

            try:
                if rule["condition"](data):
                    detection = {
                        "rule_id": rule["id"],
                        "vuln": rule["vuln"],
                        "description": rule["description"],
                        "event_type": event_type,
                        "event_data": data,
                        "severity": rule.get("severity", "high"),
                    }
                    matched.append(detection)
                    self.detections.append(detection)

                    # Track per-rule
                    if rule["id"] not in self._subscribed:
                        self._subscribed[rule["id"]] = []
                    self._subscribed[rule["id"]].append(detection)
            except Exception:
                pass

        return matched

    def check_target_reached(self, data: dict) -> bool:
        """Returns True if the red agent has successfully reached the target."""
        return data.get("exposed_keys") is not None or "target" in str(data).lower()

    def get_summary(self) -> dict:
        """Return a summary of all detections."""
        by_vuln = {}
        for d in self.detections:
            vuln = d["vuln"]
            if vuln not in by_vuln:
                by_vuln[vuln] = []
            by_vuln[vuln].append(d)

        return {
            "total_detections": len(self.detections),
            "unique_vulns": len(by_vuln),
            "by_vulnerability": {v: len(evts) for v, evts in by_vuln.items()},
            "recent": self.detections[-10:],
        }

    def reset(self):
        """Clear detection history."""
        self.detections.clear()
        self._subscribed.clear()
