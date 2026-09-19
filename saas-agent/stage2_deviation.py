"""
Stage 2: Deviation Engine
Takes endpoint_map.json, applies statistical analysis to flag anomalies.
Output: deviations.json
"""

import os
import json
import time
from collections import defaultdict
from dotenv import load_dotenv
from event_emitter import EventEmitter

emit = EventEmitter().emit

load_dotenv()

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")


def load_map():
    path = os.path.join(OUTPUT_DIR, "endpoint_map.json")
    with open(path) as f:
        return json.load(f)


def measure_deviations(data):
    """Measure statistical deviations across all probed endpoints."""
    deviations = []
    all_results = data["all_results"]

    # --- Baseline statistics -------------------------------------------
    status_codes = [r["status_code"] for r in all_results if r["status_code"] > 0]
    response_times = [r["response_time_ms"] for r in all_results if r["status_code"] > 0]
    response_sizes = [r["response_size"] for r in all_results if r["status_code"] > 0]

    if not response_times:
        return deviations

    avg_time = sum(response_times) / len(response_times)
    max_time = max(response_times)
    avg_size = sum(response_sizes) / len(response_sizes)
    max_size = max(response_sizes)

    # --- Per-endpoint analysis ----------------------------------------

    for result in all_results:
        method = result["method"]
        path = result["path"]
        status = result["status_code"]
        elapsed = result["response_time_ms"]
        size = result["response_size"]

        # Skip network errors
        if status == 0:
            continue

        # -- DEVIATION 1: Auth bypass (got 200 on endpoint that should require auth)
        if status == 200 and result.get("is_json"):
            body = result.get("response_body_preview", "").lower()

            # Check for data that shouldn't be visible without auth
            if any(k in body for k in ["user_id", "role", "email", "plan"]):
                if "me" not in path and "login" not in path and "register" not in path:
                    # This endpoint returned user data without login-like action
                    deviations.append({
                        "type": "AUTH_BYPASS",
                        "severity": "HIGH",
                        "method": method,
                        "path": path,
                        "status": status,
                        "finding": "Endpoint returned user data without requiring elevated auth",
                        "evidence": result.get("response_body_preview", "")[:300],
                        "explanation": "This endpoint returned user-level or sensitive data "
                                      "at a status code that suggests no special auth was required. "
                                      "Likely an IDOR or broken access control."
                    })

        # -- DEVIATION 2: Unusually large response (information disclosure)
        if status == 200 and size > avg_size * 3 and size > 1000:
            deviations.append({
                "type": "OVERDISCLOSURE",
                "severity": "MEDIUM",
                "method": method,
                "path": path,
                "status": status,
                "finding": f"Response size ({size} bytes) is {size/avg_size:.1f}x the average ({avg_size:.0f} bytes)",
                "evidence": f"Size: {size} bytes | Avg: {avg_size:.0f} | Max: {max_size}",
                "explanation": "Endpoint returned significantly more data than typical. "
                               "May contain data from other users or internal system information."
            })

        # -- DEVIATION 3: Slow response (internal processing leaked)
        if status == 200 and elapsed > avg_time * 5 and elapsed > 200:
            deviations.append({
                "type": "TIME_ANOMALY",
                "severity": "LOW",
                "method": method,
                "path": path,
                "status": status,
                "finding": f"Response took {elapsed}ms vs avg {avg_time:.0f}ms",
                "evidence": f"Time: {elapsed}ms | Avg: {avg_time:.0f}ms",
                "explanation": "Unusually slow response may indicate server-side processing "
                               "or a resource-intensive operation that could be exploited."
            })

        # -- DEVIATION 4: Secrets in response body
        if result.get("secrets_found"):
            for secret_type in result["secrets_found"]:
                sev = "HIGH"
                if secret_type == "file_path_leak":
                    sev = "MEDIUM"

                deviations.append({
                    "type": "SECRET_EXPOSURE",
                    "severity": sev,
                    "method": method,
                    "path": path,
                    "status": status,
                    "finding": f"Secret type detected: {secret_type}",
                    "evidence": result.get("response_body_preview", "")[:300],
                    "explanation": f"Response contains what appears to be a {secret_type.replace('_', ' ')}. "
                                   "This data should not be visible to this user."
                })

        # -- DEVIATION 5: Sequential ID access (IDOR pattern)
        if status == 200 and ("/{id}" in path or "/{file_id}" in path or "/{filename}" in path):
            # Check if the response contains resource ownership info
            body = result.get("response_body_preview", "").lower()
            if any(k in body for k in ["user_id", "owner", "uploader", "file_path"]):
                deviations.append({
                    "type": "IDOR",
                    "severity": "HIGH",
                    "method": method,
                    "path": path,
                    "status": status,
                    "finding": "ID parameter returned data without ownership verification",
                    "evidence": result.get("response_body_preview", "")[:300],
                    "explanation": "The endpoint accepted an ID parameter and returned resource "
                                   "data without verifying the authenticated user owns that resource. "
                                   "This is a classic Insecure Direct Object Reference (IDOR) vulnerability."
                })

        # -- DEVIATION 6: Scope escalation via PUT
        if method == "PUT" and "api-key" in path and status == 200:
            body = result.get("response_body_preview", "")
            if "scope" in body.lower() and ("admin" in body.lower() or "[" in body):
                deviations.append({
                    "type": "SCOPE_ESCALATION",
                    "severity": "HIGH",
                    "method": method,
                    "path": path,
                    "status": status,
                    "finding": "PUT request to API key endpoint succeeded with scope change",
                    "evidence": body[:300],
                    "explanation": "An authenticated user was able to modify their own API key's scopes. "
                                   "If 'admin' scope was granted, this is a privilege escalation."
                })

        # -- DEVIATION 7: No auth required on admin/system endpoints
        if status == 200 and ("admin" in path or "internal" in path):
            deviations.append({
                "type": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "method": method,
                "path": path,
                "status": status,
                "finding": "Admin or internal endpoint returned 200 without elevated auth",
                "evidence": result.get("response_body_preview", "")[:300],
                "explanation": "An endpoint that should require admin or system-level access "
                               "returned a successful response. This is a direct privilege escalation."
            })

        # -- DEVIATION 8: IDOR on public endpoint
        if status == 200 and "/public/" in path:
            deviations.append({
                "type": "PUBLIC_DATA_EXPOSURE",
                "severity": "MEDIUM",
                "method": method,
                "path": path,
                "status": status,
                "finding": "Publicly accessible endpoint returned resource data",
                "evidence": result.get("response_body_preview", "")[:300],
                "explanation": "A /public/ endpoint returned data without authentication. "
                               "Verify whether this data should truly be public."
            })

        # -- DEVIATION 9: Webhook without signature validation
        if status == 200 and "webhook" in path and "billing" in path:
            deviations.append({
                "type": "WEBHOOK_BYPASS",
                "severity": "CRITICAL",
                "method": method,
                "path": path,
                "status": status,
                "finding": "Webhook endpoint accepted request without signature",
                "evidence": result.get("response_body_preview", ""),
                "explanation": "The webhook endpoint accepted a POST without validating "
                               "the Stripe signature. This allows forging of billing events."
            })

        # -- DEVIATION 10: OAuth callback ignoring state
        if status == 200 and "callback" in path and "oauth" in path:
            body = result.get("response_body_preview", "")
            if "token" in body.lower():
                deviations.append({
                    "type": "OAUTH_CSRF",
                    "severity": "MEDIUM",
                    "method": method,
                    "path": path,
                    "status": status,
                    "finding": "OAuth callback accepted code without state validation",
                    "evidence": body[:300],
                    "explanation": "The OAuth callback accepted an auth code and issued a token "
                                   "without validating the state parameter. This enables CSRF attacks."
                })

    return deviations


def run():
    print("=" * 60)
    print("STAGE 2: Deviation Engine")
    print("=" * 60)
    print()

    print("[1/2] Loading endpoint map...")
    data = load_map()
    total_probed = data["summary"]["total_probed"]
    print(f"      Loaded {total_probed} endpoint results")
    print()

    print("[2/2] Measuring deviations...")
    deviations = measure_deviations(data)

    # Emit each deviation as an event for the dashboard
    for dev in deviations:
        emit("deviation_found", {
            "type": dev.get("type", "?"),
            "severity": dev.get("severity", "INFO"),
            "path": dev.get("path", "?"),
            "method": dev.get("method", "?"),
            "finding": dev.get("finding", ""),
        })

    # Categorize by severity
    critical = [d for d in deviations if d["severity"] == "CRITICAL"]
    high     = [d for d in deviations if d["severity"] == "HIGH"]
    medium   = [d for d in deviations if d["severity"] == "MEDIUM"]
    low      = [d for d in deviations if d["severity"] == "LOW"]

    print()
    print("  Deviation Summary:")
    print(f"    Critical: {len(critical)}")
    print(f"    High:     {len(high)}")
    print(f"    Medium:   {len(medium)}")
    print(f"    Low:      {len(low)}")
    print(f"    Total:    {len(deviations)}")
    print()

    if critical:
        print("  CRITICAL FINDINGS:")
        for d in critical:
            print(f"    [{d['type']}] {d['method']} {d['path']}")
            print(f"             {d['finding']}")
        print()

    if high:
        print("  HIGH SEVERITY FINDINGS:")
        for d in high:
            print(f"    [{d['type']}] {d['method']} {d['path']}")
            print(f"             {d['finding']}")
        print()

    if medium:
        print(f"  MEDIUM SEVERITY: {len(medium)} findings (see deviations.json)")
    if low:
        print(f"  LOW SEVERITY: {len(low)} findings (see deviations.json)")

    # Save output
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_probed": total_probed,
        "total_deviations": len(deviations),
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
        },
        "critical_deviations": critical,
        "high_deviations": high,
        "medium_deviations": medium,
        "low_deviations": low,
        "all_deviations": deviations,
    }

    out_path = os.path.join(OUTPUT_DIR, "deviations.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print()
    print(f"  Saved: {out_path}")
    print()
    print("=" * 60)
    print("STAGE 2 COMPLETE")
    print("=" * 60)

    return {
        "total_deviations": len(deviations),
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium),
        "low": len(low),
        "all_deviations": deviations,
    }


if __name__ == "__main__":
    run()
