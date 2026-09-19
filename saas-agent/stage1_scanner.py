"""
Stage 1: API Scanner
Registers a user, probes every known endpoint, maps raw behaviors.
Output: endpoint_map.json
"""

import os
import json
import time
import random
import string
import requests
from dotenv import load_dotenv
from event_emitter import EventEmitter

emit = EventEmitter().emit

load_dotenv()

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Generic SaaS endpoint patterns -------------------------------------------
# These patterns apply to ANY SaaS -- not hard-coded to Nexus.
# The agent tries all of them and sees what responds.

ENDPOINT_PATES = [
    # Auth
    ("POST",  "/auth/login"),
    ("POST",  "/auth/register"),
    ("POST",  "/auth/refresh"),
    ("GET",   "/auth/oauth/initiate"),
    ("GET",   "/auth/oauth/callback"),

    # Users
    ("GET",   "/users/me"),
    ("GET",   "/users/{id}"),
    ("GET",   "/users"),

    # Projects
    ("GET",   "/projects"),
    ("POST",  "/projects"),
    ("GET",   "/projects/{id}"),
    ("PUT",   "/projects/{id}"),
    ("DELETE","/projects/{id}"),

    # Files
    ("POST",  "/files/upload"),
    ("GET",   "/files/{id}"),
    ("DELETE","/files/{id}"),
    ("GET",   "/storage/{filename}"),

    # API Keys
    ("GET",   "/api-keys"),
    ("POST",  "/api-keys"),
    ("PUT",   "/api-keys/{id}"),
    ("DELETE","/api-keys/{id}"),

    # Admin Role Management
    ("PUT",   "/admin/users/{id}/role"),

    # Integrations
    ("GET",   "/integrations"),
    ("POST",  "/integrations/connect"),

    # Jobs
    ("GET",   "/jobs"),
    ("POST",  "/jobs"),
    ("GET",   "/jobs/{id}"),
    ("GET",   "/jobs/public/{id}"),

    # Billing
    ("GET",   "/billing"),
    ("POST",  "/billing/subscribe"),
    ("POST",  "/api/v1/billing/webhook"),

    # Email / Notifications
    ("POST",  "/notifications/email"),
    ("GET",   "/api/v1/ext/email/track/{token}"),

    # Webhooks
    ("POST",  "/webhooks"),
    ("GET",   "/webhooks"),

    # OAuth
    ("GET",   "/oauth/tokens"),
    ("POST",  "/oauth/token/store"),

    # Admin
    ("GET",   "/admin/audit"),
    ("GET",   "/admin/settings"),

    # Internal / System
    ("GET",   "/internal/api-keys"),

    # Health
    ("GET",   "/health"),
]

# Template parameter values to try for {id} patterns
ID_VALUES = [
    "1", "2", "3",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
]

TOKEN_VALUES = [
    "abc123",
    "00000000-0000-0000-0000-000000000001",
]

FILENAME_VALUES = [
    "../etc/passwd",
    "../../secret.txt",
    "test.pdf",
]


def random_email():
    suffix = ''.join(random.choices(string.ascii_lowercase, k=8))
    return f"agent_{suffix}@redteam.local"

def random_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

def random_name():
    return ''.join(random.choices(string.ascii_uppercase, k=1)) + \
           ''.join(random.choices(string.ascii_lowercase, k=7))

def expand_endpoint(method, path):
    """Expand path templates with test values. Returns list of (method, path)."""
    results = []

    if "{id}" in path:
        for val in ID_VALUES:
            results.append((method, path.replace("{id}", val)))
    elif "{filename}" in path:
        for val in FILENAME_VALUES:
            results.append((method, path.replace("{filename}", val)))
    elif "{job_id}" in path:
        for val in ID_VALUES:
            results.append((method, path.replace("{job_id}", val)))
    elif "{token}" in path:
        for val in TOKEN_VALUES:
            results.append((method, path.replace("{token}", val)))
    else:
        results.append((method, path))

    return results


def register():
    """Register a new agent user and return token."""
    email = random_email()
    password = random_password()
    name = random_name()

    r = requests.post(f"{BASE_URL}/auth/register", json={
        "email": email,
        "password": password,
        "name": name,
    })
    if r.status_code == 200:
        data = r.json()
        token = data["access_token"]
        api_key = data.get("api_key")
        user_id = data.get("user_id", "")
        # Emit event for dashboard
        emit("agent_registered", {
            "email": email,
            "token": token,
            "api_key": api_key,
            "user_id": user_id,
        })
        return token, email, api_key, user_id
    else:
        raise Exception(f"Registration failed: {r.status_code} {r.text}")


def probe(method, path, token, files_payload=None):
    """Probe a single endpoint. Returns probe result."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    json_body = None
    files = None

    # Special handling for file upload
    if "upload" in path and method == "POST":
        files = {"file": ("probe.txt", b"test content", "text/plain")}
    else:
        # Generic JSON body for POST/PUT
        json_body = {"test": "probe"}

    url = f"{BASE_URL}{path}"
    start = time.time()

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=5)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=json_body, files=files, timeout=5)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=json_body, timeout=5)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=5)
        else:
            return None
    except Exception as e:
        elapsed = time.time() - start
        return {
            "method": method,
            "path": path,
            "status_code": 0,
            "error": str(e),
            "response_time_ms": round(elapsed * 1000, 2),
            "response_size": 0,
        }

    elapsed = time.time() - start
    status = r.status_code

    # Parse response
    try:
        response_json = r.json()
        response_body_str = json.dumps(response_json)
    except Exception:
        response_body_str = r.text[:500] if r.text else ""

    # Extract any tokens or secrets visible in response
    secrets_found = []
    text_lower = r.text.lower()
    if "token" in text_lower:
        secrets_found.append("token_in_response")
    if "secret" in text_lower:
        secrets_found.append("secret_in_response")
    if "key" in text_lower and "api" in text_lower:
        secrets_found.append("api_key_in_response")
    if "password" in text_lower:
        secrets_found.append("password_in_response")
    if "path" in text_lower and ("uploads" in text_lower or "storage" in text_lower):
        secrets_found.append("file_path_leak")

    return {
        "method": method,
        "path": path,
        "status_code": status,
        "response_time_ms": round(elapsed * 1000, 2),
        "response_size": len(r.text),
        "response_body_preview": response_body_str[:500],
        "secrets_found": secrets_found,
        "is_json": "json" in r.headers.get("content-type", ""),
    }


def run():
    """Run the full scan."""
    print("=" * 60)
    print("STAGE 1: API Scanner")
    print("=" * 60)
    print()

    # Step 1: Register agent user
    print("[1/3] Registering agent user...")
    token, email, api_key, user_id = register()
    print(f"      Registered: {email}")
    print(f"      Token: {token[:20]}...")
    print(f"      API Key: {api_key[:20] if api_key else 'N/A'}...")
    print()

    # Step 2: Probe all endpoints
    print("[2/3] Probing all endpoints...")
    results = []
    expanded = []

    for method, path in ENDPOINT_PATES:
        expanded.extend(expand_endpoint(method, path))

    total = len(expanded)
    for i, (method, path) in enumerate(expanded):
        if i % 5 == 0:
            print(f"      [{i+1}/{total}] probing {method} {path}")

        result = probe(method, path, token)
        if result:
            results.append(result)

        # Emit events for dashboard
        emit("scan_progress", {"current": i + 1, "total": total})
        emit("endpoint_probed", {
            "method": method,
            "path": path,
            "status": result["status_code"] if result else 0,
        })

        # Small delay to avoid hammering
        time.sleep(0.02)

    print(f"      Probed {len(results)} endpoints")
    print()

    # Step 3: Categorize results
    print("[3/3] Categorizing results...")

    accessible = [r for r in results if 200 <= r["status_code"] < 300]
    redirect   = [r for r in results if r["status_code"] in (301, 302, 307, 308)]
    auth_fail  = [r for r in results if r["status_code"] in (401,)]
    forbidden  = [r for r in results if r["status_code"] in (403,)]
    not_found  = [r for r in results if r["status_code"] == 404]
    server_err = [r for r in results if 500 <= r["status_code"] < 600]
    errors     = [r for r in results if r["status_code"] == 0]

    # Endpoints that returned data (interesting)
    data_leaks = [r for r in results if r["secrets_found"]]

    print()
    print("  Results:")
    print(f"    Accessible (200-299):    {len(accessible)}")
    print(f"    Auth Required (401):     {len(auth_fail)}")
    print(f"    Forbidden (403):          {len(forbidden)}")
    print(f"    Not Found (404):         {len(not_found)}")
    print(f"    Server Errors (5xx):     {len(server_err)}")
    print(f"    Network Errors:          {len(errors)}")
    print(f"    Potential Data Leaks:     {len(data_leaks)}")

    if data_leaks:
        print()
        print("  Leaked data detected:")
        for r in data_leaks:
            print(f"    [{r['status_code']}] {r['method']} {r['path']}")
            for s in r["secrets_found"]:
                print(f"           -> {s}")
            print(f"           preview: {r['response_body_preview'][:100]}")

    # Save output
    output = {
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "agent_email": email,
        "summary": {
            "total_probed": len(results),
            "accessible": len(accessible),
            "auth_fail": len(auth_fail),
            "forbidden": len(forbidden),
            "not_found": len(not_found),
            "server_errors": len(server_err),
            "errors": len(errors),
            "data_leaks": len(data_leaks),
        },
        "accessible_endpoints": accessible,
        "auth_fail_endpoints": auth_fail,
        "forbidden_endpoints": forbidden,
        "not_found_endpoints": not_found,
        "server_errors": server_err,
        "network_errors": errors,
        "data_leaks": data_leaks,
        "all_results": results,
    }

    out_path = os.path.join(OUTPUT_DIR, "endpoint_map.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print()
    print(f"  Saved: {out_path}")
    print()
    print("=" * 60)
    print("STAGE 1 COMPLETE")
    print("=" * 60)

    # Emit scan complete
    emit("scan_complete", {
        "total": len(results),
        "accessible": len(accessible),
        "leaks": len(data_leaks),
        "email": email,
    })

    return {
        "user_email": email,
        "user_token": token,
        "total_probed": len(results),
        "accessible_count": len(accessible),
        "denied_count": len(auth_fail) + len(forbidden),
        "data_leaks": len(data_leaks),
    }


if __name__ == "__main__":
    run()
