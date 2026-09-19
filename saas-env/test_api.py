"""Test script for Nexus Workspace SaaS environment."""
import requests
import time
import json

BASE = 'http://localhost:8000'
results = {}

def test(name, condition, detail=""):
    results[name] = condition
    status = 'PASS' if condition else 'FAIL'
    print(f'  [{status}] {name} {detail}')

print("=" * 60)
print("NEXUS WORKSPACE — API TEST SUITE")
print("=" * 60)

# 1. Health check
r = requests.get(f'{BASE}/health')
test('health_check', r.status_code == 200, f'{r.status_code}')
print(f"    → {r.json()}")

# 2. Register two users
r1 = requests.post(f'{BASE}/auth/register', json={'email': 'alice@test.com', 'password': 'pass123', 'name': 'Alice Admin'})
r2 = requests.post(f'{BASE}/auth/register', json={'email': 'bob@test.com', 'password': 'pass456', 'name': 'Bob User'})
alice = r1.json()
bob = r2.json()
test('register_alice', r1.status_code == 200, f'status={r1.status_code}')
test('register_bob', r2.status_code == 200, f'status={r2.status_code}')

alice_token = alice['access_token']
bob_token = bob['access_token']

# 3. Login
r = requests.post(f'{BASE}/auth/login', json={'email': 'alice@test.com', 'password': 'pass123'})
test('login', r.status_code == 200, f'status={r.status_code}')

# 4. Get me
r = requests.get(f'{BASE}/users/me', headers={'Authorization': f'Bearer {alice_token}'})
test('get_me', r.status_code == 200 and r.json().get('role') == 'user', f'role={r.json().get("role")}')

# Save a non-admin alice token for testing ownership checks before upgrading to admin
alice_user_token = alice_token

# 5. Register alice as admin
import sqlite3
conn = sqlite3.connect('nexus.db')
cur = conn.cursor()
cur.execute("UPDATE users SET role='admin' WHERE email='alice@test.com'")
conn.commit()
conn.close()
r = requests.post(f'{BASE}/auth/login', json={'email': 'alice@test.com', 'password': 'pass123'})
alice_token = r.json()['access_token']

# 6. Get another user's details as a regular user (V2: IDOR)
r = requests.get(f'{BASE}/users/{bob["user_id"]}', headers={'Authorization': f'Bearer {bob_token}'})
test('V2_idor_user_enum', r.status_code == 200, f'got email={r.json().get("email")}')
test('V2_idor_not_403', r.status_code != 403, 'user should NOT get 403 for viewing other user')

# 7. List users as admin
r = requests.get(f'{BASE}/users', headers={'Authorization': f'Bearer {alice_token}'})
test('list_users_admin', r.status_code == 200, f'count={len(r.json().get("users", []))}')

# 8. Create API key
r = requests.post(f'{BASE}/api-keys', headers={'Authorization': f'Bearer {bob_token}'}, json={'name': 'Test Key', 'scopes': ['read:files']})
bob_key_id = r.json()['id']
bob_new_key = r.json()['key']
test('create_api_key', r.status_code == 200, f'key={bob_new_key[:20]}...')

# 9. V3: Escalate API key scope to admin
r = requests.put(f'{BASE}/api-keys/{bob_key_id}', headers={'Authorization': f'Bearer {bob_token}'}, json={'name': 'Escalated Key', 'scopes': ['admin']})
test('V3_api_key_escalation', r.status_code == 200, f'scopes={r.json().get("scopes")}')
test('V3_admin_scope_granted', 'admin' in r.json().get('scopes', []), f'admin in scopes: {r.json().get("scopes")}')

# 10. Upload a file
files = {'file': ('secret.txt', b'Secret content - V2 target', 'text/plain')}
r = requests.post(f'{BASE}/files/upload', headers={'Authorization': f'Bearer {bob_token}'}, files=files)
bob_file = r.json()
test('upload_file', r.status_code == 200, f'file_id={bob_file.get("id")}')
print(f"    → URL: {bob_file.get('url')}")

# 11. V2: Alice downloads Bob's file (IDOR)
r = requests.get(f'{BASE}/files/{bob_file["id"]}', headers={'Authorization': f'Bearer {alice_token}'})
test('V2_idor_file_download', r.status_code == 200, f'got file owner={r.json().get("uploader")}')
test('V2_file_path_leaked', 'file_path' in r.json(), f'file_path exposed: {r.json().get("file_path")}')

# 12. Create a project
r = requests.post(f'{BASE}/projects', headers={'Authorization': f'Bearer {bob_token}'}, json={'name': 'Secret Project', 'description': 'Contains sensitive data'})
bob_project = r.json()
test('create_project', r.status_code == 200, f'project_id={bob_project.get("id")[:20]}...')

# 13. Connect integration
r = requests.post(f'{BASE}/integrations/connect', headers={'Authorization': f'Bearer {bob_token}'}, json={'provider': 'stripe'})
test('connect_integration', r.status_code == 200, f'status={r.status_code}')

# 14. Store OAuth token
r = requests.post(f'{BASE}/oauth/token/store', headers={'Authorization': f'Bearer {bob_token}'}, json={'provider': 'google', 'access_token': 'ya29.simulated_stolen_token_xyz'})
test('store_oauth_token', r.status_code == 200, f'status={r.status_code}')

# 15. Connect integration to trigger webhook (V1: tokens in webhook)
r = requests.post(f'{BASE}/integrations/connect', headers={'Authorization': f'Bearer {bob_token}'}, json={'provider': 'email'})
test('webhook_triggered', r.status_code == 200, f'status={r.status_code}')

# 16. Create background job
r = requests.post(f'{BASE}/jobs', headers={'Authorization': f'Bearer {bob_token}'}, json={'job_type': 'report.generate', 'params': {'report_id': 'Q1-2025'}})
bob_job = r.json()
test('create_job', r.status_code == 200, f'job_id={bob_job.get("id")[:20]}...')

# 17. Wait for job completion
time.sleep(1.5)
r = requests.get(f'{BASE}/jobs/{bob_job["id"]}', headers={'Authorization': f'Bearer {bob_token}'})
test('get_job_result', r.status_code == 200 and r.json().get('status') == 'completed', f'status={r.json().get("status")}')

# 18. V4: Access job result without auth (public endpoint)
r = requests.get(f'{BASE}/jobs/public/{bob_job["id"]}')
test('V4_public_job_result', r.status_code == 200, f'owner={r.json().get("owner_user_id")}')

# 19. Subscribe to billing
r = requests.post(f'{BASE}/billing/subscribe', headers={'Authorization': f'Bearer {bob_token}'}, json={'plan_id': 'pro'})
test('subscribe', r.status_code == 200, f'status={r.status_code}')

# 20. V6: Stripe webhook without signature (dev mode bypass)
r = requests.post(f'{BASE}/api/v1/billing/webhook', json={'event_type': 'customer.subscription.deleted', 'data': {'customer_id': 'cus_fake123'}})
test('V6_stripe_bypass', r.status_code == 200, f'status={r.status_code}')
test('V6_webhook_accepted', r.json().get('received') == True, 'webhook accepted without signature')

# 21. V8: Email tracking pixel
r = requests.post(f'{BASE}/notifications/email', headers={'Authorization': f'Bearer {bob_token}'}, json={'to': 'victim@test.com', 'template': 'alert', 'body': '<h1>Hello</h1>'})
test('V8_email_tracking', r.status_code == 200 and r.json().get('tracking_pixel') is not None, f'pixel={r.json().get("tracking_pixel")}')

# 22. Admin-only endpoints blocked for regular users
r = requests.get(f'{BASE}/admin/audit', headers={'Authorization': f'Bearer {bob_token}'})
test('admin_audit_denied', r.status_code == 403, f'status={r.status_code} (expected 403)')

r = requests.get(f'{BASE}/admin/settings', headers={'Authorization': f'Bearer {bob_token}'})
test('admin_settings_denied', r.status_code == 403, f'status={r.status_code} (expected 403)')

# 23. Admin can access admin endpoints
r = requests.get(f'{BASE}/admin/settings', headers={'Authorization': f'Bearer {alice_token}'})
test('admin_settings_allowed', r.status_code == 200, f'status={r.status_code}')
test('V1_stripe_secret_exposed', 'stripe_webhook_secret' in r.json(), f'secret exposed: {r.json().get("stripe_webhook_secret")}')

# 24. V9: OAuth CSRF — callback accepts any state
r = requests.get(f'{BASE}/auth/oauth/callback?code=evil_code&state=any_state')
test('V9_oauth_state_not_validated', r.status_code == 200, f'status={r.status_code}')
test('V9_token_issued_no_validation', 'access_token' in r.json(), 'token issued without state validation')

# 25. Internal API keys (system only — should fail for admin too)
r = requests.get(f'{BASE}/internal/api-keys', headers={'Authorization': f'Bearer {alice_token}'})
test('internal_denied_for_admin', r.status_code == 403, f'status={r.status_code} (expected 403)')

# 26. List integrations
r = requests.get(f'{BASE}/integrations', headers={'Authorization': f'Bearer {bob_token}'})
test('list_integrations', r.status_code == 200, f'available={r.json().get("available")}')

# 27. OAuth initiate
r = requests.get(f'{BASE}/auth/oauth/initiate', headers={'Authorization': f'Bearer {bob_token}'})
test('oauth_initiate', r.status_code == 200, f'status={r.status_code}')

# 28. List jobs
r = requests.get(f'{BASE}/jobs', headers={'Authorization': f'Bearer {bob_token}'})
test('list_jobs', r.status_code == 200, f'count={len(r.json().get("jobs", []))}')

# 29. Get billing
r = requests.get(f'{BASE}/billing', headers={'Authorization': f'Bearer {bob_token}'})
test('get_billing', r.status_code == 200, f'plans={len(r.json().get("plans", []))}')

# 30. Delete project as non-owner (should fail — reset alice to user first)
conn3 = sqlite3.connect('nexus.db')
cur3 = conn3.cursor()
cur3.execute("UPDATE users SET role='user' WHERE email='alice@test.com'")
conn3.commit()
conn3.close()
r = requests.delete(f'{BASE}/projects/{bob_project["id"]}', headers={'Authorization': f'Bearer {alice_user_token}'})
test('delete_other_project_denied', r.status_code == 403, f'status={r.status_code} (expected 403)')

# 31. Admin can delete any project
conn2 = sqlite3.connect('nexus.db')
cur2 = conn2.cursor()
cur2.execute("UPDATE users SET role='admin' WHERE email='alice@test.com'")
conn2.commit()
conn2.close()
r = requests.delete(f'{BASE}/projects/{bob_project["id"]}', headers={'Authorization': f'Bearer {alice_token}'})
r = requests.delete(f'{BASE}/projects/{bob_project["id"]}', headers={'Authorization': f'Bearer {alice_token}'})
test('admin_delete_any', r.status_code == 200, f'status={r.status_code}')

# 32. List audit log as admin
r = requests.get(f'{BASE}/admin/audit', headers={'Authorization': f'Bearer {alice_token}'})
test('admin_audit', r.status_code == 200, f'entries={len(r.json().get("entries", []))}')

print()
print("=" * 60)
print("RESULTS")
print("=" * 60)
passed = 0
failed = []
for name, ok in results.items():
    status = 'PASS' if ok else 'FAIL'
    if ok:
        passed += 1
    else:
        failed.append(name)
    print(f'  [{status}] {name}')

print()
print(f'Total: {passed}/{len(results)} passed')
if failed:
    print(f'Failed: {", ".join(failed)}')
else:
    print('All tests passed!')
