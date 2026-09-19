# Red Agent Plan — Pulse Analytics (SaaS Env 2)

**Date:** September 2026
**Target:** Pulse Analytics SaaS Environment
**Objective:** Privilege Escalation from Regular User to System Access
**Method:** Formula-Based Discovery (No Hard-Coded Vulnerabilities)

---

## 1. Overview

Pulse Analytics is a more complex SaaS than Nexus, with 9 integrations:
- OAuth (Google), GitHub, Slack, Stripe Billing, Webhooks, Analytics, API Keys, Admin Panel

The attack surface is wider and the privilege ladder is taller:
```
guest → user → admin → system
```

The target is `/internal/api-keys` which requires `system` role.

---

## 2. Known Attack Chain (for reference)

The red agent discovers this path autonomously:

**Step 1 — V16: Stripe Webhook Dev Mode Bypass → `admin`**
- Endpoint: `POST /billing/stripe-webhook`
- Method: POST a `subscription.updated` event with `metadata.user_id = email`
- Because DEV_MODE=true, Stripe signature validation is skipped
- The webhook looks up user by email and sets role to `admin`

**Step 2 — V20: Admin Role Management → `system`**
- Endpoint: `PATCH /admin/users/{user_id}/role`
- Method: As an admin, POST `new_role=system`
- The admin panel does NOT restrict which roles an admin can assign

**Step 3 — TARGET: `/internal/api-keys` → system role required**
- Reaching this endpoint exposes all internal API keys

---

## 3. Vulnerability Summary

| Vuln | Name | Integration | Severity |
|------|------|-------------|----------|
| V11 | User Profile IDOR | Users | HIGH |
| V12 | Analytics Data Injection | Analytics | MEDIUM |
| V13 | API Key Enumeration | API Keys | MEDIUM |
| V14 | GitHub Token Exposure | GitHub | HIGH |
| V15 | Slack Team ID Disclosure | Slack | LOW |
| V16 | Stripe Webhook Dev Mode Bypass | Billing | CRITICAL |
| V17 | Webhook Payload OAuth Leak | Webhooks | HIGH |
| V18 | Analytics Export IDOR | Analytics | MEDIUM |
| V19 | OAuth State Not Validated | OAuth | MEDIUM |
| V20 | Admin Role Privilege Escalation | Admin | CRITICAL |

---

## 4. Red Agent Stages

### Stage 1: Scanner
Same as Nexus — register, probe every endpoint, collect responses.

Additional endpoint patterns for Pulse:
- `/billing/*` — Stripe integration
- `/github/*` — GitHub integration
- `/slack/*` — Slack integration
- `/analytics/*` — Event tracking
- `/admin/*` — Admin panel
- `/internal/*` — Internal endpoints

### Stage 2: Deviation Engine
Same approach — measure statistical deviations from expected responses.

Key deviations to look for:
- Admin endpoints returning 200 for non-admin users (IDOR)
- Webhook responses containing more data than expected
- Analytics endpoints leaking other users' data

### Stage 3: Permission Graph
Build the role-permission graph from observed behaviors:
- `user` role: basic CRUD on own resources
- `admin` role: admin panel, audit log, user management
- `system` role: internal endpoints (target)

### Stage 4: Chain Validator
Execute the attack path:
1. Discover V16 by probing `/billing/stripe-webhook` with crafted events
2. Discover V20 by examining what `/admin/*` endpoints allow when authenticated as admin
3. Execute admin→system escalation
4. Reach `/internal/api-keys`

---

## 5. Key Differences from Nexus

1. **Longer chain** — 3 steps instead of 2 (Nexus: V6+V10; Pulse: V16+V20)
2. **9 integrations** vs 4 — more attack surface
3. **Webhook token leak (V17/V18)** — separate from Stripe path
4. **OAuth CSRF (V19)** — alternative entry point via state parameter bypass
5. **GitHub token exposure (V14)** — token returned in response body on `/github/connect`

---

## 6. Running the Red Agent Against Pulse

Set `BASE_URL=http://localhost:8001` in `saas-agent/.env` and run:
```bash
cd saas-agent
python run_agent.py
```
