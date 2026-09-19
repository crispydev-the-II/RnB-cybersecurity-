# Nexus Red Agent

An autonomous red-team agent that discovers and exploits security vulnerabilities in a simulated SaaS environment — without any prior knowledge of the system.

It works in 4 stages:

```
┌──────────────────────────────────────────────────────────────┐
│  STAGE 1: Scanner                                           │
│  Probes every endpoint of the SaaS like a robot finger     │
│  tapping every door to see which ones open                 │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 2: Deviation Engine                                  │
│  Analyzes all responses for anything strange or unexpected  │
│  Flags 18 types of potential vulnerabilities (V1–V18)     │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 3: Permission Graph Builder                           │
│  Maps out the "permission ladder" — how roles connect       │
│  Finds paths from a regular user up to the most powerful   │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│  STAGE 4: Chain Validator & Attacker                         │
│  Actually executes the attack — climbs the permission       │
│  ladder step by step until reaching the target             │
└──────────────────────────────────────────────────────────────┘
```

**Result:** The agent discovers a target (like `/internal/api-keys`), finds a path to it, and extracts the sensitive data — all autonomously.

---

## What It Found in the Simulated SaaS

| Vulnerability | Type | Severity | How It Was Exploited |
|---|---|---|---|
| V6 | Stripe Webhook Bypass | CRITICAL | Forged a webhook event to promote its own account to admin |
| V10 | Admin Role Management | CRITICAL | As admin, changed its own role to `system` |
| V3 | API Key Scope Escalation | HIGH | Modified its own API key's scopes to gain admin |
| V1 | OAuth Token Leakage | HIGH | Leaked OAuth tokens via webhook response |
| V2 | IDOR (Insecure Direct Object Reference) | HIGH | Accessed other users' files by guessing IDs |

**Target reached: `/internal/api-keys` — all API keys in the database exposed.**

---

## Architecture

```
saas-project/
├── saas-env/          ← The simulated SaaS being attacked (Nexus Workspace)
│   ├── main.py        ← FastAPI server with planted vulnerabilities
│   ├── nexus.db       ← SQLite database (holds users, API keys, etc.)
│   └── storage/       ← File upload directory (exploited via path traversal)
│
└── saas-agent/        ← The red team agent (attacker)
    ├── run_agent.py   ← Orchestrator — runs all 4 stages in sequence
    ├── event_emitter.py ← Publish/subscribe system for live dashboard
    ├── dashboard.py   ← Live terminal visualization
    ├── stage1_scanner.py    ← Probes every endpoint
    ├── stage2_deviation.py ← Finds anomalies in responses
    ├── stage3_graph.py      ← Builds permission ladder graph
    ├── stage4_chain.py      ← Validates attack path live
    └── output/        ← Generated attack reports
```

**The agent knows nothing about the vulnerabilities ahead of time.** It discovers them by probing, observing, and reasoning.

---

## Prerequisites

- **Python 3.10+**
- **Git**
- **GitHub account** (to push)
- No other tools needed — all dependencies are in `requirements.txt`

---

## Installation

```bash
# 1. Navigate to the project folder
cd "D:\saas project capstone final"

# 2. Set up the SaaS environment
cd saas-env
pip install -r requirements.txt

# 3. Set up the red agent
cd ../saas-agent
pip install -r requirements.txt
```

**Requirements for saas-env:**
- fastapi
- uvicorn
- python-multipart (for file uploads)
- python-jose (for JWT tokens)
- passlib (for password hashing)
- pydantic

**Requirements for saas-agent:**
- requests
- python-dotenv
- networkx (for graph operations)
- rich (for live terminal dashboard)

---

## Running

### Step 1: Start the SaaS environment

```bash
cd saas-env
python main.py
```

You'll see:
```
============================================================
  Nexus Workspace v1.0.0
============================================================
  Vulnerabilities planted:
  [V1] OAuth Token Leakage via Webhook
  [V2] Insecure Direct Object Reference on Files
  [V3] API Key Privilege Escalation
  [V4] Job Result Information Disclosure
  [V5] Webhook Replay Attack
============================================================
INFO:     Uvicorn running on http://127.0.0.1:8000
```

Keep this terminal open.

### Step 2: Run the red agent

```bash
cd saas-agent
python run_agent.py
```

The agent runs autonomously and takes about **3–4 minutes**. You'll see:
- Terminal text output from each stage
- A **live dashboard** rendering in real-time showing:
  - Endpoints being probed
  - Vulnerabilities appearing as they're found
  - The permission graph building
  - The attack chain executing step by step

---

## Output Files

After running, check `saas-agent/output/`:

| File | Contents |
|---|---|
| `endpoint_map.json` | Every endpoint, its status code, response size, and whether it leaked data |
| `deviations.json` | All anomalies found with severity, type, and evidence |
| `permission_graph.json` | Nodes (roles) and edges (escalation paths) |
| `attack_chain.json` | The validated attack path with all steps and target data |
| `final_report.json` | Human-readable summary of the full attack |

---

## How the Attack Chain Works (Simple Explanation)

The agent starts as a **regular user** (like you signing up for a SaaS). It needs to reach `/internal/api-keys` which only the system administrator can access.

**Step 1 — User to Admin:**
The agent discovers that the Stripe webhook endpoint accepts events without verifying the signature. It sends a forged event saying "this user's role is now admin" — and the system believes it.

**Step 2 — Admin to System:**
The agent, now acting as admin, calls a role management endpoint. It tells the server "change my role from admin to system." The server complies — because that's a normal admin function.

**Step 3 — System to Target:**
The agent accesses `/internal/api-keys` using its system-level token and pulls every API key in the database.

No individual step is catastrophic. The power comes from chaining them together.

---

## The Live Dashboard

While running, the terminal shows a rich live-updating dashboard:

```
┌─────────────────────────────────────────────────────────────────┐
│  NEXUS RED AGENT  ● LIVE  │  Target: /internal/api-keys        │
├──────────────────────────┬──────────────────────────────────────┤
│  ENDPOINT SCANNER       │  ANOMALIES DETECTED                  │
│  88 probed | 23 ok      │  [!CRIT] webhook_bypass             │
│  [200] GET /users/me    │  [!HIGH] idor_file_access           │
│  [200] POST /files      │  [!HIGH] secret_exposure            │
├──────────────────────────┴──────────────────────────────────────┤
│  PERMISSION GRAPH                                                  │
│  guest ──> user ──> admin ──> system                            │
├─────────────────────────────────────────────────────────────────┤
│  ATTACK CHAIN                                                     │
│  [1] V6: Webhook Bypass            [SUCCESS]                   │
│  [2] V10: Role Management           [SUCCESS]                   │
│  [3] Target: /internal/api-keys      [SUCCESS]                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Origin

This was built as a capstone project to explore autonomous red-teaming in simulated SaaS environments. The agent discovers vulnerabilities through API probing and response analysis — no hardcoded exploit knowledge.

**The simulated SaaS is deliberately vulnerable** (that's the point — it's a training environment). The vulnerabilities are planted as specific code patterns in `saas-env/main.py`.

---

## Pushing to GitHub

```bash
cd "D:\saas project capstone final"

git init
git add .
git commit -m "Initial commit: Nexus Red Agent v1.0

- saas-env: Simulated SaaS with planted vulnerabilities
- saas-agent: 4-stage autonomous red team agent
- Live terminal dashboard with rich
- Full attack chain: user -> admin -> system -> target"

git remote add origin https://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@github.com/crispydev-the-II/RnB-cybersecurity-.git
git branch -M main
git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username in the remote URL.

---

## Disclaimer

This project is for **educational and authorized security research only**. The simulated SaaS environment contains intentional vulnerabilities. Do not use these techniques against systems you don't own or have explicit written permission to test.
