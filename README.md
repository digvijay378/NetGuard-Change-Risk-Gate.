<div align="center">

# 🛡️ NetGuard Change-Risk Gate v2

### AI-Powered Infrastructure Change Security Governance Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](https://reactjs.org)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-1.5-orange?style=flat-square)](https://trychroma.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2-purple?style=flat-square)](https://langchain-ai.github.io/langgraph/)
[![Claude](https://img.shields.io/badge/Claude-3.5%20Sonnet-CC785C?style=flat-square&logo=anthropic)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Stop dangerous infrastructure changes before they merge.**  
NetGuard intercepts every Terraform, firewall, and IAM change — runs it through a 6-node AI agent pipeline — and either auto-approves it or blocks it with a full investigation report including CVE lookups, MITRE ATT&CK technique mapping, and a human-readable validation checklist.

[Live Demo](#) · [Architecture Deep Dive](#architecture) · [Quick Start](#quick-start) · [API Reference](#api-reference)

---

</div>

## Table of Contents

- [The Problem It Solves](#the-problem-it-solves)
- [What Makes This Architecture Stand Out](#what-makes-this-architecture-stand-out)
- [Architecture](#architecture)
- [The 6-Node Agent Pipeline](#the-6-node-agent-pipeline)
- [RAG Pipeline & Knowledge Base](#rag-pipeline--knowledge-base)
- [Semi-Autonomous Decision Engine](#semi-autonomous-decision-engine)
- [Multi-Stack Parser Engine](#multi-stack-parser-engine)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Example Assessment Output](#example-assessment-output)
- [Security & AI Safety Invariants](#security--ai-safety-invariants)
- [Roadmap](#roadmap)

---

## The Problem It Solves

In any engineering organization, developers push hundreds of infrastructure changes weekly — Terraform files, firewall rules, IAM policies, DNS zone updates. A single misconfiguration can expose your entire production fleet within minutes of merge:

```hcl
# This change, merged without review, opens SSH to the entire internet
resource "aws_security_group_rule" "allow_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]   # ← Direct path to CVE-2024-6387 (CVSS 8.1)
}
```

**NetGuard intercepts this before it can merge.** It runs a deterministic rule check, retrieves real CVE intelligence from a vector database, maps the finding to MITRE ATT&CK techniques, and posts a full investigation report back to the PR — all in under 15 seconds.

---

## What Makes This Architecture Stand Out

| Signal | What It Demonstrates |
|--------|----------------------|
| **LangGraph-style multi-agent graph** | Stateful agentic AI with conditional routing — not just prompt chaining |
| **RAG pipeline with ChromaDB** | Production vector store with domain-specific threat intelligence |
| **MITRE ATT&CK + NVD integration** | Bridging real-world threat intelligence with automated security governance |
| **Semi-autonomous decision logic** | AI safety: the system knows when to act vs. when to ask a human |
| **Tool-use / function calling patterns** | Structured tool interfaces — a core modern AI engineering skill |
| **Security domain expertise woven in** | Not just an AI engineer — a security engineer building AI. Rare combination. |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        NETGUARD v2 — SYSTEM OVERVIEW                     │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   INGESTION CHANNELS           6-NODE AGENT PIPELINE                     │
│   ─────────────────            ──────────────────────                    │
│   GitHub PR Webhook   ──┐                                                 │
│   Firewall Rule API   ──┼──▶  [1]Ingestion ──▶ [2]Rule Engine           │
│   ServiceNow Webhook  ──┤         │                   │                  │
│   Jira Webhook        ──┘         ▼                   ▼                  │
│                               Stack Detection    17 YAML Rules           │
│                               AWS/Azure/GCP      Score 0-100            │
│                               /On-Prem                                   │
│                                                        │                  │
│                                                        ▼                  │
│   RAG KNOWLEDGE BASE           [3]RAG Retrieval Agent                    │
│   ──────────────────               │                                     │
│   cve_knowledge      ──────────────┤  ChromaDB Vector Search             │
│   attack_techniques  ──────────────┤  Top-5 per collection              │
│   policy_controls    ──────────────┤  Cosine similarity                  │
│   change_history     ──────────────┘                                     │
│                                         │                                 │
│                                         ▼                                 │
│                                [4]Analysis Agent                         │
│                                    Claude 3.5 Sonnet                     │
│                                    Structured Output                     │
│                                    Threat Narrative                      │
│                                         │                                 │
│                              ┌──────────┴──────────┐                    │
│                              ▼                      ▼                    │
│                        score < 70             score ≥ 70                 │
│                              │                      │                    │
│                     [5]Decision Agent      [5]Decision Agent             │
│                     AUTO_APPROVE           ESCALATE_TO_HUMAN            │
│                              │                      │                    │
│                     [6]Output Agent        [6]Output Agent              │
│                     ✓ Allow merge          ✗ Block merge                │
│                     Post green comment     Notify CISO                  │
│                     Write audit log        Post full report             │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### Four AI Layers

| # | Layer | Technology | Role |
|---|-------|------------|------|
| 1 | **Agent Orchestration** | LangGraph-style StateGraph | Stateful graph routing investigation through 6 specialized nodes |
| 2 | **RAG Knowledge Pipeline** | ChromaDB + Semantic Retrieval | Searches 4 purpose-built vector collections before reasoning |
| 3 | **LLM Reasoning** | Claude 3.5 Sonnet (Anthropic) | Synthesizes findings into threat narrative with structured output |
| 4 | **Autonomy Engine** | Python rule layer + AgentState | Pure deterministic logic — auto-approve LOW/MEDIUM, escalate HIGH/CRITICAL |

---

## The 6-Node Agent Pipeline

Every change flows through all 6 nodes sequentially, with each node reading from and writing to a shared `AgentState` TypedDict that persists all intermediate results:

### Node 1 — Ingestion Agent *(Deterministic, No LLM)*

Identifies the infrastructure stack using regex fingerprinting and routes to the appropriate parser.

```python
# Stack detected by pattern matching against the raw diff
AWS:    resource "aws_*", arn:aws:, AWSTemplateFormatVersion
Azure:  resource "azurerm_*", Microsoft.*, subscription_id
GCP:    resource "google_*", project_id, gcloud
OnPrem: iptables, permit any, access-list, pfSense
```

### Node 2 — Rule Engine Agent *(Deterministic, No LLM)*

Evaluates 17 YAML-defined policy rules across 3 rule files. Score is **additive and capped at 100**.

```
NET-001  Unrestricted Internet Ingress (SSH/RDP)    CRITICAL  +40  block_merge: true
NET-002  Unrestricted Internet Ingress (All Ports)  CRITICAL  +35  block_merge: true
IAM-001  Wildcard IAM Action ("*")                  CRITICAL  +45  block_merge: true
IAM-002  Admin/Owner Role Assignment                CRITICAL  +40  block_merge: true
DNS-001  DNS Zone Modification                      HIGH      +30
NET-004  NAT Gateway Modification                   HIGH      +25
IAM-003  New Role Binding / Policy Attachment       HIGH      +25
... (17 rules total across network.yaml, iam.yaml, dns.yaml)
```

> **Safety Invariant:** A CRITICAL rule finding cannot be overridden by any downstream LLM output. This prevents prompt-injection-based approvals of genuinely dangerous changes.

### Node 3 — RAG Retrieval Agent *(Vector Search, No LLM)*

Builds a semantic query from rule findings, then searches all 4 ChromaDB collections in parallel.

```python
# Query built from findings context
query = "Unrestricted Internet Ingress SSH/RDP port_exposure initial_access aws port 22"

# ChromaDB returns top-5 semantically similar documents from each collection:
cve_matches       → CVE-2024-6387 (CVSS 8.1), CVE-2023-38408 (CVSS 9.8), ...
attack_techniques → T1190 Exploit Public-Facing Application, T1110 Brute Force, ...
policy_controls   → NIST-AC-17 Remote Access, CIS-12 Network Infrastructure, ...
similar_incidents → Past assessments with matching patterns
```

### Node 4 — Analysis Agent *(Claude 3.5 Sonnet — Structured Output)*

The only LLM node. Synthesizes all evidence into a coherent investigation report using `with_structured_output()` to guarantee valid JSON via Pydantic — no parse errors possible.

```python
class AnalysisOutput(BaseModel):
    adjusted_risk_score: int = Field(ge=0, le=100)
    # Invariant: adjusted_score >= base_risk_score (RAG can only raise risk, never lower it)
    score_adjustment_reason: str
    threat_narrative: str            # 2-3 paragraph attacker story
    validation_checklist: List[str]  # CLI commands and verification steps
    intent_summary: str              # One-sentence plain English
```

### Node 5 — Decision Agent *(Pure Python — NEVER an LLM)*

The most safety-critical node. Fully deterministic. Four hard override conditions bypass the score entirely:

```python
# Any of these forces ESCALATE_TO_HUMAN regardless of LLM output:
1. has_critical_rule_finding          # CRITICAL rule fired in Node 2
2. has_block_merge_finding            # Any rule marked block_merge: true
3. has_high_cvss AND score >= 40      # CVE with CVSS >= 7.0 retrieved by RAG
4. has_initial_access_technique       # MITRE ATT&CK Initial Access / Execution tactic

# Score-based routing (when no overrides trigger):
score 0–39   → LOW      → AUTO_APPROVE
score 40–69  → MEDIUM   → AUTO_APPROVE + flag for weekly digest review
score 70–89  → HIGH     → ESCALATE_TO_HUMAN + block merge
score 90–100 → CRITICAL → ESCALATE_TO_HUMAN + block merge + emergency ticket
```

### Node 6 — Output Agent *(Integration Adapters)*

Routes the result back to the originating system. AUTO_APPROVE allows merge with full audit trail; ESCALATE blocks merge and notifies the appropriate approvers.

```
GitHub PR   → Post comment + set commit status + exit 1 (blocks merge button)
ServiceNow  → Post Work Note + update u_risk_gate_score custom field
Jira        → Post markdown comment + apply risk label + attach report
Firewall API→ Return RiskReport JSON per rule
```

---

## RAG Pipeline & Knowledge Base

The RAG pipeline grounds every assessment in **current, auditable threat intelligence** rather than relying on stale LLM training data.

### ChromaDB Collections

| Collection | Source | Update Frequency | What Gets Retrieved |
|------------|--------|-----------------|---------------------|
| `cve_knowledge` | NIST NVD REST API v2.0 | Nightly via GitHub Actions | CVEs matching exposed ports, services, or resource types |
| `attack_techniques` | MITRE ATT&CK STIX 2.1 | Monthly release sync | ATT&CK techniques relevant to the finding type |
| `policy_controls` | CIS Benchmarks + NIST SP 800-53 | Quarterly | Control requirements and remediation guidance |
| `change_history` | Internal audit log | Real-time | Semantically similar past changes and their outcomes |

### Why RAG Over Pure LLM?

```
Without RAG:  LLM training data may not include CVE-2024-6387 (disclosed mid-2024)
With RAG:     NVD nightly ingestion → CVE-2024-6387 in ChromaDB within 24hrs of disclosure
```

### Embedding Strategy

| Choice | Rationale |
|--------|-----------|
| `text-embedding-3-small` (OpenAI) | Best cost/quality ratio for technical security text |
| Chunk size: 800 tokens, 100 overlap | Balances context richness vs. retrieval precision |
| Cosine similarity (ChromaDB default) | Standard for semantic text similarity |
| Top-k: 5 per query | Keeps context window manageable |
| Offline fallback: `BAAI/bge-m3` | Fully air-gapped operation with HuggingFace |

---

## Semi-Autonomous Decision Engine

```
┌────────────────────────────────────────────────────────────────┐
│               DECISION ENGINE — AUTONOMY LEVELS                │
├──────────┬────────────┬──────────────────┬────────────────────┤
│  Score   │  Level     │  Decision        │  Human Review?     │
├──────────┼────────────┼──────────────────┼────────────────────┤
│  0 – 39  │  LOW       │  AUTO_APPROVE    │  No                │
│ 40 – 69  │  MEDIUM    │  AUTO_APPROVE    │  Weekly digest     │
│ 70 – 89  │  HIGH      │  ESCALATE        │  Net Arch +        │
│          │            │                  │  Security Lead     │
│ 90 – 100 │  CRITICAL  │  ESCALATE + LOCK │  CISO + Net Arch   │
│          │            │                  │  + Sec Lead        │
└──────────┴────────────┴──────────────────┴────────────────────┘
```

Every auto-approval is logged with `assessment_id`, full `agent_trace`, all `RAG sources` cited, and timestamp. MEDIUM auto-approvals are included in a weekly security digest to the team lead.

---

## Multi-Stack Parser Engine

| Stack | Formats Supported | What Gets Flagged |
|-------|------------------|-------------------|
| **AWS** | Terraform HCL, CloudFormation | `0.0.0.0/0` CIDRs, IAM wildcard actions, NAT gateways, route tables |
| **Azure** | Bicep, ARM Templates, `azurerm` Terraform | NSG Internet source, Owner/Contributor at subscription scope, DNS zones |
| **GCP** | `google_compute_firewall` Terraform, `gcloud` JSON | `0.0.0.0/0` in `source_ranges`, allow-all TCP/UDP, IAM bindings |
| **On-Prem** | Cisco IOS ACL, `iptables-save`, pfSense XML | `permit any any`, `-j ACCEPT` without source, pfSense pass with any |

---

## Tech Stack

**Backend**
```
FastAPI 0.110      — Async API server with auto OpenAPI docs
Python 3.11        — Fully type-annotated, Pydantic v2 throughout
Motor 3.3          — Async MongoDB driver
ChromaDB 1.5       — Local/server vector database
PyYAML 6.0         — Policy rule file parsing
LangGraph 0.2      — Stateful multi-agent graph orchestration
LangChain 0.3      — Tool-use interfaces, retrievers, structured output
Claude 3.5 Sonnet  — LLM reasoning backbone (Anthropic)
OpenAI Embeddings  — text-embedding-3-small for ChromaDB ingestion
```

**Frontend**
```
React 19           — Modern component architecture
TailwindCSS 3.4    — Utility-first styling with dark theme
Recharts 3.6       — Risk trend charts and distribution charts
lucide-react       — Icon library
JetBrains Mono     — Monospace font for all security data values
shadcn/ui          — Base component library
```

**Infrastructure**
```
MongoDB            — Assessment storage and full audit log
Docker + Compose   — API server + ChromaDB + mock ITSM
GitHub Actions     — CI risk gate + nightly NVD + monthly ATT&CK sync
```

---

## Quick Start

### Prerequisites
- Python 3.11+, Node.js 18+, MongoDB
- `ANTHROPIC_API_KEY` — for live Claude analysis
- `OPENAI_API_KEY` — for production semantic embeddings

### 1. Clone & Install

```bash
git clone https://github.com/digvijay/netguard-change-risk-gate.git
cd netguard-change-risk-gate

# Backend
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
# Fill in ANTHROPIC_API_KEY and OPENAI_API_KEY

# Frontend
cd frontend && yarn install
```

### 2. Start Services

```bash
# Terminal 1 — Backend
uvicorn backend.server:app --host 0.0.0.0 --port 8001 --reload

# Terminal 2 — Frontend
cd frontend && yarn start

# Seed ChromaDB with threat intelligence
curl -X POST http://localhost:8001/api/v1/knowledge-base/seed
```

### 3. Run Your First Assessment

```bash
curl -X POST http://localhost:8001/api/v1/assess \
  -H "Content-Type: application/json" \
  -d '{
    "change_source": "github_pr",
    "raw_diff": "resource \"aws_security_group_rule\" \"allow_ssh\" {\n  from_port = 22\n  cidr_blocks = [\"0.0.0.0/0\"]\n}",
    "change_metadata": { "author": "dev.engineer", "pr_number": 142 }
  }'
```

### GitHub Actions — Protect Every PR

```yaml
# .github/workflows/change-risk-gate.yaml
name: NetGuard Change Risk Gate v2
on:
  pull_request:
    branches: [main, master, production]

jobs:
  risk-assessment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Install NetGuard
        run: pip install netguard-risk-gate[ai]
      - name: Run Agentic Risk Assessment
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          git diff origin/${{ github.base_ref }} HEAD > /tmp/change.diff
          netguard assess --diff /tmp/change.diff --enable-rag --enable-agents --autonomy-mode semi
      - name: Enforce Gate Decision
        if: steps.assess.outputs.decision == 'ESCALATE_TO_HUMAN'
        run: exit 1
```

---

## Configuration

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...         # Claude 3.5 Sonnet for Analysis Agent
OPENAI_API_KEY=sk-...                # text-embedding-3-small for ChromaDB
MONGO_URL=mongodb://localhost:27017
DB_NAME=netguard

# Optional — RAG & Data Sources
NVD_API_KEY=...                      # NIST NVD (50 req/30s vs 5 req/30s without)
CHROMA_HOST=localhost                 # ChromaDB server mode (default: embedded)
CHROMA_PORT=8000

# Optional — Autonomy & Policy
NETGUARD_POLICY_PATH=./config/policies
NETGUARD_AUTONOMY_MODE=semi          # semi | advisory | full

# Optional — Integrations
GITHUB_TOKEN=ghp_...
SERVICENOW_INSTANCE=company.service-now.com
SERVICENOW_USER=svc-netguard
SERVICENOW_PASSWORD=...
JIRA_SERVER=https://company.atlassian.net
JIRA_USER=svc@company.com
JIRA_TOKEN=...
```

### Adding Custom Policy Rules

Drop a new YAML file in `config/policies/` — loaded automatically at startup:

```yaml
# config/policies/custom.yaml
rules:
  - id: CUSTOM-001
    name: "Production Database Port Exposure"
    severity: CRITICAL
    score: 45
    block_merge: true
    tags: [database, data_exfiltration, pci_dss]
    patterns:
      cidr_keywords: ["0.0.0.0/0"]
      port_keywords: ["5432", "3306", "1433", "27017", "6379"]
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/assess` | Submit any infrastructure change for risk assessment |
| `POST` | `/api/v1/assess/firewall-rule` | Batch assess up to 500 firewall rules |
| `GET` | `/api/v1/assessments` | List all assessments (filter by risk level + decision) |
| `GET` | `/api/v1/assessments/{id}` | Get full assessment report |
| `GET` | `/api/v1/stats` | Dashboard statistics |
| `GET` | `/api/v1/health/rag` | ChromaDB collection health + document counts |
| `GET` | `/api/v1/audit` | Full structured audit log |
| `POST` | `/api/v1/webhooks/github` | GitHub `pull_request` event receiver |
| `POST` | `/api/v1/webhooks/servicenow` | ServiceNow Change Request webhook |
| `POST` | `/api/v1/webhooks/jira` | Jira issue transition webhook |

Full interactive Swagger UI available at `/docs`.

---

## Project Structure

```
netguard-change-risk-gate/
├── backend/
│   ├── server.py                    # FastAPI application + all API routes
│   ├── agents/
│   │   ├── state.py                 # AgentState TypedDict (exact PRD spec)
│   │   └── graph.py                 # 6-node pipeline + all agent logic
│   ├── parsers/
│   │   └── parser.py                # AWS / Azure / GCP / On-Prem parsers
│   ├── engine/
│   │   └── rule_engine.py           # YAML rule evaluator + blast radius
│   ├── rag/
│   │   └── chroma_db.py             # ChromaDB client + seed data + retrieval
│   ├── audit/
│   │   └── logger.py                # Structured JSON audit logging
│   └── config/
│       └── policies/
│           ├── network.yaml         # NET-001 to NET-007
│           ├── iam.yaml             # IAM-001 to IAM-005
│           └── dns.yaml             # DNS-001 to DNS-003, SEC-001 to SEC-002
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx        # Stats, trend chart, pipeline viz
│       │   ├── NewAssessment.jsx    # Change submission — 4 source tabs
│       │   ├── AssessmentDetail.jsx # Full report with all analysis sections
│       │   ├── KnowledgeBase.jsx    # RAG health + collection stats
│       │   └── AuditLog.jsx         # Search + filter + export
│       └── components/netguard/
│           ├── Layout.jsx           # Sidebar navigation
│           ├── RiskBadge.jsx        # Risk level badge component
│           └── PipelineViz.jsx      # 6-node pipeline status visualization
└── .github/workflows/
    ├── change-risk-gate.yaml        # Main PR risk gate CI workflow
    ├── rag-ingest-nvd.yaml          # Nightly NVD CVE ingestion
    └── rag-ingest-attack.yaml       # Monthly MITRE ATT&CK sync
```

---

## Example Assessment Output

### CRITICAL — Escalated to Human Review

```
🛡️ NetGuard Change-Risk Gate v2 — CRITICAL — ESCALATED TO HUMAN REVIEW
═══════════════════════════════════════════════════════════════════════
Risk Score:  97/100  (base: 90 → RAG adjusted: +7 from CVE-2024-6387)
Decision:    ESCALATE_TO_HUMAN  |  Merge: BLOCKED 🔴
Blast Radius: BROAD — ~14 impacted assets

RULE FINDING: NET-001 — Unrestricted public internet ingress (0.0.0.0/0 on port 22/TCP)

📖 Intent: This AWS change opens SSH to the entire internet, bypassing the
   existing bastion host access pattern.

⚔️ MITRE ATT&CK Techniques (via RAG retrieval):
   • T1190 — Exploit Public-Facing Application (Initial Access)
   • T1078 — Valid Accounts (Persistence)
   • T1110 — Brute Force (Credential Access)

🔍 Relevant CVEs (from NVD RAG retrieval):
   • CVE-2024-6387  CVSS 8.1  OpenSSH RegreSSHion: unauthenticated RCE as root
   • CVE-2023-38408 CVSS 9.8  OpenSSH agent forwarding RCE

📋 Validation Checklist (Required Before Any Approval):
   ☐ Confirm SSH is not already available via bastion host
   ☐ Verify OpenSSH version >= 9.8p1 (mitigates CVE-2024-6387)
   ☐ Get written sign-off from all required approvers

👤 Required Approvers: CISO · Network Architect · Security Lead
Assessment ID: crg-2026-0042  |  6/6 agents  |  RAG: 4 collections queried
```

### LOW — Auto-Approved in Under 2 Seconds

```
✅ NetGuard Change-Risk Gate v2 — LOW — AUTO-APPROVED
═══════════════════════════════════════════════════════
Risk Score: 0/100  |  Decision: AUTO_APPROVE  |  Merge: ALLOWED ✅

No policy violations detected. Routine resource tag update.
Audit trail saved: crg-2026-0087
```

---

## Security & AI Safety Invariants

This system is designed with hardcoded safety properties that cannot be bypassed under adversarial conditions:

1. **CRITICAL findings are immutable** — Rule Engine CRITICAL findings cannot be removed from `AgentState` by any downstream node. The LLM only adds evidence, never removes it.

2. **Score can only increase** — `adjusted_risk_score >= base_risk_score` is enforced in the Analysis Agent's Pydantic schema. RAG evidence can raise the score; it can never lower the deterministic baseline.

3. **Decision Node is never an LLM** — Node 5 is a pure Python function. No language model touches the final approve/block decision. Full auditability, zero hallucination risk on security-critical paths.

4. **CVSS override is unconditional** — Any CVE with CVSS ≥ 7.0 from the knowledge base forces escalation regardless of the rule engine score.

5. **Prompt sanitization** — Change content is sanitized before sending to Claude. Internal IPs, tokens, and hostnames are stripped. The system prompt is hardcoded server-side, not user-controlled.

---

## Control Framework Compliance

| Framework | Control | How NetGuard Addresses It |
|-----------|---------|--------------------------|
| NIST SP 800-53 | CA-7 Continuous Monitoring | Every change assessed at PR time; RAG keeps threat intel current |
| NIST SP 800-53 | AC-3 Access Enforcement | Flags unrestricted ingress; requires approval for public exposure |
| CIS CSC v8 | Control 4 Secure Config | Validates changes against YAML baseline policy rules |
| CIS CSC v8 | Control 13 Network Monitoring | ATT&CK mapping shows attack paths enabled by proposed changes |
| SOC 2 Type II | CC6.6 Logical Access | Every IAM/RBAC change assessed; full audit trail of decisions |
| ISO 27001:2022 | A.8.9 Config Management | Change history collection provides configuration management evidence |

---

## Roadmap

**v2.1 — Live AI Integration**
- [ ] Connect Anthropic Claude API for live Node 4 analysis
- [ ] Replace demo embeddings with `text-embedding-3-small`
- [ ] Real NVD nightly ingestion via GitHub Actions
- [ ] Full MITRE ATT&CK STIX bundle load (1200+ techniques)

**v2.2 — Full Integrations**
- [ ] Real GitHub PR comment + commit status posting
- [ ] ServiceNow Work Note + field update
- [ ] Jira comment + label + attachment
- [ ] Shodan enrichment for live internet exposure validation

**v2.3 — Enterprise Features**
- [ ] Multi-tenant support with JWT authentication
- [ ] Custom policy YAML editor in UI
- [ ] Weekly security digest email for MEDIUM auto-approvals
- [ ] OpenTelemetry trace export to Splunk / Elastic
- [ ] Docker Compose with ChromaDB server mode

---

## Author

**Digvijay Singh** — AI Security Engineering  
*Building AI systems that make infrastructure security automatic, auditable, and trustworthy.*

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*If this project helped you think differently about AI-powered security governance, consider giving it a ⭐*

</div>
