<div align="center">

# NetGuard Change-Risk Gate v2

### AI-Powered Infrastructure Change Security Governance Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](https://reactjs.org)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-1.5-orange?style=flat-square)](https://trychroma.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-Architecture-purple?style=flat-square)](https://langchain-ai.github.io/langgraph/)
[![Claude](https://img.shields.io/badge/Claude-3.5%20Sonnet-CC785C?style=flat-square&logo=anthropic)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Stop dangerous infrastructure changes before they merge.**

NetGuard intercepts Terraform, firewall ACLs, Kubernetes manifests, and IAM policies across **7 vendor platforms** — normalizes them into a vendor-neutral Intermediate Representation — runs them through a 6-node AI agent pipeline — and either auto-approves or blocks with a full investigation report including CVE lookups, MITRE ATT&CK mapping, remediation code, and a human-readable validation checklist.

[Architecture](#architecture) · [Vendor Support](#vendor-neutral-intermediate-representation) · [Pipeline](#the-6-node-agent-pipeline) · [Quick Start](#quick-start) · [API Reference](#api-reference)

---

</div>

## Table of Contents

- [The Problem It Solves](#the-problem-it-solves)
- [What Makes This Architecture Stand Out](#what-makes-this-architecture-stand-out)
- [Architecture](#architecture)
- [Vendor-Neutral Intermediate Representation](#vendor-neutral-intermediate-representation)
- [The 7-Vendor Parser Engine](#the-7-vendor-parser-engine)
- [The 6-Node Agent Pipeline](#the-6-node-agent-pipeline)
- [IR-Based Rule Engine (22+ Rules)](#ir-based-rule-engine-22-rules)
- [RAG Pipeline & Knowledge Base](#rag-pipeline--knowledge-base)
- [Semi-Autonomous Decision Engine](#semi-autonomous-decision-engine)
- [Auto-Generated Remediation](#auto-generated-remediation)
- [Frontend — Security Operations Dashboard](#frontend--security-operations-dashboard)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Example Assessment Output](#example-assessment-output)
- [Security & AI Safety Invariants](#security--ai-safety-invariants)
- [Control Framework Compliance](#control-framework-compliance)
- [Roadmap](#roadmap)

---

## The Problem It Solves

In any engineering organization, developers push hundreds of infrastructure changes weekly — Terraform files, firewall rules, IAM policies, Kubernetes manifests, Cisco ACLs, PAN-OS XML configs. A single misconfiguration can expose your entire production fleet within minutes of merge:

```hcl
# AWS Terraform — opens SSH to the entire internet
resource "aws_security_group_rule" "allow_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]   # Direct path to CVE-2024-6387 (CVSS 8.1)
}
```

```
! Cisco IOS — permits all traffic from any source
ip access-list extended OUTSIDE-IN
  permit tcp any any eq 22
  permit tcp any any eq 3389
interface GigabitEthernet0/0
  ip access-group OUTSIDE-IN in
```

```yaml
# Kubernetes — allows ingress from the entire internet to all pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
spec:
  podSelector: {}
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
```

**NetGuard intercepts all of these before they can merge.** Regardless of the vendor or format, every change is normalized into the same IR, evaluated against the same rule engine, enriched with the same threat intelligence, and gated by the same deterministic decision logic.

---

## What Makes This Architecture Stand Out

| Signal | What It Demonstrates |
|--------|----------------------|
| **Vendor-Neutral IR** | All 7 vendor formats normalized to a single `NormalizedChange` dataclass — rules written once, work everywhere |
| **LangGraph-style multi-agent graph** | Stateful agentic AI with conditional routing — not just prompt chaining |
| **22+ IR-based rules with auto-remediation** | Each finding includes the exact line number, affected code snippet, and suggested fix code |
| **Cross-resource correlation** | Detects compound risks like "IAM wildcard + network exposure in the same PR" |
| **Compensating control detection** | Automatically reduces score when WAF, NACL deny rules, or MFA enforcement are present |
| **RAG pipeline with ChromaDB** | Production vector store with CVE, ATT&CK, and compliance threat intelligence |
| **Semi-autonomous decision logic** | AI safety: the system knows when to act vs. when to ask a human |
| **7-vendor parser coverage** | AWS, Azure, GCP, Cisco IOS/NX-OS, Palo Alto PAN-OS, Fortinet FortiGate, Kubernetes |

---

## Architecture

```
                          NETGUARD v2 — SYSTEM ARCHITECTURE

  INGESTION CHANNELS              VENDOR-NEUTRAL IR              6-NODE AGENT PIPELINE
  ==================              ==================             =====================

  GitHub PR Webhook  ---+
  Firewall Rule API  ---+---> [ Stack Detection ] ---> [ Multi-Vendor Parser ]
  ServiceNow Webhook ---+         (8 vendors)              |
  Jira Webhook       ---+                                  |
                                                           v
                                              +--  NormalizedChange IR  --+
                                              |   change_type: ADD        |
                                              |   resource_type: fw_rule  |
                                              |   vendor: aws             |
                                              |   direction: INGRESS      |
                                              |   source_cidrs: [0.0.0.0] |
                                              |   ports: [22]             |
                                              |   action: ALLOW           |
                                              |   line_start: 14          |
                                              |   raw_snippet: "..."      |
                                              +---------------------------+
                                                           |
               +-------------------------------------------+
               |
               v
  [1] Ingestion --> [2] Rule Engine (22+ rules)
                         |
                         | findings + base_score
                         v
                    [3] RAG Retrieval
                         |  ChromaDB: CVEs, ATT&CK, Controls, History
                         v
                    [4] Analysis Agent (Claude 3.5 Sonnet)
                         |  threat narrative + adjusted score
                         v
                    [5] Decision Agent (Pure Python - NOT LLM)
                         |
                    +----+----+
                    |         |
               score < 70  score >= 70
                    |         |
              AUTO_APPROVE  ESCALATE_TO_HUMAN
                    |         |
               [6] Output  [6] Output
               Allow merge  Block merge
               Audit log    Notify CISO + full report
```

### Four AI Layers

| # | Layer | Technology | Role |
|---|-------|------------|------|
| 1 | **Agent Orchestration** | LangGraph-style StateGraph | Stateful graph routing through 6 specialized nodes |
| 2 | **RAG Knowledge Pipeline** | ChromaDB + Semantic Retrieval | Searches 4 vector collections before reasoning |
| 3 | **LLM Reasoning** | Claude 3.5 Sonnet (Anthropic) | Synthesizes findings into threat narrative with structured output |
| 4 | **Autonomy Engine** | Deterministic Python + AgentState | Pure logic — auto-approve LOW/MEDIUM, escalate HIGH/CRITICAL |

---

## Vendor-Neutral Intermediate Representation

The core innovation of v2: every parser — regardless of vendor syntax — outputs the same `NormalizedChange` dataclass. The rule engine, RAG query builder, and LLM prompts all operate against this IR. **Rules are written once, they work for all 7 vendors.**

```python
@dataclass
class NormalizedChange:
    change_type: str       # ADD | REMOVE | MODIFY
    resource_type: str     # firewall_rule | iam_policy | dns_record | k8s_network_policy | ...
    resource_name: str     # "aws_security_group.web_tier" | "panos:allow-all" | "k8s_netpol:allow-all"
    vendor: str            # aws | azure | gcp | cisco_ios | paloalto | fortigate | kubernetes

    # Network fields
    direction: str         # INGRESS | EGRESS | BOTH | LATERAL | UNKNOWN
    source_cidrs: List[str]
    dest_cidrs: List[str]
    ports: List[PortRange]
    protocol: str          # TCP | UDP | ICMP | ANY
    action: str            # ALLOW | DENY

    # IAM / RBAC fields
    iam_actions: List[str]
    iam_resources: List[str]

    # Evidence fields (for pinpointed findings)
    raw_snippet: str       # Affected code
    line_start: int        # Exact line number in the diff
    line_end: int

    # Computed methods
    def is_internet_exposed(self) -> bool: ...
    def has_wildcard_iam(self) -> bool: ...
    def exposes_port(self, *ports) -> bool: ...
```

### PortRange

```python
@dataclass
class PortRange:
    start: int    # -1 = all ports
    end: int

    @classmethod
    def any(cls) -> "PortRange": ...       # All ports
    @classmethod
    def from_string(cls, s: str): ...      # "22", "80-443", "any", "ssh"
    def contains_port(self, port: int): ...
    def is_any(self) -> bool: ...
```

The IR includes 75+ named port mappings (`ssh=22`, `rdp=3389`, `mysql=3306`, `kubernetes-api=6443`, etc.), Cisco wildcard mask-to-CIDR conversion, and internet CIDR normalization (`0.0.0.0/0`, `::/0`, `*`, `any`, `internet`, `all` -> `0.0.0.0/0`).

---

## The 7-Vendor Parser Engine

Each parser produces `List[NormalizedChange]`. The rule engine never sees raw text.

| # | Vendor | Format | What Gets Parsed |
|---|--------|--------|-----------------|
| 1 | **AWS** | Terraform HCL, CloudFormation JSON | Security groups, IAM policies, IAM attachments, NAT gateways, routes, DNS zones, CloudTrail logging. **Variable resolution** for `var.x` and `local.x`. |
| 2 | **Azure** | azurerm Terraform, NSG inline rules | NSG security rules, role assignments (Owner/Contributor detection), DNS zones, NAT/routes. Azure source address normalization (`Internet` -> `0.0.0.0/0`). |
| 3 | **GCP** | google_compute Terraform | Compute firewalls, IAM bindings/members, DNS managed zones. Source range extraction from allow/deny blocks. |
| 4 | **Cisco IOS/NX-OS** | Named & numbered ACLs, interface bindings | Full ACL parsing with `permit`/`deny` ACE extraction, `host` keyword handling, **wildcard mask to CIDR** conversion, **interface-to-ACL binding** tracking for direction inference. |
| 5 | **Palo Alto PAN-OS** | XML security rules, Panorama exports | XML entry parsing with **zone-based direction detection** (untrust/trust zones), service-to-port mapping (`service-ssh=22`, etc.), App-ID inspection detection. Regex fallback for malformed XML. |
| 6 | **Fortinet FortiGate** | FortiOS config blocks | Policy blocks with `edit N`/`set` parsing, **VIP port forwarding detection**, SSL-VPN settings changes, WAN interface identification. FortiGate address normalization (`all`->`0.0.0.0/0`). |
| 7 | **Kubernetes** | YAML manifests | NetworkPolicy with ipBlock CIDR and podSelector analysis, ClusterRole wildcard verb/resource detection, ClusterRoleBinding with dangerous subject detection (`system:unauthenticated`), **privileged container** and **hostNetwork** detection on Pods/Deployments/DaemonSets/StatefulSets. |

### Auto-Detection

Stack detection uses weighted pattern scoring across 50+ regex signatures. The highest-scoring vendor wins:

```python
# Example detection signatures (subset)
AWS:        aws_, AWSTemplateFormatVersion, arn:aws:, ec2, vpc, ami-, aws_security_group
Azure:      azurerm_, Microsoft., subscription_id, bicep, arm_template
GCP:        google_compute, google_, gcp, gcloud, project_id, googleapis
Cisco:      ip access-list, access-list \d+, ip access-group, interface gigabit, nx-os
PAN-OS:     pan-os, panos, <entry name=, <security>, <rulebase>, <from><member>
FortiGate:  config firewall policy, config firewall vip, set srcaddr, set dstaddr
Kubernetes: kind: networkpolicy, kind: clusterrole, apiversion: networking, podselector
```

---

## The 6-Node Agent Pipeline

Every change flows through all 6 nodes sequentially, with each node reading from and writing to a shared `AgentState` TypedDict that persists all intermediate results:

### Node 1 — Ingestion Agent *(Deterministic, No LLM)*

Detects the infrastructure vendor using weighted regex scoring, then routes to the appropriate parser. The parser outputs `List[NormalizedChange]` IR objects + a legacy dict for blast radius calculation.

**Input:** Raw diff text + change source  
**Output:** `detected_stack`, `normalized_changes[]`, `parsed_change` (legacy dict)

### Node 2 — Rule Engine Agent *(Deterministic, No LLM)*

Evaluates 22+ pure-function rules against each `NormalizedChange` object. Score is **additive and capped at 100**. Includes cross-resource correlation and compensating control detection.

**Input:** `List[NormalizedChange]` from Node 1  
**Output:** `rule_findings[]` (with line numbers, code snippets, remediation), `base_risk_score`, `blast_radius`

### Node 3 — RAG Retrieval Agent *(Vector Search, No LLM)*

Builds a semantic query from rule findings + IR metadata, then searches all 4 ChromaDB collections.

**Input:** Findings + IR changes + detected stack  
**Output:** `cve_matches[]`, `attack_techniques[]`, `policy_controls[]`, `similar_incidents[]`

### Node 4 — Analysis Agent *(Claude 3.5 Sonnet — Structured Output)*

The only LLM node. Synthesizes all evidence into a threat narrative with score adjustment based on RAG matches.

**Input:** All findings + CVEs + ATT&CK techniques + policy controls  
**Output:** `adjusted_risk_score`, `threat_narrative`, `validation_checklist[]`, `intent_summary`

> **Safety Invariant:** `adjusted_score >= base_risk_score` — RAG can only raise risk, never lower the deterministic baseline.

### Node 5 — Decision Agent *(Pure Python — NEVER an LLM)*

Fully deterministic. Four hard override conditions bypass the score entirely:

```python
# Any of these forces ESCALATE_TO_HUMAN regardless of LLM output:
1. has_critical_rule_finding          # CRITICAL rule fired in Node 2
2. has_block_merge_finding            # Any rule marked block_merge: true
3. has_high_cvss AND score >= 40      # CVE with CVSS >= 7.0 from RAG
4. has_initial_access_technique       # MITRE ATT&CK Initial Access / Execution
```

### Node 6 — Output Agent *(Integration Adapters)*

Routes the result back to the originating system. Adds the assessment to the `change_history` RAG collection for future similarity matching.

---

## IR-Based Rule Engine (22+ Rules)

Every rule is a pure function: `NormalizedChange -> List[Finding]`. No regex on raw text. Fully deterministic, testable, vendor-agnostic.

### Network Rules

| Rule | Title | Severity | Score | Trigger |
|------|-------|----------|-------|---------|
| NET-001 | Unrestricted Internet Ingress (SSH/RDP) | CRITICAL | +40 | `is_internet_exposed() AND exposes_port(22, 3389)` |
| NET-002 | Unrestricted Internet Ingress (All Ports) | CRITICAL | +35 | `is_internet_exposed() AND any_port_is_wildcard()` |
| NET-003 | Unrestricted Egress Rule | MEDIUM | +20 | `direction=EGRESS AND dest=0.0.0.0/0 AND all_ports` |
| NET-004 | NAT Gateway Modification | HIGH | +25 | `resource_type=nat_gateway AND change_type=ADD/MODIFY` |
| NET-005 | Route Table Modification | MEDIUM | +15 | `resource_type=route AND change_type=ADD/MODIFY` |
| NET-006 | Firewall/SG Modification | MEDIUM | +10 | `resource_type=firewall_rule AND NOT internet_exposed` |
| NET-007 | VPN / Tunnel Config Change | HIGH | +25 | `resource_type=vpn_config OR "vpn" in resource_name` |
| NET-008 | Management Ports Exposed | HIGH | +30 | `is_internet_exposed() AND exposes_port(23, 161, 8080, 9200)` |
| NET-009 | Database Port Exposed | CRITICAL | +45 | `is_internet_exposed() AND exposes_port(3306, 5432, 27017, 6379)` |

### IAM Rules

| Rule | Title | Severity | Score | Trigger |
|------|-------|----------|-------|---------|
| IAM-001 | Wildcard IAM Action (Action=\*) | CRITICAL | +45 | `has_wildcard_iam() AND "*" in iam_actions` |
| IAM-002 | Admin/Owner Role Assignment | CRITICAL | +40 | `iam_actions contains Owner/Admin/cluster-admin` |
| IAM-003 | New Role Binding | HIGH | +25 | `resource_type=iam_binding AND change_type=ADD` |
| IAM-005 | Wildcard Resource | HIGH | +20 | `"*" in iam_resources AND NOT wildcard_action` |

### Platform-Specific Rules

| Rule | Title | Severity | Score | Vendor |
|------|-------|----------|-------|--------|
| PAN-001 | Any Source to Trusted Zone | HIGH | +35 | Palo Alto |
| PAN-002 | Application=Any (App-ID Disabled) | MEDIUM | +20 | Palo Alto |
| NET-FG-001 | VIP Port Forwarding from Internet | HIGH | +30 | FortiGate |
| K8S-001 | NetworkPolicy Allow-All Ingress | CRITICAL | +40 | Kubernetes |
| K8S-002 | RBAC Wildcard Permissions | CRITICAL | +45 | Kubernetes |
| K8S-003 | Privileged Container | CRITICAL | +40 | Kubernetes |
| K8S-004 | hostNetwork=true | HIGH | +30 | Kubernetes |

### Cross-Resource Correlation Rules

| Rule | Title | Severity | Score | Trigger |
|------|-------|----------|-------|---------|
| CORR-001 | Exposed Database Endpoint | CRITICAL | +55 | DB port exposed via firewall + publicly_accessible |
| CORR-002 | IAM Wildcard + Network Exposure | CRITICAL | +20 | Both wildcard IAM AND internet exposure in same PR |

### Compensating Controls (Score Reducers)

| Control | Reduction | Condition |
|---------|-----------|-----------|
| WAF Association | -10 | `aws_wafv2_web_acl_association` in diff |
| Deny NACL | -8 | `aws_network_acl_rule` with deny in diff |
| MFA Enforcement | -5 | `aws:MultiFactorAuthPresent` or `mfa_enabled` |
| Security Exception | -5 | `APPROVED-SEC-XXXX-N` pattern in diff |

> **Safety:** CRITICAL findings are never reduced below score 30 by compensating controls.

### DNS & Security Rules

| Rule | Title | Severity | Score |
|------|-------|----------|-------|
| DNS-001 | DNS Zone / Record Modification | HIGH | +30 |
| SEC-002 | Logging / Monitoring Disabled | HIGH | +30 |

---

## Auto-Generated Remediation

Every finding includes a `suggested_fix` field with production-ready remediation code:

```
FINDING: NET-001 — Unrestricted Internet Ingress (SSH/RDP)
RESOURCE: aws_security_group.web_tier (Line 14)

AFFECTED CODE:
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
  to_port     = 22

SUGGESTED REMEDIATION:
  # Option A — Restrict to VPN/bastion CIDR only:
  cidr_blocks = [var.vpn_cidr]   # e.g. 10.0.0.0/8

  # Option B — Use bastion security group reference (preferred):
  source_security_group_id = aws_security_group.bastion.id

  # Option C — Eliminate SSH entirely (recommended):
  # aws ssm start-session --target i-xxxxx
  # Remove ingress rule entirely and configure SSM Session Manager
```

Remediation templates exist for all major rules: NET-001 through NET-004, IAM-001, IAM-002, DNS-001, SEC-002, PAN-001, PAN-002, K8S-001, K8S-002, K8S-003, CORR-001.

---

## RAG Pipeline & Knowledge Base

The RAG pipeline grounds every assessment in **current, auditable threat intelligence** rather than relying on stale LLM training data.

### ChromaDB Collections

| Collection | Source | Documents | What Gets Retrieved |
|------------|--------|-----------|---------------------|
| `cve_knowledge` | NIST NVD | 15 high-impact CVEs (seed) | CVEs matching exposed ports, services, or resource types |
| `attack_techniques` | MITRE ATT&CK STIX 2.1 | 15 techniques (seed) | Techniques relevant to the finding type |
| `policy_controls` | CIS + NIST SP 800-53 | 10 controls (seed) | Control requirements and remediation guidance |
| `change_history` | Internal audit log | Real-time populated | Past assessments with matching patterns |

### Seed Data Highlights

**CVEs:** CVE-2024-6387 (OpenSSH RCE, CVSS 8.1), CVE-2024-3400 (PAN-OS RCE, CVSS 10.0), CVE-2023-27997 (FortiGate Heap Overflow, CVSS 9.8), CVE-2019-0708 (BlueKeep RDP, CVSS 9.8), CVE-2021-44228 (Log4Shell, CVSS 10.0), and 10 more.

**ATT&CK:** T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts), T1041 (Exfiltration Over C2), T1562.001 (Impair Defenses), T1068 (Privilege Escalation), and 10 more.

---

## Semi-Autonomous Decision Engine

```
+----------+------------+------------------+--------------------+
|  Score   |  Level     |  Decision        |  Human Review?     |
+----------+------------+------------------+--------------------+
|  0 - 39  |  LOW       |  AUTO_APPROVE    |  No                |
| 40 - 69  |  MEDIUM    |  AUTO_APPROVE    |  Weekly digest     |
| 70 - 89  |  HIGH      |  ESCALATE        |  Net Arch +        |
|          |            |                  |  Security Lead     |
| 90 - 100 |  CRITICAL  |  ESCALATE + LOCK |  CISO + Net Arch   |
|          |            |                  |  + Security Lead   |
+----------+------------+------------------+--------------------+
```

Every auto-approval is logged with `assessment_id`, full `agent_trace`, all RAG sources cited, and timestamp.

---

## Frontend — Security Operations Dashboard

Built with React 19 + TailwindCSS with a dark HUD theme optimized for security operations centers.

### Pages

| Page | Features |
|------|----------|
| **Dashboard** | Real-time stats, risk score trend chart, risk distribution pie chart, 6-node pipeline visualization, recent assessments table |
| **New Assessment** | 6 source tabs (GitHub PR, Firewall Rule, Network Device, Kubernetes, ServiceNow, Jira) with pre-loaded sample diffs for each vendor |
| **Assessment Detail** | Risk gauge, expandable finding cards with code snippets + remediation code, CVE table, ATT&CK mapping, policy controls, blast radius analysis, validation checklist |
| **Knowledge Base** | ChromaDB collection health monitor with document counts and status indicators |
| **Audit Log** | Searchable, filterable history of all assessments |

### Finding Cards (v2)

Each rule finding is displayed as an expandable card showing:
- **Header:** Rule ID, severity badge, title, score contribution, block indicator
- **Body:** Description, resource name with pin icon, line number, tags
- **Expanded:** Affected code snippet (red-highlighted) + suggested remediation code (green-highlighted)

---

## Tech Stack

**Backend**
```
FastAPI 0.110      — Async API server with auto OpenAPI docs
Python 3.11        — Fully type-annotated, Pydantic v2 throughout
Motor 3.3          — Async MongoDB driver
ChromaDB 1.5       — Local persistent vector database
PyYAML 6.0         — Policy rule file parsing
xml.etree          — PAN-OS XML config parsing
dataclasses        — NormalizedChange IR + PortRange
```

**Frontend**
```
React 19           — Modern component architecture
TailwindCSS 3.4    — Utility-first styling with dark HUD theme
Recharts 3.6       — Risk trend charts and distribution charts
lucide-react       — Icon library (Shield, Code, Wrench, MapPin, Router, Server)
JetBrains Mono     — Monospace font for all security data
shadcn/ui          — Base component library
```

**Infrastructure**
```
MongoDB            — Assessment storage + full audit log
ChromaDB           — Embedded persistent vector store
```

---

## Quick Start

### Prerequisites
- Python 3.11+, Node.js 18+, MongoDB

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/netguard-change-risk-gate.git
cd netguard-change-risk-gate

# Backend
cd backend
pip install -r requirements.txt
cp .env.example .env  # Configure MONGO_URL, DB_NAME

# Frontend
cd ../frontend
yarn install
```

### 2. Start Services

```bash
# Terminal 1 — Backend
cd backend && uvicorn server:app --host 0.0.0.0 --port 8001 --reload

# Terminal 2 — Frontend
cd frontend && yarn start
```

### 3. Run Your First Assessment

```bash
# AWS — SSH from internet (should return CRITICAL)
curl -X POST http://localhost:8001/api/v1/assess \
  -H "Content-Type: application/json" \
  -d '{
    "change_source": "github_pr",
    "raw_diff": "resource \"aws_security_group_rule\" \"allow_ssh\" {\n  type = \"ingress\"\n  from_port = 22\n  to_port = 22\n  protocol = \"tcp\"\n  cidr_blocks = [\"0.0.0.0/0\"]\n}",
    "change_metadata": { "author": "dev.engineer", "pr_number": 142 }
  }'

# Cisco IOS — ACL permitting SSH/RDP from any (should detect cisco_ios, CRITICAL)
curl -X POST http://localhost:8001/api/v1/assess \
  -H "Content-Type: application/json" \
  -d '{
    "change_source": "github_pr",
    "raw_diff": "ip access-list extended OUTSIDE-IN\n permit tcp any any eq 22\n permit tcp any any eq 3389\ninterface GigabitEthernet0/0\n ip access-group OUTSIDE-IN in"
  }'

# Kubernetes — NetworkPolicy allowing all ingress + RBAC wildcard
curl -X POST http://localhost:8001/api/v1/assess \
  -H "Content-Type: application/json" \
  -d '{
    "change_source": "github_pr",
    "raw_diff": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: allow-all\nspec:\n  podSelector: {}\n  ingress:\n  - from:\n    - ipBlock:\n        cidr: 0.0.0.0/0"
  }'
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/assess` | Core assessment — accepts any vendor format, auto-detects stack |
| `POST` | `/api/v1/assess/firewall-rule` | Batch assess up to 500 firewall rules |
| `GET` | `/api/v1/assessments` | List all assessments (filter by `risk_level`, `decision`) |
| `GET` | `/api/v1/assessments/{id}` | Full assessment report with all findings |
| `GET` | `/api/v1/stats` | Dashboard statistics (counts by risk level, source, recent list) |
| `GET` | `/api/v1/health/rag` | ChromaDB collection health + document counts |
| `GET` | `/api/v1/audit` | Structured audit log |
| `POST` | `/api/v1/webhooks/github` | GitHub `pull_request` event receiver |
| `POST` | `/api/v1/webhooks/servicenow` | ServiceNow Change Request webhook |
| `POST` | `/api/v1/webhooks/jira` | Jira issue transition webhook |
| `POST` | `/api/v1/knowledge-base/seed` | Seed ChromaDB with sample threat intelligence |

Interactive Swagger UI available at `/docs`.

---

## Project Structure

```
netguard-change-risk-gate/
├── backend/
│   ├── server.py                    # FastAPI application + all API routes
│   ├── agents/
│   │   ├── state.py                 # AgentState TypedDict (normalized_changes + all pipeline fields)
│   │   ├── graph.py                 # 6-node pipeline orchestrator using parse_to_ir
│   │   └── prompts.py               # LLM prompt templates
│   ├── parsers/
│   │   ├── ir.py                    # NormalizedChange IR + PortRange + helpers
│   │   └── parser.py                # 7 vendor parsers (AWS, Azure, GCP, Cisco, PAN-OS, FortiGate, K8s)
│   ├── engine/
│   │   └── rule_engine.py           # 22+ IR-based rules + correlation + compensating controls + remediation
│   ├── rag/
│   │   └── chroma_db.py             # ChromaDB client + seed data + retrieval + formatters
│   ├── audit/
│   │   └── logger.py                # Structured JSON audit logging
│   ├── config/policies/             # Legacy YAML rules (reference)
│   └── data/chroma/                 # ChromaDB persistent storage
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx        # Stats, charts, pipeline viz, recent assessments
│       │   ├── NewAssessment.jsx    # 6 source tabs with multi-vendor sample diffs
│       │   ├── AssessmentDetail.jsx # Expandable FindingCards with snippets + remediation
│       │   ├── KnowledgeBase.jsx    # RAG health monitor
│       │   └── AuditLog.jsx         # Search + filter assessment history
│       └── components/netguard/
│           ├── Layout.jsx           # Sidebar navigation
│           ├── RiskBadge.jsx        # Risk level badge (LOW/MEDIUM/HIGH/CRITICAL)
│           └── PipelineViz.jsx      # 6-node pipeline status visualization
└── README.md
```

---

## Example Assessment Output

### CRITICAL — Escalated to Human Review

```
NetGuard Change-Risk Gate v2 — CRITICAL — ESCALATED TO HUMAN REVIEW
========================================================================
Assessment:  crg-2026-3185
Stack:       AWS (auto-detected)
Risk Score:  50/100 (base: 40 + RAG adjustment: +10 from CVE-2019-0708)
Decision:    ESCALATE_TO_HUMAN | Merge: BLOCKED
Blast Radius: BROAD — ~8 impacted assets

FINDING: NET-001 — Unrestricted Internet Ingress (SSH/RDP)
  Severity:  CRITICAL | Score: +40 | Block: YES
  Resource:  aws_security_group_rule.allow_ssh (Line 1)
  Code:      cidr_blocks = ["0.0.0.0/0"]  from_port = 22
  Fix:       cidr_blocks = [var.vpn_cidr]  # Or use bastion SG reference

CVE Intelligence:
  CVE-2024-6387  CVSS 8.1   OpenSSH RegreSSHion RCE
  CVE-2023-38408 CVSS 9.8   OpenSSH Agent Forwarding RCE
  CVE-2019-0708  CVSS 9.8   BlueKeep RDP RCE

MITRE ATT&CK:
  T1190 — Exploit Public-Facing Application (Initial Access)
  T1110 — Brute Force (Credential Access)
  T1133 — External Remote Services (Initial Access)

Required Approvers: CISO, Network Architect, Security Lead
Pipeline: 6/6 nodes completed | RAG: 4 collections queried
```

### LOW — Auto-Approved

```
NetGuard v2 — LOW — AUTO-APPROVED
===================================
Risk Score: 0/100 | Decision: AUTO_APPROVE | Merge: ALLOWED
No policy violations detected. Routine configuration update.
```

---

## Security & AI Safety Invariants

1. **CRITICAL findings are immutable** — Rule Engine CRITICAL findings cannot be removed by any downstream node. The LLM only adds evidence, never removes it.

2. **Score can only increase** — `adjusted_risk_score >= base_risk_score` is enforced. RAG evidence raises the score; it never lowers the deterministic baseline.

3. **Decision Node is never an LLM** — Node 5 is a pure Python function. No language model touches the final approve/block decision. Full auditability, zero hallucination risk.

4. **CVSS override is unconditional** — Any CVE with CVSS >= 7.0 forces escalation regardless of rule engine score.

5. **Compensating controls have safety limits** — CRITICAL findings are never reduced below score 30, even with WAF + NACL + MFA all present.

---

## Control Framework Compliance

| Framework | Control | How NetGuard Addresses It |
|-----------|---------|--------------------------|
| NIST SP 800-53 | CA-7 Continuous Monitoring | Every change assessed at PR time; RAG keeps threat intel current |
| NIST SP 800-53 | AC-3 Access Enforcement | Flags unrestricted ingress; requires approval for public exposure |
| NIST SP 800-53 | SC-7 Boundary Protection | Multi-vendor firewall rule analysis across all 7 platforms |
| CIS CSC v8 | Control 4 Secure Config | Validates changes against 22+ deterministic policy rules |
| CIS CSC v8 | Control 13 Network Monitoring | ATT&CK mapping shows attack paths enabled by proposed changes |
| SOC 2 Type II | CC6.6 Logical Access | Every IAM/RBAC change assessed; full audit trail of decisions |
| ISO 27001:2022 | A.8.9 Config Management | Change history RAG provides configuration management evidence |

---

## Roadmap

**v2.1 — Live AI + Enhanced RAG**
- [ ] Connect Claude 3.5 Sonnet for live Node 4 analysis
- [ ] Upgrade embeddings from keyword-hash to semantic model
- [ ] CISA KEV (Known Exploited Vulnerabilities) list ingestion
- [ ] Few-shot examples in Analysis Agent prompt
- [ ] Real NVD nightly ingestion
- [ ] Full MITRE ATT&CK STIX bundle (1200+ techniques)

**v2.2 — Full Integrations**
- [ ] Real GitHub PR comment + commit status posting
- [ ] ServiceNow Work Note + field update
- [ ] Jira comment + label + attachment
- [ ] Streaming assessment progress via SSE

**v2.3 — Enterprise Features**
- [ ] Multi-tenant support with JWT authentication
- [ ] Custom policy YAML editor in UI
- [ ] LLM confidence scoring on analysis output
- [ ] Weekly security digest email for MEDIUM auto-approvals
- [ ] OpenTelemetry tracing integration
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

*If this project helped you think differently about AI-powered security governance, consider giving it a star.*

</div>
