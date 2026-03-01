# NetGuard Change-Risk Gate v2 -- PRD

## Problem Statement
Build a complete full-stack AI security governance platform based on the NetGuard CRG PRD v2.0 document by Digvijay Singh (2026). Platform combines deterministic infrastructure change parsing with LangGraph-orchestrated multi-agent AI for automated risk assessment of infrastructure changes.

## Architecture

### Backend (FastAPI + Python 3.11)
```
/app/backend/
├── server.py              # Main FastAPI app -- all API routes
├── agents/
│   ├── state.py           # AgentState TypedDict (includes normalized_changes field)
│   └── graph.py           # 6-node pipeline using parse_to_ir + IR-based rule engine
├── parsers/
│   ├── ir.py              # NormalizedChange IR dataclass + PortRange + helpers
│   └── parser.py          # 7 vendor parsers: AWS, Azure, GCP, Cisco IOS, PaloAlto, FortiGate, K8s
├── engine/
│   └── rule_engine.py     # 22+ IR-based rules + cross-resource correlation + remediation templates
├── rag/
│   └── chroma_db.py       # ChromaDB + seed data + retrieval (4 collections)
├── audit/
│   └── logger.py          # Structured audit logging
└── config/policies/       # Legacy v1 YAML rules (unused, kept for reference)
```

### Frontend (React 19 + TailwindCSS)
```
/app/frontend/src/
├── pages/
│   ├── Dashboard.jsx       # Stats, trend chart, pipeline viz, recent assessments
│   ├── NewAssessment.jsx   # 6 source tabs with multi-vendor sample diffs
│   ├── AssessmentDetail.jsx # Expandable FindingCard with code snippets + remediation
│   ├── KnowledgeBase.jsx   # RAG health + ChromaDB collection stats
│   └── AuditLog.jsx        # Searchable/filterable assessment history
└── components/netguard/
    ├── Layout.jsx           # Sidebar nav
    ├── RiskBadge.jsx        # Risk level badge (LOW/MEDIUM/HIGH/CRITICAL)
    └── PipelineViz.jsx      # 6-node pipeline status visualization
```

## Tech Stack
- **Backend**: FastAPI, Motor (async MongoDB), ChromaDB 1.5, PyYAML
- **Frontend**: React 19, Recharts, lucide-react, TailwindCSS, shadcn/ui
- **Database**: MongoDB (assessments collection)
- **Vector DB**: ChromaDB (4 collections: cve_knowledge, attack_techniques, policy_controls, change_history)
- **Design**: Dark HUD theme (#09090b), JetBrains Mono for data

## Core Features Implemented

### v2 Intermediate Representation (IR) Pipeline
- **NormalizedChange dataclass**: Vendor-neutral representation with change_type, resource_type, vendor, direction, source/dest CIDRs, ports, protocol, action, IAM fields, line numbers, code snippets
- **PortRange class**: Handles port ranges, named ports, wildcard ports with comparison methods
- **Helper functions**: normalize_cidr, wildcard_to_cidr, resolve_named_port

### v2 Multi-Vendor Parsers (7 platforms)
1. **AWSParser**: Terraform HCL + CloudFormation. Security groups, IAM policies, NAT gateways, routes, DNS, CloudTrail. Variable resolution.
2. **AzureParser**: azurerm Terraform + NSG rules. Role assignments, DNS, NAT/routes.
3. **GCPParser**: google_compute Terraform. Firewall rules, IAM bindings, DNS.
4. **CiscoIOSParser**: Named/numbered ACLs, interface bindings, ACE parsing with wildcard mask conversion.
5. **PaloAltoParser**: PAN-OS XML entries, zone-based direction detection, service-to-port mapping.
6. **FortiGateParser**: FortiOS policy blocks, VIP definitions, SSL-VPN settings.
7. **KubernetesParser**: NetworkPolicy, ClusterRole, ClusterRoleBinding, Workload (Pod/Deployment) with hostNetwork and privileged container detection.

### v2 Rule Engine (22+ rules)
- **Network rules**: NET-001 (SSH/RDP from internet), NET-002 (all ports), NET-003 (unrestricted egress), NET-004 (NAT gateway), NET-005 (route table), NET-006 (SG modification), NET-007 (VPN/tunnel), NET-008 (mgmt ports), NET-009 (database ports)
- **IAM rules**: IAM-001 (wildcard action), IAM-002 (admin role), IAM-003 (new binding), IAM-005 (wildcard resource)
- **DNS/SEC rules**: DNS-001 (DNS modification), SEC-002 (logging disabled)
- **PAN-OS rules**: PAN-001 (any source to trusted zone), PAN-002 (application=any)
- **FortiGate rules**: NET-FG-001 (VIP port forwarding)
- **Kubernetes rules**: K8S-001 (allow-all ingress), K8S-002 (RBAC wildcard), K8S-003 (privileged container), K8S-004 (hostNetwork)
- **Cross-resource**: CORR-001 (exposed database), CORR-002 (IAM wildcard + network exposure)
- **Compensating controls**: WAF (-10), Deny NACL (-8), MFA (-5), Security exception (-5)
- **Remediation templates**: Auto-generated fix code for all major rule IDs

### Agent Pipeline (6 nodes)
1. **Node 1 -- Ingestion**: Stack detection (8 vendors) + parse_to_ir → (List[NormalizedChange], legacy_dict)
2. **Node 2 -- Rule Engine**: IR-based evaluation (22+ rules) + blast radius
3. **Node 3 -- RAG Retrieval**: ChromaDB semantic search across 4 collections
4. **Node 4 -- Analysis**: [PLACEHOLDER] Realistic mock based on findings (Claude 3.5 Sonnet in production)
5. **Node 5 -- Decision**: Pure Python deterministic logic -- safety invariants enforced
6. **Node 6 -- Output**: [PLACEHOLDER] GitHub PR comment / ServiceNow / Jira targets

### Decision Logic
| Score | Level | Decision |
|-------|-------|----------|
| 0-39 | LOW | AUTO_APPROVE |
| 40-69 | MEDIUM | AUTO_APPROVE + FLAG |
| 70-89 | HIGH | ESCALATE |
| 90-100 | CRITICAL | ESCALATE + LOCK |

### Safety Invariants
- CRITICAL rule findings cannot be overridden by LLM output
- CVSS >= 7.0 CVE match forces escalation
- ATT&CK Initial Access / Execution tactic forces escalation
- Decision node is pure Python (not LLM)

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/assess | Core assessment endpoint |
| POST | /api/v1/assess/firewall-rule | Batch firewall rules [PLACEHOLDER] |
| POST | /api/v1/webhooks/github | GitHub PR webhook [PLACEHOLDER] |
| POST | /api/v1/webhooks/servicenow | ServiceNow webhook [PLACEHOLDER] |
| POST | /api/v1/webhooks/jira | Jira webhook [PLACEHOLDER] |
| GET | /api/v1/assessments | List all assessments |
| GET | /api/v1/assessments/{id} | Get single assessment |
| GET | /api/v1/stats | Dashboard statistics |
| GET | /api/v1/health/rag | ChromaDB collection health |
| GET | /api/v1/audit | Audit log |
| POST | /api/v1/knowledge-base/seed | Seed ChromaDB |

## What's PLACEHOLDER (not connected)
- Claude 3.5 Sonnet analysis calls (returns realistic mock based on rule findings)
- NVD live API ingestion (uses seeded sample CVEs)
- MITRE ATT&CK live sync (uses seeded sample techniques)
- GitHub PR comment posting
- ServiceNow Work Note posting
- Jira comment/label posting

## Implementation Dates
- 2026-03-01: Full MVP + v2 architecture overhaul (IR pipeline, multi-vendor parsers, enhanced rule engine, frontend v2 features)

## Prioritized Backlog

### P0 (Critical for production)
- Connect real Anthropic API (Claude 3.5 Sonnet) for Node 4 Analysis
- Upgrade ChromaDB embeddings from SimpleEmbeddingFunction to semantic model (OpenAI text-embedding-3-large or local BAAI/bge-m3)
- Ingest CISA KEV (Known Exploited Vulnerabilities) list into RAG
- Add few-shot examples to Analysis Agent prompt

### P1 (High value)
- NVD nightly ingestion script
- MITRE ATT&CK STIX bundle full ingestion
- Real GitHub PR comment posting (GitHub API)
- Real ServiceNow Work Note posting
- Streaming assessment progress (SSE)
- LangGraph library integration (replace custom orchestrator)

### P2 (Nice to have)
- User authentication
- LLM confidence scoring
- Multi-tenant support
- Custom policy YAML editor in UI
- Weekly digest email for MEDIUM approvals
- OpenTelemetry tracing integration
- Docker Compose with ChromaDB server mode

## Environment Variables
```
MONGO_URL=mongodb://localhost:27017
DB_NAME=test_database
CORS_ORIGINS=*
```
