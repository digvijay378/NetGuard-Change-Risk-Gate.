# NetGuard Change-Risk Gate v2 — PRD

## Problem Statement
Build a complete full-stack AI security governance platform based on the NetGuard CRG PRD v2.0 document by Digvijay Singh (2026). Platform combines deterministic infrastructure change parsing with LangGraph-orchestrated multi-agent AI for automated risk assessment of infrastructure changes.

## Architecture

### Backend (FastAPI + Python 3.11)
```
/app/backend/
├── server.py              # Main FastAPI app — all API routes
├── agents/
│   ├── state.py           # AgentState TypedDict (exact PRD spec)
│   └── graph.py           # 6-node pipeline orchestration
├── parsers/
│   └── parser.py          # AWS/Azure/GCP/on-prem stack parsers
├── engine/
│   └── rule_engine.py     # YAML rule evaluation + blast radius
├── rag/
│   └── chroma_db.py       # ChromaDB + seed data + retrieval
├── audit/
│   └── logger.py          # Structured audit logging
└── config/policies/
    ├── network.yaml        # NET-001..007 rules
    ├── iam.yaml            # IAM-001..005 rules
    └── dns.yaml            # DNS-001..003, SEC-001..002 rules
```

### Frontend (React 19 + TailwindCSS)
```
/app/frontend/src/
├── pages/
│   ├── Dashboard.jsx       # Stats, trend chart, pipeline viz, recent assessments
│   ├── NewAssessment.jsx   # Change submission (4 source tabs)
│   ├── AssessmentDetail.jsx # Full report (risk gauge, ATT&CK, CVE, checklist)
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
- **Design**: Dark HUD theme (#09090b), JetBrains Mono for data, Sentinel Interface

## Core Features Implemented

### Agent Pipeline (6 nodes)
1. **Node 1 — Ingestion**: Stack detection (AWS/Azure/GCP/on-prem) + change parsing
2. **Node 2 — Rule Engine**: YAML-driven rule evaluation (17 rules across 3 policy files)
3. **Node 3 — RAG Retrieval**: ChromaDB semantic search across 4 collections
4. **Node 4 — Analysis**: [PLACEHOLDER] Realistic mock based on findings (Claude 3.5 Sonnet in production)
5. **Node 5 — Decision**: Pure Python deterministic logic (NOT LLM) — safety invariants enforced
6. **Node 6 — Output**: [PLACEHOLDER] GitHub PR comment / ServiceNow / Jira targets

### Decision Logic
| Score | Level | Decision |
|-------|-------|----------|
| 0–39 | LOW | AUTO_APPROVE |
| 40–69 | MEDIUM | AUTO_APPROVE + FLAG |
| 70–89 | HIGH | ESCALATE |
| 90–100 | CRITICAL | ESCALATE + LOCK |

### Safety Invariants
- CRITICAL rule findings cannot be overridden by LLM output
- CVSS >= 7.0 CVE match forces escalation
- ATT&CK Initial Access / Execution tactic forces escalation
- Decision node is pure Python (not LLM)

### RAG Knowledge Base
- **cve_knowledge**: 15 sample CVEs seeded (NVD format)
- **attack_techniques**: 15 MITRE ATT&CK techniques seeded (STIX 2.1 format)
- **policy_controls**: 10 CIS/NIST controls seeded
- **change_history**: Real-time populated as assessments complete
- **Embedding**: SimpleEmbeddingFunction (256-dim, no model download required)

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
- 2026-03-01: Full MVP implementation (all 6 nodes, RAG pipeline, 4 pages, YAML rules)

## Prioritized Backlog

### P0 (Critical for production)
- Connect real Anthropic API (Claude 3.5 Sonnet) for Node 4 Analysis
- Connect OpenAI embeddings for ChromaDB (replace SimpleEmbeddingFunction)
- Implement real NVD nightly ingestion GitHub Action
- Implement real MITRE ATT&CK monthly sync

### P1 (High value)
- Real GitHub PR comment posting (GitHub API)
- Real ServiceNow Work Note posting
- Real Jira comment/label posting
- LangGraph library integration (replace custom orchestrator)
- Streaming assessment progress (SSE)

### P2 (Nice to have)
- User authentication
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
