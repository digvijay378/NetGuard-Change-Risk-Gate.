"""
NetGuard Change-Risk Gate v2 — FastAPI Backend
Full LangGraph-style multi-agent system with RAG pipeline and ChromaDB.
"""
import os
import uuid
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Any

from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("netguard")

# MongoDB
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="NetGuard Change-Risk Gate v2", version="2.0.0")
api_router = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Pydantic Models ──────────────────────────────────────────────────────────

class AssessmentRequest(BaseModel):
    change_source: str = "github_pr"   # github_pr | firewall_api | servicenow | jira
    raw_diff: str
    change_metadata: dict = {}


class FirewallRuleRequest(BaseModel):
    rules: List[dict]  # up to 500 rules
    metadata: dict = {}


class GitHubWebhookPayload(BaseModel):
    action: str = ""
    pull_request: dict = {}
    repository: dict = {}


class ServiceNowWebhook(BaseModel):
    sys_id: str = ""
    number: str = ""
    description: str = ""
    short_description: str = ""
    state: str = ""
    metadata: dict = {}


class JiraWebhook(BaseModel):
    issue_key: str = ""
    summary: str = ""
    description: str = ""
    status: str = ""
    metadata: dict = {}


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    assessment_id: str
    change_source: str
    detected_stack: str
    risk_level: str
    base_risk_score: int
    adjusted_risk_score: int
    final_decision: str
    block_merge: bool
    intent_summary: str
    threat_narrative: str
    score_adjustment_reason: str
    rule_findings: List[dict]
    blast_radius: Optional[dict]
    cve_matches: List[dict]
    attack_techniques: List[dict]
    policy_controls: List[dict]
    similar_incidents: List[dict]
    validation_checklist: List[str]
    required_approvers: List[str]
    agent_trace: List[dict]
    rag_sources: List[dict]
    llm_rag_enriched: bool
    change_metadata: dict
    output_targets: List[str]
    errors: List[str]
    created_at: str


def _serialize_assessment(state: dict, created_at: str) -> dict:
    """Convert AgentState to a serializable dict for MongoDB and API response."""
    return {
        "assessment_id": state.get("change_metadata", {}).get("assessment_id", "unknown"),
        "change_source": state.get("change_source", ""),
        "detected_stack": state.get("detected_stack", "unknown"),
        "risk_level": state.get("risk_level", "LOW"),
        "base_risk_score": state.get("base_risk_score", 0),
        "adjusted_risk_score": state.get("adjusted_risk_score", 0),
        "final_decision": state.get("final_decision", "AUTO_APPROVE"),
        "block_merge": state.get("block_merge", False),
        "intent_summary": state.get("intent_summary", ""),
        "threat_narrative": state.get("threat_narrative", ""),
        "score_adjustment_reason": state.get("score_adjustment_reason", ""),
        "rule_findings": state.get("rule_findings", []),
        "blast_radius": state.get("blast_radius"),
        "cve_matches": state.get("cve_matches", []),
        "attack_techniques": state.get("attack_techniques", []),
        "policy_controls": state.get("policy_controls", []),
        "similar_incidents": state.get("similar_incidents", []),
        "validation_checklist": state.get("validation_checklist", []),
        "required_approvers": state.get("required_approvers", []),
        "agent_trace": state.get("agent_trace", []),
        "rag_sources": state.get("rag_sources", []),
        "llm_rag_enriched": state.get("llm_rag_enriched", False),
        "change_metadata": state.get("change_metadata", {}),
        "output_targets": state.get("output_targets", []),
        "errors": state.get("errors", []),
        "created_at": created_at,
    }


# ─── Core Assessment Route ────────────────────────────────────────────────────

@api_router.post("/v1/assess", response_model=AssessmentResponse)
async def create_assessment(req: AssessmentRequest):
    """Submit any infrastructure change for AI risk assessment."""
    from agents.graph import run_agent_graph
    from audit.logger import log_assessment, log_error

    if not req.raw_diff.strip():
        raise HTTPException(status_code=400, detail="raw_diff cannot be empty")

    meta = {**req.change_metadata, "submitted_at": datetime.now(timezone.utc).isoformat()}
    state = run_agent_graph(req.change_source, req.raw_diff, meta)

    created_at = datetime.now(timezone.utc).isoformat()
    doc = _serialize_assessment(state, created_at)

    await db.assessments.insert_one({**doc, "_id": doc["assessment_id"]})

    assessment_id = doc["assessment_id"]
    log_assessment(assessment_id, doc["final_decision"], doc["risk_level"],
                   doc["adjusted_risk_score"], doc["change_source"], doc["block_merge"])

    return AssessmentResponse(**doc)


@api_router.post("/v1/assess/firewall-rule", response_model=List[AssessmentResponse])
async def assess_firewall_rules(req: FirewallRuleRequest):
    """
    PLACEHOLDER: Assess a batch of firewall rules (up to 500).
    In production: parses JSON/CSV firewall rule format.
    """
    from agents.graph import run_agent_graph

    results = []
    for rule in req.rules[:10]:  # Limit to 10 for demo
        diff = _firewall_rule_to_diff(rule)
        meta = {**req.metadata, "rule_id": rule.get("id", str(uuid.uuid4())[:8])}
        state = run_agent_graph("firewall_api", diff, meta)
        created_at = datetime.now(timezone.utc).isoformat()
        doc = _serialize_assessment(state, created_at)
        await db.assessments.insert_one({**doc, "_id": doc["assessment_id"]})
        results.append(AssessmentResponse(**doc))
    return results


@api_router.post("/v1/webhooks/github")
async def github_webhook(payload: GitHubWebhookPayload):
    """
    PLACEHOLDER: Receives GitHub PR webhook.
    In production: extracts git diff and triggers assessment.
    """
    return {
        "status": "placeholder",
        "message": "GitHub webhook received. In production, this triggers a risk assessment on the PR diff.",
        "pr_number": payload.pull_request.get("number"),
        "action": payload.action,
    }


@api_router.post("/v1/webhooks/servicenow")
async def servicenow_webhook(payload: ServiceNowWebhook):
    """
    PLACEHOLDER: Receives ServiceNow Change Request webhook.
    In production: parses description, runs assessment, posts Work Note.
    """
    from agents.graph import run_agent_graph
    if not payload.description:
        return {"status": "placeholder", "message": "ServiceNow webhook received (no description to assess)"}

    meta = {"ticket_id": payload.number, "source_system": "servicenow", "sys_id": payload.sys_id}
    state = run_agent_graph("servicenow", payload.description, meta)
    created_at = datetime.now(timezone.utc).isoformat()
    doc = _serialize_assessment(state, created_at)
    await db.assessments.insert_one({**doc, "_id": doc["assessment_id"]})
    return {"status": "assessed", "assessment_id": doc["assessment_id"],
            "risk_level": doc["risk_level"], "decision": doc["final_decision"],
            "placeholder_note": "In production, this Work Note would be posted back to ServiceNow ticket"}


@api_router.post("/v1/webhooks/jira")
async def jira_webhook(payload: JiraWebhook):
    """
    PLACEHOLDER: Receives Jira issue transition webhook.
    In production: downloads attachments, assesses, posts comment.
    """
    from agents.graph import run_agent_graph
    if not payload.description:
        return {"status": "placeholder", "message": "Jira webhook received (no description to assess)"}

    meta = {"issue_key": payload.issue_key, "source_system": "jira"}
    state = run_agent_graph("jira", payload.description, meta)
    created_at = datetime.now(timezone.utc).isoformat()
    doc = _serialize_assessment(state, created_at)
    await db.assessments.insert_one({**doc, "_id": doc["assessment_id"]})
    return {"status": "assessed", "assessment_id": doc["assessment_id"],
            "risk_level": doc["risk_level"], "decision": doc["final_decision"],
            "placeholder_note": "In production, markdown comment with ATT&CK mapping would be posted to Jira"}


# ─── Assessment Read Routes ───────────────────────────────────────────────────

@api_router.get("/v1/assessments", response_model=List[AssessmentResponse])
async def list_assessments(limit: int = 50, risk_level: Optional[str] = None,
                            decision: Optional[str] = None):
    """List all assessments with optional filtering."""
    query: dict[str, Any] = {}
    if risk_level:
        query["risk_level"] = risk_level.upper()
    if decision:
        query["final_decision"] = decision.upper()
    cursor = db.assessments.find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(limit)
    return [AssessmentResponse(**d) for d in docs]


@api_router.get("/v1/assessments/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(assessment_id: str):
    doc = await db.assessments.find_one({"assessment_id": assessment_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return AssessmentResponse(**doc)


@api_router.get("/v1/stats")
async def get_stats():
    """Dashboard statistics."""
    total = await db.assessments.count_documents({})
    auto_approved = await db.assessments.count_documents({"final_decision": "AUTO_APPROVE"})
    escalated = await db.assessments.count_documents({"final_decision": "ESCALATE_TO_HUMAN"})
    blocked = await db.assessments.count_documents({"block_merge": True})
    by_risk = {
        "LOW": await db.assessments.count_documents({"risk_level": "LOW"}),
        "MEDIUM": await db.assessments.count_documents({"risk_level": "MEDIUM"}),
        "HIGH": await db.assessments.count_documents({"risk_level": "HIGH"}),
        "CRITICAL": await db.assessments.count_documents({"risk_level": "CRITICAL"}),
    }
    by_source = {
        "github_pr": await db.assessments.count_documents({"change_source": "github_pr"}),
        "firewall_api": await db.assessments.count_documents({"change_source": "firewall_api"}),
        "servicenow": await db.assessments.count_documents({"change_source": "servicenow"}),
        "jira": await db.assessments.count_documents({"change_source": "jira"}),
    }
    recent = await db.assessments.find({}, {"_id": 0, "assessment_id": 1,
        "risk_level": 1, "adjusted_risk_score": 1, "final_decision": 1,
        "intent_summary": 1, "change_source": 1, "detected_stack": 1,
        "created_at": 1}).sort("created_at", -1).limit(10).to_list(10)
    return {
        "total": total,
        "auto_approved": auto_approved,
        "escalated": escalated,
        "blocked": blocked,
        "by_risk_level": by_risk,
        "by_source": by_source,
        "recent_assessments": recent,
    }


# ─── Health & RAG Routes ──────────────────────────────────────────────────────

@api_router.get("/v1/health/rag")
async def rag_health():
    """Return ChromaDB collection stats."""
    from rag.chroma_db import get_collection_stats
    stats = get_collection_stats()
    overall = "healthy" if all(v["status"] == "healthy" for v in stats.values()) else "degraded"
    return {
        "status": overall,
        "collections": stats,
        "embedding_model": "SimpleEmbeddingFunction (256-dim keyword-frequency)",
        "last_checked": datetime.now(timezone.utc).isoformat(),
    }


@api_router.post("/v1/knowledge-base/seed")
async def seed_knowledge_base():
    """Seed ChromaDB with sample CVE, ATT&CK, and CIS/NIST data."""
    from rag.chroma_db import seed_all_collections, get_collection_stats
    seed_all_collections()
    stats = get_collection_stats()
    return {"status": "seeded", "collections": stats}


@api_router.get("/v1/audit")
async def get_audit_log(limit: int = 100):
    """Return structured audit log of all assessments."""
    cursor = db.assessments.find({}, {
        "_id": 0,
        "assessment_id": 1,
        "change_source": 1,
        "detected_stack": 1,
        "risk_level": 1,
        "adjusted_risk_score": 1,
        "final_decision": 1,
        "block_merge": 1,
        "intent_summary": 1,
        "llm_rag_enriched": 1,
        "output_targets": 1,
        "errors": 1,
        "created_at": 1,
    }).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(limit)
    return {"entries": docs, "total": len(docs)}


@api_router.get("/")
async def root():
    return {"service": "NetGuard Change-Risk Gate v2", "status": "running",
            "docs": "/docs", "version": "2.0.0"}


# ─── App Lifecycle ────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    """Initialize ChromaDB and seed knowledge base on startup."""
    try:
        from rag.chroma_db import seed_all_collections
        seed_all_collections()
        logger.info("ChromaDB initialized and seeded successfully")
    except Exception as e:
        logger.warning(f"ChromaDB seed failed (non-fatal): {e}")


@app.on_event("shutdown")
async def shutdown():
    client.close()


app.include_router(api_router)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _firewall_rule_to_diff(rule: dict) -> str:
    """Convert a firewall rule dict to a pseudo-diff string for assessment."""
    lines = []
    lines.append("+ resource \"aws_security_group_rule\" \"netguard_rule\" {")
    for k, v in rule.items():
        lines.append(f"+   {k} = \"{v}\"")
    lines.append("+ }")
    return "\n".join(lines)
