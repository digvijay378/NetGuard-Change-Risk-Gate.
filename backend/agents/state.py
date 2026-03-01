"""AgentState TypedDict — persists all intermediate results across the 6-node graph."""
from typing import TypedDict, List, Optional, Annotated
import operator


class FindingItem(TypedDict):
    rule_id: str
    title: str
    severity: str        # LOW | MEDIUM | HIGH | CRITICAL
    description: str
    score_contribution: int
    block_merge: bool
    tags: List[str]


class CVEMatch(TypedDict):
    cve_id: str
    title: str
    cvss: float
    description: str
    services: List[str]
    source: str


class AttackTechnique(TypedDict):
    technique_id: str
    technique_name: str
    tactic: str
    relevance: str
    description: str


class PolicyControl(TypedDict):
    control_id: str
    framework: str
    title: str
    description: str
    remediation: str


class SimilarIncident(TypedDict):
    assessment_id: str
    summary: str
    outcome: str
    risk_level: str
    date: str


class AgentStep(TypedDict):
    node: str
    status: str      # pending | running | completed | failed
    input_summary: str
    output_summary: str
    duration_ms: int


class AgentState(TypedDict):
    # Input
    change_source: str       # github_pr | firewall_api | servicenow | jira
    raw_diff: str
    change_metadata: dict

    # Node 1 output — Ingestion
    parsed_change: Optional[dict]          # Legacy dict for blast radius
    normalized_changes: list               # List[NormalizedChange] IR objects
    detected_stack: str      # aws | azure | gcp | cisco_ios | paloalto | fortigate | kubernetes | onprem | unknown

    # Node 2 output — Rule Engine
    rule_findings: List[FindingItem]
    base_risk_score: int
    blast_radius: Optional[dict]

    # Node 3 output — RAG Retrieval
    cve_matches: List[CVEMatch]
    attack_techniques: List[AttackTechnique]
    policy_controls: List[PolicyControl]
    similar_incidents: List[SimilarIncident]

    # Node 4 output — Analysis Agent
    adjusted_risk_score: int
    score_adjustment_reason: str
    threat_narrative: str
    validation_checklist: List[str]
    intent_summary: str

    # Node 5 output — Decision Agent
    risk_level: str          # LOW | MEDIUM | HIGH | CRITICAL
    final_decision: str      # AUTO_APPROVE | ESCALATE_TO_HUMAN
    required_approvers: List[str]
    block_merge: bool

    # Node 6 output — Output Agent
    output_posted: bool
    output_targets: List[str]

    # Pipeline trace
    agent_trace: List[AgentStep]
    rag_sources: List[dict]
    llm_rag_enriched: bool

    # Errors
    errors: List[str]
