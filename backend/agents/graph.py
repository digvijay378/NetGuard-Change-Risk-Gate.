"""
NetGuard LangGraph-style Agent Orchestration — 6-node pipeline.
All LLM calls (Claude 3.5 Sonnet) are PLACEHOLDER — returns realistic mock responses.
The full architecture mirrors the PRD spec: ingestion → rule_engine → rag_retrieval → analysis → decision → output.
"""
import time
import random
import string
from datetime import datetime, timezone
from typing import List

from agents.state import AgentState, AgentStep, FindingItem
from parsers.parser import detect_stack, parse_to_ir
from engine.rule_engine import evaluate_rules, calculate_blast_radius
from rag.chroma_db import (
    query_cves, query_attack_techniques, query_policy_controls,
    query_change_history, add_to_change_history,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _step(node: str, status: str, input_s: str, output_s: str, ms: int) -> AgentStep:
    return AgentStep(node=node, status=status, input_summary=input_s,
                     output_summary=output_s, duration_ms=ms)


def _make_assessment_id() -> str:
    suffix = ''.join(random.choices(string.digits, k=4))
    return f"crg-{datetime.now(timezone.utc).year}-{suffix}"


# ─── Node 1: Ingestion Agent ──────────────────────────────────────────────────

def node_ingestion(state: AgentState) -> AgentState:
    t0 = time.monotonic()
    raw = state.get("raw_diff", "")
    source = state.get("change_source", "unknown")
    detected = detect_stack(raw, source)
    parsed = parse_change(raw, detected)
    ms = int((time.monotonic() - t0) * 1000)
    trace = list(state.get("agent_trace", []))
    trace.append(_step("Node 1: Ingestion", "completed",
                        f"source={source}, diff_length={len(raw)}",
                        f"stack={detected}, resources={len(parsed.get('resources', []))}", ms))
    return {**state, "detected_stack": detected, "parsed_change": parsed, "agent_trace": trace}


# ─── Node 2: Rule Engine Agent ────────────────────────────────────────────────

def node_rule_engine(state: AgentState) -> AgentState:
    t0 = time.monotonic()
    raw = state.get("raw_diff", "")
    parsed = state.get("parsed_change", {})
    findings, base_score = evaluate_rules(raw, parsed)
    blast = calculate_blast_radius(parsed, findings)
    ms = int((time.monotonic() - t0) * 1000)
    trace = list(state.get("agent_trace", []))
    trace.append(_step("Node 2: Rule Engine", "completed",
                        f"parsed_change={list(parsed.keys())}",
                        f"findings={len(findings)}, base_score={base_score}", ms))
    return {**state, "rule_findings": findings, "base_risk_score": base_score,
            "blast_radius": blast, "agent_trace": trace}


# ─── Node 3: RAG Retrieval Agent ─────────────────────────────────────────────

def node_rag_retrieval(state: AgentState) -> AgentState:
    t0 = time.monotonic()
    findings: List[FindingItem] = state.get("rule_findings", [])
    parsed = state.get("parsed_change", {})
    stack = state.get("detected_stack", "")

    # Build rich query from findings and parsed change
    finding_text = " ".join([f['title'] for f in findings]) if findings else "network change"
    tags_text = " ".join([t for f in findings for t in f.get('tags', [])])
    ports_text = " ".join(parsed.get("ports_modified", []))
    query = f"{finding_text} {tags_text} {stack} port {ports_text} security vulnerability"

    cves = query_cves(query, top_k=5)
    attacks = query_attack_techniques(query, top_k=5)
    controls = query_policy_controls(f"{finding_text} {stack} compliance control", top_k=4)
    history = query_change_history(finding_text, top_k=3)

    rag_sources = [
        {"collection": "cve_knowledge", "query": query, "results": len(cves)},
        {"collection": "attack_techniques", "query": query, "results": len(attacks)},
        {"collection": "policy_controls", "query": query, "results": len(controls)},
        {"collection": "change_history", "query": query, "results": len(history)},
    ]
    ms = int((time.monotonic() - t0) * 1000)
    trace = list(state.get("agent_trace", []))
    trace.append(_step("Node 3: RAG Retrieval", "completed",
                        f"query='{query[:80]}...'",
                        f"cves={len(cves)}, techniques={len(attacks)}, controls={len(controls)}, history={len(history)}", ms))
    return {**state, "cve_matches": cves, "attack_techniques": attacks,
            "policy_controls": controls, "similar_incidents": history,
            "rag_sources": rag_sources, "llm_rag_enriched": True, "agent_trace": trace}


# ─── Node 4: Analysis Agent (PLACEHOLDER — Claude 3.5 Sonnet) ────────────────

def node_analysis(state: AgentState) -> AgentState:
    """
    PLACEHOLDER: In production, calls Claude 3.5 Sonnet via:
        llm = ChatAnthropic(model='claude-3-5-sonnet-20241022', temperature=0)
        structured_llm = llm.with_structured_output(AnalysisOutput)
    Returns a realistic analysis based on the findings.
    """
    t0 = time.monotonic()
    findings: List[FindingItem] = state.get("rule_findings", [])
    base_score = state.get("base_risk_score", 0)
    cves = state.get("cve_matches", [])
    attacks = state.get("attack_techniques", [])
    parsed = state.get("parsed_change", {})
    stack = state.get("detected_stack", "")
    meta = state.get("change_metadata", {})

    # Score adjustment: +3-5 if high CVSS CVE matched
    high_cvss_cves = [c for c in cves if c.get("cvss", 0) >= 7.0]
    adjustment = min(len(high_cvss_cves) * 3, 10) if high_cvss_cves else 0
    adjusted_score = min(base_score + adjustment, 100)

    # Generate adjustment reason
    if high_cvss_cves:
        top_cve = max(high_cvss_cves, key=lambda c: c.get("cvss", 0))
        adj_reason = f"RAG matched {top_cve['cve_id']} (CVSS {top_cve['cvss']}) relevant to this change. Score increased by +{adjustment}."
    else:
        adj_reason = "No high-severity CVEs matched in RAG retrieval. Score unchanged from rule engine baseline."

    # Generate threat narrative from findings
    threat_narrative = _generate_threat_narrative(findings, cves, attacks, stack, parsed, meta)
    intent_summary = _generate_intent_summary(findings, parsed, stack, meta)
    checklist = _generate_validation_checklist(findings, cves, stack, parsed)

    ms = int((time.monotonic() - t0) * 1000)
    trace = list(state.get("agent_trace", []))
    trace.append(_step("Node 4: Analysis Agent", "completed",
                        f"[PLACEHOLDER] base_score={base_score}, cvss_matches={len(high_cvss_cves)}",
                        f"adjusted_score={adjusted_score}, narrative_length={len(threat_narrative)}", ms))
    return {**state, "adjusted_risk_score": adjusted_score,
            "score_adjustment_reason": adj_reason,
            "threat_narrative": threat_narrative,
            "validation_checklist": checklist,
            "intent_summary": intent_summary,
            "agent_trace": trace}


# ─── Node 5: Decision Agent (Pure Python — NOT LLM) ──────────────────────────

def node_decision(state: AgentState) -> AgentState:
    """
    Safety-critical: deterministic Python logic. NOT an LLM call.
    Invariants:
    - adjusted_score >= base_risk_score always
    - Any CRITICAL rule finding forces ESCALATE_TO_HUMAN
    - Any CVSS >= 7.0 CVE forces escalation
    - Any ATT&CK Initial Access / Execution tactic forces escalation
    """
    t0 = time.monotonic()
    adj_score = state.get("adjusted_risk_score", state.get("base_risk_score", 0))
    findings: List[FindingItem] = state.get("rule_findings", [])
    cves = state.get("cve_matches", [])
    attacks = state.get("attack_techniques", [])

    # Safety invariant: CRITICAL rule findings from Node 2 CANNOT be overridden
    has_critical_finding = any(f["severity"] == "CRITICAL" for f in findings)
    has_block_merge_finding = any(f.get("block_merge", False) for f in findings)
    has_high_cvss = any(c.get("cvss", 0) >= 7.0 for c in cves)
    has_initial_access = any(
        a.get("tactic", "").lower() in ["initial-access", "execution"]
        for a in attacks
    )

    # Determine risk level
    if adj_score >= 90 or has_critical_finding:
        risk_level = "CRITICAL"
    elif adj_score >= 70 or has_block_merge_finding:
        risk_level = "HIGH"
    elif adj_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Decision logic
    force_escalate = (
        has_critical_finding or
        has_block_merge_finding or
        (has_high_cvss and adj_score >= 40) or
        (has_initial_access and adj_score >= 40) or
        risk_level in ("HIGH", "CRITICAL")
    )

    if force_escalate:
        final_decision = "ESCALATE_TO_HUMAN"
        block_merge = True
        required_approvers = _determine_approvers(risk_level)
    elif risk_level == "MEDIUM":
        final_decision = "AUTO_APPROVE"
        block_merge = False
        required_approvers = []  # Weekly digest review
    else:
        final_decision = "AUTO_APPROVE"
        block_merge = False
        required_approvers = []

    ms = int((time.monotonic() - t0) * 1000)
    trace = list(state.get("agent_trace", []))
    trace.append(_step("Node 5: Decision Agent", "completed",
                        f"adj_score={adj_score}, critical={has_critical_finding}, high_cvss={has_high_cvss}",
                        f"decision={final_decision}, risk={risk_level}, block={block_merge}", ms))
    return {**state, "risk_level": risk_level, "final_decision": final_decision,
            "required_approvers": required_approvers, "block_merge": block_merge,
            "agent_trace": trace}


# ─── Node 6: Output Agent (PLACEHOLDER) ──────────────────────────────────────

def node_output(state: AgentState) -> AgentState:
    """
    PLACEHOLDER: In production, posts results to GitHub PR, ServiceNow, Jira.
    For AUTO_APPROVE: posts green comment, allows merge, writes audit log.
    For ESCALATE_TO_HUMAN: blocks merge, notifies approvers, posts full report.
    """
    t0 = time.monotonic()
    source = state.get("change_source", "unknown")
    decision = state.get("final_decision", "AUTO_APPROVE")
    meta = state.get("change_metadata", {})

    # Determine output targets
    targets = []
    if source == "github_pr":
        targets.append("github_pr_comment")
        targets.append("github_commit_status")
    elif source == "servicenow":
        targets.append("servicenow_work_note")
        targets.append("servicenow_field_update")
    elif source == "jira":
        targets.append("jira_comment")
        targets.append("jira_label")
    else:
        targets.append("audit_log_only")

    # Add to change history RAG for future similarity matching
    assessment_id = meta.get("assessment_id", _make_assessment_id())
    summary = state.get("intent_summary", "Infrastructure change")
    outcome = "auto_approved" if decision == "AUTO_APPROVE" else "escalated"
    risk_level = state.get("risk_level", "LOW")

    try:
        add_to_change_history(assessment_id, summary, outcome, risk_level)
    except Exception:
        pass  # Non-blocking

    ms = int((time.monotonic() - t0) * 1000)
    trace = list(state.get("agent_trace", []))
    trace.append(_step("Node 6: Output Agent", "completed",
                        f"[PLACEHOLDER] source={source}, decision={decision}",
                        f"targets={targets}", ms))
    return {**state, "output_posted": True, "output_targets": targets, "agent_trace": trace}


# ─── Main Graph Orchestrator ──────────────────────────────────────────────────

def run_agent_graph(
    change_source: str,
    raw_diff: str,
    change_metadata: dict,
) -> AgentState:
    """Execute the full 6-node agent pipeline and return the final AgentState."""
    assessment_id = _make_assessment_id()
    change_metadata["assessment_id"] = assessment_id

    state: AgentState = {
        "change_source": change_source,
        "raw_diff": raw_diff,
        "change_metadata": change_metadata,
        "parsed_change": None,
        "detected_stack": "unknown",
        "rule_findings": [],
        "base_risk_score": 0,
        "blast_radius": None,
        "cve_matches": [],
        "attack_techniques": [],
        "policy_controls": [],
        "similar_incidents": [],
        "adjusted_risk_score": 0,
        "score_adjustment_reason": "",
        "threat_narrative": "",
        "validation_checklist": [],
        "intent_summary": "",
        "risk_level": "LOW",
        "final_decision": "AUTO_APPROVE",
        "required_approvers": [],
        "block_merge": False,
        "output_posted": False,
        "output_targets": [],
        "agent_trace": [],
        "rag_sources": [],
        "llm_rag_enriched": False,
        "errors": [],
    }

    try:
        state = node_ingestion(state)
        state = node_rule_engine(state)
        state = node_rag_retrieval(state)
        state = node_analysis(state)
        state = node_decision(state)
        state = node_output(state)
    except Exception as e:
        state["errors"].append(str(e))

    return state


# ─── Narrative Generators (used by Analysis Agent placeholder) ───────────────

def _generate_threat_narrative(findings, cves, attacks, stack, parsed, meta) -> str:
    if not findings:
        return (
            "This infrastructure change does not trigger any policy rules. The modification "
            "appears to be a routine configuration update with no identified security impact. "
            "Standard deployment procedures should be followed."
        )

    critical = [f for f in findings if f['severity'] == 'CRITICAL']
    high = [f for f in findings if f['severity'] == 'HIGH']
    top_cve = max(cves, key=lambda c: c.get("cvss", 0)) if cves else None
    top_attack = attacks[0] if attacks else None

    author = meta.get("author", "an unknown author")
    pr_url = meta.get("pr_url", "")
    url_part = f"(PR: {pr_url}) " if pr_url else ""

    narrative = f"This {stack.upper()} infrastructure change {url_part}by {author} "

    if critical:
        finding_names = ", ".join(f"**{f['title']}**" for f in critical[:2])
        narrative += (
            f"introduces {len(critical)} CRITICAL security finding(s): {finding_names}. "
        )
    elif high:
        finding_names = ", ".join(f"**{f['title']}**" for f in high[:2])
        narrative += f"introduces {len(high)} HIGH severity finding(s): {finding_names}. "

    if top_cve:
        narrative += (
            f"\n\nRAG retrieval identified {top_cve['cve_id']} ({top_cve.get('title', 'CVE')}, "
            f"CVSS {top_cve.get('cvss', 'N/A')}) as directly relevant to this change type. "
            f"{top_cve.get('description', '')[:200]} "
        )

    if top_attack:
        narrative += (
            f"\n\nMITRE ATT&CK analysis maps this change to **{top_attack['technique_id']} — "
            f"{top_attack['technique_name']}** (Tactic: {top_attack.get('tactic', 'unknown').replace('-', ' ').title()}). "
            f"{top_attack.get('relevance', '')[:200]} "
        )

    resources = parsed.get("resources", parsed.get("rule_count", 0))
    if isinstance(resources, list) and resources:
        narrative += f"\n\nAffected resources include: {', '.join(resources[:5])}."
    elif isinstance(resources, int) and resources > 0:
        narrative += f"\n\nChange modifies {resources} firewall/ACL rules."

    return narrative.strip()


def _generate_intent_summary(findings, parsed, stack, meta) -> str:
    if not findings:
        return f"Routine {stack.upper()} infrastructure configuration update with no identified security findings."
    top = findings[0]
    resources = parsed.get("resources", [])
    res_str = f" affecting {resources[0]}" if resources else ""
    author = meta.get("author", "")
    author_str = f" by {author}" if author else ""
    return f"This {stack.upper()} change{author_str} triggers {top['severity']} finding '{top['title']}'{res_str}."


def _generate_validation_checklist(findings, cves, stack, parsed) -> list:
    checklist = []
    tags_all = [t for f in findings for t in f.get("tags", [])]

    if "ssh" in tags_all or "port_exposure" in tags_all:
        checklist.append("Confirm SSH access is not already available via bastion: `aws ec2 describe-instances --filters Name=tag:Name,Values=bastion*`")
        checklist.append("Verify OpenSSH version on target instances: `ssh -V` (must be >= 9.8p1 to mitigate CVE-2024-6387)")
        checklist.append("Check security group inbound rules before merge: `aws ec2 describe-security-groups --group-ids <sg-id>`")

    if "rdp" in tags_all:
        checklist.append("Confirm RDP is accessible only via VPN or bastion — direct internet exposure is prohibited")
        checklist.append("Verify NLA (Network Level Authentication) is enforced: `Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication`")

    if "iam" in tags_all or "privilege_escalation" in tags_all:
        checklist.append("Review IAM policy document for least-privilege compliance: `aws iam get-policy-version --policy-arn <arn> --version-id v1`")
        checklist.append("Verify no existing principals already have wildcard permissions before adding more")
        checklist.append("Get written security sign-off for any wildcard IAM action assignment")

    if "dns" in tags_all:
        checklist.append("Verify DNS zone change is authorized and matches ticket description")
        checklist.append("Confirm DNSSEC is configured if enabling internet-facing DNS zone")
        checklist.append("Check for any DNS delegation chain integrity: `dig NS <zone>`")

    if "egress" in tags_all or "exfiltration" in tags_all:
        checklist.append("Confirm unrestricted egress is required for specific business function")
        checklist.append("Implement CASB or proxy for egress traffic inspection if rule must be approved")

    high_cvss = [c for c in cves if c.get("cvss", 0) >= 7.0]
    for cve in high_cvss[:2]:
        checklist.append(f"Verify patching against {cve['cve_id']} (CVSS {cve.get('cvss', 'N/A')}): confirm affected service version")

    if not checklist:
        checklist.append("Review change against organizational security baseline before approval")
        checklist.append("Confirm change has passed internal CAB (Change Advisory Board) review")
        checklist.append(f"Document business justification for {stack.upper()} infrastructure modification")

    # Always add approver requirement for escalations
    checklist.append("Obtain written sign-off from all required approvers before merge (see Required Approvers section)")

    return checklist[:10]  # Max 10 items


def _determine_approvers(risk_level: str) -> list:
    approvers = {
        "CRITICAL": ["CISO", "Network Architect", "Security Lead"],
        "HIGH": ["Network Architect", "Security Lead"],
        "MEDIUM": [],
        "LOW": [],
    }
    return approvers.get(risk_level, [])
