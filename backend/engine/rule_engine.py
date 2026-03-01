"""YAML rule engine — deterministic evaluation of policy rules against parsed changes."""
import os
import re
import yaml
from pathlib import Path
from typing import List
from agents.state import FindingItem


POLICIES_DIR = Path(__file__).parent.parent / "config" / "policies"


def load_all_rules() -> list:
    """Load all YAML policy files from config/policies/."""
    all_rules = []
    for yaml_file in POLICIES_DIR.glob("*.yaml"):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
            if data and "rules" in data:
                all_rules.extend(data["rules"])
    return all_rules


def calculate_blast_radius(parsed_change: dict, rule_findings: List[FindingItem]) -> dict:
    """Estimate blast radius based on resources and findings."""
    resource_count = parsed_change.get("resource_count", 0)
    services = parsed_change.get("services_detected", [])
    critical_findings = [f for f in rule_findings if f["severity"] == "CRITICAL"]
    high_findings = [f for f in rule_findings if f["severity"] == "HIGH"]

    if critical_findings:
        scope = "BROAD"
        impacted = max(resource_count * 3, 8)
    elif high_findings:
        scope = "MODERATE"
        impacted = max(resource_count * 2, 4)
    elif rule_findings:
        scope = "NARROW"
        impacted = max(resource_count, 2)
    else:
        scope = "MINIMAL"
        impacted = resource_count or 1

    return {
        "scope": scope,
        "impacted_count": impacted,
        "impacted_services": services,
        "description": _blast_description(scope, impacted),
    }


def evaluate_rules(raw_diff: str, parsed_change: dict) -> tuple:
    """
    Evaluate all rules against the raw diff and parsed change.
    Returns (findings, base_risk_score).
    Safety invariant: CRITICAL findings (score contribution >= 35) force block_merge.
    """
    rules = load_all_rules()
    findings: List[FindingItem] = []
    total_score = 0
    diff_lower = raw_diff.lower()

    for rule in rules:
        matched = _match_rule(rule, raw_diff, diff_lower, parsed_change)
        if matched:
            severity = rule.get("severity", "LOW")
            score_contribution = rule.get("score", 10)
            block = rule.get("block_merge", False)

            # Safety invariant: CRITICAL always blocks
            if severity == "CRITICAL":
                block = True

            findings.append(FindingItem(
                rule_id=rule["id"],
                title=rule["name"],
                severity=severity,
                description=rule["description"],
                score_contribution=score_contribution,
                block_merge=block,
                tags=rule.get("tags", []),
            ))
            total_score += score_contribution

    # Cap at 100
    base_risk_score = min(total_score, 100)
    return findings, base_risk_score


def _match_rule(rule: dict, raw_diff: str, diff_lower: str, parsed_change: dict) -> bool:
    """Check if a rule matches based on pattern keywords."""
    patterns = rule.get("patterns", {})
    if not patterns:
        return False

    matches = []

    # CIDR keywords
    if "cidr_keywords" in patterns:
        cidr_match = any(kw.lower() in diff_lower for kw in patterns["cidr_keywords"])
        matches.append(cidr_match)

    # Port keywords (only relevant if CIDR already matched for NET-001/002)
    if "port_keywords" in patterns and matches and matches[-1]:
        port_match = any(kw.lower() in diff_lower for kw in patterns["port_keywords"])
        matches.append(port_match)

    # Resource type keywords
    if "resource_keywords" in patterns:
        res_match = any(kw.lower() in diff_lower for kw in patterns["resource_keywords"])
        matches.append(res_match)

    # Action keywords (IAM wildcards)
    if "action_keywords" in patterns:
        action_match = any(kw.lower() in diff_lower for kw in patterns["action_keywords"])
        matches.append(action_match)

    # Role keywords
    if "role_keywords" in patterns:
        role_match = any(kw in raw_diff for kw in patterns["role_keywords"])
        matches.append(role_match)

    # Direction keywords (for egress rules)
    if "direction_keywords" in patterns:
        dir_match = any(kw.lower() in diff_lower for kw in patterns["direction_keywords"])
        matches.append(dir_match)

    # General keyword patterns
    if "keyword_patterns" in patterns:
        kw_match = any(kw.lower() in diff_lower for kw in patterns["keyword_patterns"])
        matches.append(kw_match)

    return all(matches) if matches else False


def _blast_description(scope: str, count: int) -> str:
    desc = {
        "BROAD": f"Change affects approximately {count} assets across multiple availability zones",
        "MODERATE": f"Change affects approximately {count} assets within a single availability zone",
        "NARROW": f"Change affects approximately {count} assets in a targeted segment",
        "MINIMAL": "Change has minimal blast radius — isolated resource modification",
    }
    return desc.get(scope, "Unknown blast radius")
