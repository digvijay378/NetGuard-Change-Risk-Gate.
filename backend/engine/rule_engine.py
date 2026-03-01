"""
IR-based rule engine — evaluates NormalizedChange objects against policy rules.
Each rule is a pure function → deterministic, testable, vendorless.
Includes: network rules, IAM rules, DNS/SEC rules, PAN-OS rules, Kubernetes rules,
          cross-resource correlation rules, compensating controls, temporal scoring.
"""
import re
from typing import List, Optional, Tuple
import yaml
from pathlib import Path

from parsers.ir import NormalizedChange, PortRange

# ─── Remediation Templates ────────────────────────────────────────────────────

REMEDIATION_TEMPLATES = {
    "NET-001": (
        "# Option A — Restrict to VPN/bastion CIDR only:\n"
        "cidr_blocks = [var.vpn_cidr]   # e.g. 10.0.0.0/8\n\n"
        "# Option B — Use bastion security group reference (preferred):\n"
        "source_security_group_id = aws_security_group.bastion.id\n\n"
        "# Option C — Eliminate SSH entirely (recommended):\n"
        "# aws ssm start-session --target i-xxxxx\n"
        "# Remove ingress rule entirely and configure SSM Session Manager"
    ),
    "NET-002": (
        "# Replace all-port rule with specific service ports:\n"
        "from_port = 443\nto_port   = 443\nprotocol  = \"tcp\"\n"
        "cidr_blocks = [var.vpn_cidr]\n\n"
        "# Or use security group references instead of CIDRs"
    ),
    "NET-003": (
        "# Restrict egress to specific destinations:\n"
        "egress {\n"
        "  from_port   = 443\n  to_port     = 443\n  protocol    = \"tcp\"\n"
        "  cidr_blocks = [\"specific.service.ip/32\"]\n}\n"
        "# Consider VPC endpoints to avoid internet egress entirely"
    ),
    "NET-004": (
        "# Document change in CAB ticket before approval\n"
        "# Verify NAT gateway change doesn't break existing private subnet connectivity\n"
        "# Test with: aws ec2 describe-nat-gateways --filter Name=state,Values=available"
    ),
    "IAM-001": (
        "# Replace wildcard with minimum required permissions:\n"
        "# BEFORE: Action = [\"*\"]\n"
        "# AFTER (example — S3 + Lambda):\n"
        "actions = [\n"
        "  \"s3:GetObject\", \"s3:PutObject\", \"s3:ListBucket\",\n"
        "  \"lambda:InvokeFunction\"\n"
        "]\n"
        "resources = [\"arn:aws:s3:::my-bucket/*\"]\n\n"
        "# Use IAM Access Analyzer to generate least-privilege policy:\n"
        "# aws accessanalyzer start-policy-generation --policy-generation-details '{\"principalArn\":\"...\"}"
    ),
    "IAM-002": (
        "# Replace broad role with specific permissions:\n"
        "# BEFORE: role_definition_name = \"Owner\"\n"
        "# AFTER: Create custom role with only required actions\n"
        "resource \"azurerm_role_definition\" \"custom\" {\n"
        "  permissions { actions = [\"Microsoft.Compute/virtualMachines/read\"] }\n"
        "}\n"
        "# Or use built-in Reader + specific write permissions"
    ),
    "DNS-001": (
        "# Verify DNS zone change is authorized via CAB ticket\n"
        "# Enable DNSSEC if exposing internet-facing zone\n"
        "# Validate after change: dig NS <zone> && dig A <record>"
    ),
    "SEC-002": (
        "# Logging must remain enabled — restore:\n"
        "enable_log_file_validation = true\n"
        "enable_logging = true\n"
        "# NIST CA-7 requires continuous monitoring — disabling is a compliance violation"
    ),
    "PAN-001": (
        "# Replace 'any' source with specific trusted address objects\n"
        "# Create address object for permitted source ranges:\n"
        "# set address VPN-Users ip-netmask 10.200.0.0/16\n"
        "# Update rule: set source VPN-Users\n"
        "# Also apply Security Profiles (AV, URL, IPS) to the rule"
    ),
    "PAN-002": (
        "# Replace application=any with specific App-IDs:\n"
        "# Identify required applications using App-ID test:\n"
        "# test security-policy-match source <ip> destination <ip> application <app>\n"
        "# Replace 'any' with specific application names to re-enable App-ID inspection"
    ),
    "K8S-001": (
        "# Remove empty ingress rule and add explicit allow sources:\n"
        "ingress:\n"
        "- from:\n"
        "  - namespaceSelector:\n"
        "      matchLabels:\n"
        "        kubernetes.io/metadata.name: allowed-namespace\n"
        "  ports:\n"
        "  - protocol: TCP\n"
        "    port: 8080\n"
        "# Never use empty ingress: [] — it allows ALL sources"
    ),
    "K8S-002": (
        "# Replace wildcard RBAC with specific resource permissions:\n"
        "rules:\n"
        "- apiGroups: [\"apps\"]\n"
        "  resources: [\"deployments\"]\n"
        "  verbs: [\"get\", \"list\", \"watch\"]\n"
        "# Use 'kubectl auth can-i' to verify minimum required permissions"
    ),
    "K8S-003": (
        "# Remove privileged: true from securityContext:\n"
        "securityContext:\n"
        "  privileged: false\n"
        "  runAsNonRoot: true\n"
        "  runAsUser: 1000\n"
        "  readOnlyRootFilesystem: true\n"
        "# Use Linux capabilities instead of full privileged mode"
    ),
    "CORR-001": (
        "# Database directly exposed to internet:\n"
        "# 1. Remove public internet ingress on database security group\n"
        "# 2. Set publicly_accessible = false on the RDS instance\n"
        "# 3. Use VPC peering or PrivateLink for cross-account database access"
    ),
}


# ─── FindingItem Helper ───────────────────────────────────────────────────────

def make_finding(
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    score_contribution: int,
    block_merge: bool,
    tags: List[str],
    change: Optional[NormalizedChange] = None,
    extra_description: str = "",
) -> dict:
    finding = {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "description": description + (" " + extra_description if extra_description else ""),
        "score_contribution": score_contribution,
        "block_merge": block_merge or severity == "CRITICAL",
        "tags": tags,
        "line_number": change.line_start if change else 0,
        "code_snippet": (change.raw_snippet[:200] if change and change.raw_snippet else ""),
        "suggested_fix": REMEDIATION_TEMPLATES.get(rule_id, ""),
        "resource_name": (change.resource_name if change else ""),
    }
    return finding


# ─── Individual Rule Functions ────────────────────────────────────────────────

def _check_net001(c: NormalizedChange) -> List[dict]:
    """SSH or RDP from 0.0.0.0/0."""
    if (c.is_internet_exposed() and c.change_type != "REMOVE" and
            c.exposes_port(22, 2222, 3389, 5900)):
        port_str = ", ".join(
            str(p) for p in c.ports
            if p.is_any() or p.contains_port(22) or p.contains_port(3389) or p.contains_port(2222)
        )
        return [make_finding(
            "NET-001", "Unrestricted Internet Ingress (SSH/RDP)", "CRITICAL",
            f"Port {port_str or 'SSH/RDP'} exposed to {', '.join(c.source_cidrs[:2])} "
            f"on {c.resource_name}. Direct brute-force and exploit attack surface.",
            40, True, ["port_exposure", "ssh", "rdp", "initial_access"], c,
        )]
    return []


def _check_net002(c: NormalizedChange) -> List[dict]:
    """All ports from 0.0.0.0/0."""
    if (c.is_internet_exposed() and c.change_type != "REMOVE" and
            any(p.is_any() for p in c.ports)):
        # Skip if already caught by NET-001 for specific SSH/RDP ports
        if c.exposes_port(22, 3389) and len(c.ports) == 1:
            return []
        return [make_finding(
            "NET-002", "Unrestricted Internet Ingress (All Ports)", "CRITICAL",
            f"All TCP/UDP ports exposed to {', '.join(c.source_cidrs[:2])} "
            f"on {c.resource_name}. Entire service surface publicly accessible.",
            35, True, ["port_exposure", "initial_access", "wildcard_port"], c,
        )]
    return []


def _check_net003(c: NormalizedChange) -> List[dict]:
    """Unrestricted egress."""
    if (c.direction == "EGRESS" and c.action == "ALLOW" and c.change_type != "REMOVE" and
            any(p.is_any() for p in c.ports) and
            any(normalize_ip(d) in ("0.0.0.0/0", "::/0") for d in c.dest_cidrs)):
        return [make_finding(
            "NET-003", "Unrestricted Egress Rule", "MEDIUM",
            f"All outbound traffic permitted on {c.resource_name}. "
            "Enables data exfiltration over any protocol/port.",
            20, False, ["exfiltration", "egress", "data_exfiltration"], c,
        )]
    return []


def _check_net004(c: NormalizedChange) -> List[dict]:
    """NAT gateway modification."""
    if c.resource_type == "nat_gateway" and c.change_type in ("ADD", "MODIFY"):
        return [make_finding(
            "NET-004", "NAT Gateway Modification", "HIGH",
            f"NAT gateway change on {c.resource_name}. "
            "Can create covert exfiltration channels or break private subnet connectivity.",
            25, False, ["nat", "routing", "command_and_control"], c,
        )]
    return []


def _check_net005(c: NormalizedChange) -> List[dict]:
    """Route table modification."""
    if c.resource_type == "route" and c.change_type in ("ADD", "MODIFY"):
        return [make_finding(
            "NET-005", "Route Table Modification", "MEDIUM",
            f"Route change on {c.resource_name}. "
            "Route table changes can redirect traffic to attacker-controlled hosts.",
            15, False, ["routing", "lateral_movement"], c,
        )]
    return []


def _check_net006(c: NormalizedChange) -> List[dict]:
    """Security group or firewall rule modification — general."""
    if (c.resource_type == "firewall_rule" and c.change_type in ("ADD", "MODIFY") and
            not c.is_internet_exposed()):
        return [make_finding(
            "NET-006", "Firewall/Security Group Modification", "MEDIUM",
            f"Security control change on {c.resource_name}. "
            "Review for unintended access grants within VPC/network perimeter.",
            10, False, ["security_group", "network_perimeter"], c,
        )]
    return []


def _check_net007(c: NormalizedChange) -> List[dict]:
    """VPN or tunnel config change."""
    if (c.resource_type == "vpn_config" or
            (c.resource_type == "firewall_policy" and "vpn" in c.resource_name.lower())):
        return [make_finding(
            "NET-007", "VPN / Tunnel Configuration Change", "HIGH",
            f"VPN config change on {c.resource_name}. "
            "VPN changes can expose internal networks or create backdoor tunnels.",
            25, False, ["vpn", "tunnel", "network_boundary"], c,
        )]
    return []


def _check_net_admin(c: NormalizedChange) -> List[dict]:
    """Admin ports (Telnet, SNMP) from internet."""
    if (c.is_internet_exposed() and c.change_type != "REMOVE" and
            c.exposes_port(23, 161, 162, 8080, 8443, 9090, 9200)):
        port_str = ", ".join(str(p) for p in c.ports if not p.is_any())
        return [make_finding(
            "NET-008", "Unrestricted Internet Ingress (Management Ports)", "HIGH",
            f"Management port {port_str or 'admin/mgmt'} exposed to internet "
            f"on {c.resource_name}. Telnet, SNMP, and web consoles should never be internet-facing.",
            30, True, ["port_exposure", "management_interface", "initial_access"], c,
        )]
    return []


def _check_net_db(c: NormalizedChange) -> List[dict]:
    """Database ports from internet."""
    if (c.is_internet_exposed() and c.change_type != "REMOVE" and
            c.exposes_port(3306, 5432, 1433, 1521, 27017, 6379, 9200, 5601, 11211)):
        port_str = ", ".join(str(p) for p in c.ports if not p.is_any())
        return [make_finding(
            "NET-009", "Database Port Exposed to Internet", "CRITICAL",
            f"Database port {port_str or 'db'} exposed to {', '.join(c.source_cidrs[:2])} "
            f"on {c.resource_name}. Direct database access enables data theft and credential stuffing.",
            45, True, ["database", "data_exfiltration", "initial_access"], c,
        )]
    return []


def _check_iam001(c: NormalizedChange) -> List[dict]:
    """Wildcard IAM action."""
    if c.resource_type in ("iam_policy", "iam_attachment", "k8s_rbac") and c.has_wildcard_iam():
        if "*" in c.iam_actions:
            return [make_finding(
                "IAM-001", "Wildcard IAM Action (Action=[*])", "CRITICAL",
                f"IAM policy on {c.resource_name} grants all actions. "
                "Any compromised identity becomes a full cloud administrator.",
                45, True, ["iam", "privilege_escalation", "defense_evasion"], c,
            )]
    return []


def _check_iam002(c: NormalizedChange) -> List[dict]:
    """Admin/Owner role assignment."""
    admin_roles = {"owner", "contributor", "administrator", "administratoraccess",
                   "poweruseraccess", "fullaccess", "cluster-admin"}
    if c.resource_type in ("iam_rbac", "iam_attachment", "k8s_rbac"):
        for action in c.iam_actions:
            if action.lower() in admin_roles or action.lower().endswith("admin"):
                return [make_finding(
                    "IAM-002", f"Admin/Owner Role Assignment ({action})", "CRITICAL",
                    f"Role '{action}' assigned on {c.resource_name}. "
                    "Cloud admin access can disable logging and delete audit trails.",
                    40, True, ["iam", "rbac", "privilege_escalation"], c,
                )]
    return []


def _check_iam003(c: NormalizedChange) -> List[dict]:
    """New role binding/policy attachment."""
    if (c.resource_type in ("iam_binding", "iam_attachment", "iam_rbac") and
            c.change_type == "ADD" and not _check_iam001(c) and not _check_iam002(c)):
        return [make_finding(
            "IAM-003", "New IAM Role Binding / Policy Attachment", "HIGH",
            f"New permission grant on {c.resource_name}. "
            "Expand blast radius if grantee is compromised.",
            25, False, ["iam", "rbac", "permission_grant"], c,
        )]
    return []


def _check_iam005(c: NormalizedChange) -> List[dict]:
    """Wildcard resource in IAM."""
    if (c.resource_type in ("iam_policy",) and
            "*" in c.iam_resources and "*" not in c.iam_actions):
        return [make_finding(
            "IAM-005", "Wildcard Resource in IAM Policy (Resource=[*])", "HIGH",
            f"IAM policy on {c.resource_name} targets all resources (*). "
            "Should specify exact resource ARNs.",
            20, False, ["iam", "over_permissive"], c,
        )]
    return []


def _check_dns001(c: NormalizedChange) -> List[dict]:
    """DNS zone modification."""
    if c.resource_type == "dns_record" and c.change_type in ("ADD", "MODIFY"):
        return [make_finding(
            "DNS-001", "DNS Zone / Record Modification", "HIGH",
            f"DNS change on {c.resource_name}. "
            "DNS modifications enable MitM attacks, credential harvesting, and BGP hijacking.",
            30, False, ["dns", "hijacking", "collection"], c,
        )]
    return []


def _check_sec002(c: NormalizedChange) -> List[dict]:
    """Logging disabled."""
    if c.resource_type == "logging_config" and c.action == "DENY":
        return [make_finding(
            "SEC-002", "Logging / Monitoring Disabled", "HIGH",
            f"Logging disabled on {c.resource_name}. "
            "Violates NIST CA-7. Attacker can disable logging to cover tracks.",
            30, False, ["logging", "monitoring", "defense_evasion"], c,
        )]
    return []


def _check_pan001(c: NormalizedChange) -> List[dict]:
    """PAN-OS: any source to trusted zone."""
    if (c.vendor == "paloalto" and c.is_internet_exposed() and
            c.direction in ("INGRESS", "LATERAL")):
        return [make_finding(
            "PAN-001", "PAN-OS: Any Source to Trusted Zone", "HIGH",
            f"PAN-OS rule {c.resource_name} allows any source to internal zone. "
            "Disables zone-based segmentation. Apply Security Profiles to this rule.",
            35, False, ["panos", "firewall", "initial_access", "zone_bypass"], c,
        )]
    return []


def _check_pan002(c: NormalizedChange) -> List[dict]:
    """PAN-OS: application=any disables App-ID."""
    if (c.vendor == "paloalto" and c.resource_type == "firewall_policy" and
            any(p.is_any() for p in c.ports) and not c.is_internet_exposed()):
        return [make_finding(
            "PAN-002", "PAN-OS: Application=Any — App-ID Inspection Disabled", "MEDIUM",
            f"PAN-OS rule {c.resource_name} uses application=any, disabling deep packet "
            "inspection. Traffic passes without App-ID or threat prevention profiles.",
            20, False, ["panos", "app_id", "inspection_bypass"], c,
        )]
    return []


def _check_fortigate(c: NormalizedChange) -> List[dict]:
    """FortiGate VIP (port forwarding from internet)."""
    if c.vendor == "fortigate" and c.resource_type == "firewall_vip":
        return [make_finding(
            "NET-FG-001", "FortiGate VIP — Port Forwarding from Internet", "HIGH",
            f"FortiGate VIP {c.resource_name} forwards internet traffic to internal host. "
            "Any vulnerability in the target service is directly exploitable.",
            30, False, ["fortigate", "vip", "port_forwarding", "initial_access"], c,
        )]
    return []


def _check_k8s001(c: NormalizedChange) -> List[dict]:
    """Kubernetes NetworkPolicy allow-all ingress."""
    if (c.vendor == "kubernetes" and c.resource_type == "k8s_network_policy" and
            c.is_internet_exposed()):
        return [make_finding(
            "K8S-001", "Kubernetes NetworkPolicy: Allow-All Ingress", "CRITICAL",
            f"NetworkPolicy {c.resource_name} allows ingress from 0.0.0.0/0 to "
            f"{'all pods' if 'ALL_PODS' in c.dest_cidrs else 'selected pods'}. "
            "Eliminates pod-level network isolation.",
            40, True, ["kubernetes", "network_policy", "initial_access"], c,
        )]
    return []


def _check_k8s002(c: NormalizedChange) -> List[dict]:
    """Kubernetes RBAC wildcard."""
    if (c.vendor == "kubernetes" and c.resource_type == "k8s_rbac" and c.has_wildcard_iam()):
        return [make_finding(
            "K8S-002", "Kubernetes RBAC: Wildcard Permissions", "CRITICAL",
            f"RBAC resource {c.resource_name} grants wildcard verbs and resources. "
            "Full cluster administrative access — equivalent to root on all nodes.",
            45, True, ["kubernetes", "rbac", "privilege_escalation"], c,
        )]
    return []


def _check_k8s003(c: NormalizedChange) -> List[dict]:
    """Kubernetes privileged container."""
    if (c.vendor == "kubernetes" and c.resource_type == "k8s_workload" and
            c.has_wildcard_iam() and "host" in c.iam_resources):
        return [make_finding(
            "K8S-003", "Kubernetes: Privileged Container", "CRITICAL",
            f"Container in {c.resource_name} runs with privileged=true. "
            "Full host system access — container escape trivially possible.",
            40, True, ["kubernetes", "container_escape", "privilege_escalation"], c,
        )]
    return []


def _check_k8s004(c: NormalizedChange) -> List[dict]:
    """Kubernetes hostNetwork."""
    if (c.vendor == "kubernetes" and c.resource_type == "k8s_workload" and
            "host_network" in c.dest_cidrs):
        return [make_finding(
            "K8S-004", "Kubernetes: hostNetwork=true", "HIGH",
            f"Workload {c.resource_name} shares host network namespace. "
            "Pod can bind to any host port and access node-level network traffic.",
            30, False, ["kubernetes", "host_network", "lateral_movement"], c,
        )]
    return []


# ─── Cross-Resource Correlation Rules ────────────────────────────────────────

def _check_correlation(changes: List[NormalizedChange]) -> List[dict]:
    """Rules that require multiple resources to fire."""
    findings = []

    # CORR-001: Database port exposed via SG + publicly_accessible=true
    db_ports = {3306, 5432, 1433, 1521, 27017, 6379}
    has_db_exposure = any(
        c.is_internet_exposed() and any(c.exposes_port(p) for p in db_ports)
        for c in changes
    )
    if has_db_exposure:
        # Check for RDS publicly_accessible or similar in the other changes
        findings.append(make_finding(
            "CORR-001", "Exposed Database Endpoint (Multi-Resource)", "CRITICAL",
            "Database port directly accessible from internet via firewall rule. "
            "Combined with publicly_accessible=true this creates a directly-exposed database.",
            55, True,
            ["database", "data_exfiltration", "credential_access", "multi_resource"],
        ))

    # CORR-002: IAM wildcard + network exposure (both in same PR)
    has_iam_wildcard = any(c.has_wildcard_iam() for c in changes)
    has_net_exposure = any(c.is_internet_exposed() for c in changes)
    if has_iam_wildcard and has_net_exposure:
        findings.append(make_finding(
            "CORR-002", "Simultaneous IAM Wildcard + Network Exposure", "CRITICAL",
            "PR contains both a wildcard IAM grant AND a network exposure rule. "
            "Combined risk: attacker gains initial access via network then immediately escalates via IAM.",
            20, True,
            ["iam", "network", "combined_risk", "privilege_escalation"],
        ))

    return findings


# ─── Compensating Controls (Score Reducers) ──────────────────────────────────

def _apply_compensating_controls(findings: List[dict], changes: List[NormalizedChange],
                                   raw_diff: str) -> Tuple[List[dict], int]:
    """
    Reduce score when compensating controls are present.
    Returns (findings_with_context, score_reduction).
    Safety: CRITICAL findings score is never reduced below 30.
    """
    reduction = 0
    notes = []

    # WAF association reduces network exposure risk
    if re.search(r'aws_wafv2_web_acl_association|aws_waf_web_acl', raw_diff, re.IGNORECASE):
        reduction += 10
        notes.append("WAF association present (-10)")

    # Deny NACL in same diff partially mitigates SG rule
    if re.search(r'aws_network_acl_rule.*deny|deny.*aws_network_acl', raw_diff, re.IGNORECASE | re.DOTALL):
        reduction += 8
        notes.append("Deny NACL rule in same diff (-8)")

    # MFA enforcement on IAM change
    if re.search(r'aws:MultiFactorAuthPresent|mfa_enabled.*true|MFA', raw_diff, re.IGNORECASE):
        reduction += 5
        notes.append("MFA enforcement present (-5)")

    # Security exception reference in diff/commit
    if re.search(r'APPROVED-SEC-\d{4}-\d+|SECURITY-EXCEPTION-\d+', raw_diff):
        reduction += 5
        notes.append("Approved security exception referenced (-5)")

    if notes and reduction > 0:
        for f in findings:
            if f["severity"] == "CRITICAL":
                # Safety: never reduce CRITICAL below 30
                safe_reduction = min(reduction, max(0, f["score_contribution"] - 30))
                f["score_contribution"] = max(30, f["score_contribution"] - safe_reduction)
            elif f["severity"] == "HIGH":
                f["score_contribution"] = max(10, f["score_contribution"] - reduction)

    return findings, reduction


# ─── Main Evaluation Entry Point ─────────────────────────────────────────────

ALL_RULE_FUNS = [
    _check_net001, _check_net002, _check_net003, _check_net004, _check_net005,
    _check_net006, _check_net007, _check_net_admin, _check_net_db,
    _check_iam001, _check_iam002, _check_iam003, _check_iam005,
    _check_dns001, _check_sec002,
    _check_pan001, _check_pan002,
    _check_fortigate,
    _check_k8s001, _check_k8s002, _check_k8s003, _check_k8s004,
]


def evaluate_rules(raw_diff: str, normalized_changes: List[NormalizedChange]) -> Tuple[List[dict], int]:
    """
    Evaluate all rules against normalized IR.
    Returns (findings, base_risk_score).
    Safety invariants:
    - CRITICAL findings always have block_merge=True
    - Score is additive and capped at 100
    """
    findings: List[dict] = []

    # Per-change rules
    for change in normalized_changes:
        if change.change_type == "REMOVE":
            continue  # Removing rules doesn't add risk
        for rule_fn in ALL_RULE_FUNS:
            results = rule_fn(change)
            findings.extend(results)

    # Cross-resource correlation
    findings.extend(_check_correlation(normalized_changes))

    # Apply compensating controls
    findings, _ = _apply_compensating_controls(findings, normalized_changes, raw_diff)

    # Fallback: raw diff rules (for diffs that produced no IR changes)
    if not normalized_changes:
        findings.extend(_fallback_raw_rules(raw_diff))

    # Deduplicate (same rule on same resource)
    seen = set()
    deduped = []
    for f in findings:
        key = (f["rule_id"], f.get("resource_name", ""))
        if key not in seen:
            seen.add(key)
            # Enforce safety invariant
            if f["severity"] == "CRITICAL":
                f["block_merge"] = True
            deduped.append(f)

    base_score = min(sum(f["score_contribution"] for f in deduped), 100)
    return deduped, base_score


def _fallback_raw_rules(raw_diff: str) -> List[dict]:
    """Last resort rules for raw diff that couldn't be parsed to IR."""
    findings = []
    diff_lower = raw_diff.lower()

    if re.search(r'0\.0\.0\.0/0|::/0', raw_diff) and re.search(r'\b22\b|\bssh\b', diff_lower):
        findings.append(make_finding(
            "NET-001", "Unrestricted Internet Ingress (SSH/RDP) — Raw Detection", "CRITICAL",
            "SSH/RDP port detected with 0.0.0.0/0 CIDR in diff (raw fallback detection). "
            "Parser could not fully resolve IR — review manually.",
            40, True, ["port_exposure", "ssh", "fallback_detection"],
        ))

    # Detect wildcard IAM actions in various formats:
    # - JSON: "Action": "*" or "Action": ["*"]
    # - HCL: Action = "*" or Action = ["*"] or actions = ["*"]
    iam_wildcard_patterns = [
        r'"Action"\s*:\s*"\*"',           # JSON: "Action": "*"
        r'"Action"\s*:\s*\["\*"\]',       # JSON: "Action": ["*"]
        r'\bAction\s*=\s*\[?\s*"\*"\s*\]?',  # HCL: Action = "*" or Action = ["*"]
        r'\bactions\s*=\s*\["\*"\]',      # HCL lowercase: actions = ["*"]
    ]
    if any(re.search(p, raw_diff, re.IGNORECASE) for p in iam_wildcard_patterns):
        findings.append(make_finding(
            "IAM-001", "Wildcard IAM Action — Raw Detection", "CRITICAL",
            "Wildcard Action=[*] detected in diff (raw fallback detection).",
            45, True, ["iam", "privilege_escalation", "fallback_detection"],
        ))
    return findings


# ─── Blast Radius ─────────────────────────────────────────────────────────────

def calculate_blast_radius(parsed_change: dict, rule_findings: List[dict]) -> dict:
    """Estimate blast radius from legacy dict and findings."""
    resource_count = parsed_change.get("resource_count", 0)
    services = parsed_change.get("services_detected", [])
    critical = [f for f in rule_findings if f["severity"] == "CRITICAL"]
    high = [f for f in rule_findings if f["severity"] == "HIGH"]

    if critical:
        scope, impacted = "BROAD", max(resource_count * 3, 8)
    elif high:
        scope, impacted = "MODERATE", max(resource_count * 2, 4)
    elif rule_findings:
        scope, impacted = "NARROW", max(resource_count, 2)
    else:
        scope, impacted = "MINIMAL", max(resource_count, 1)

    desc = {
        "BROAD": f"Change affects approximately {impacted} assets across multiple zones/regions",
        "MODERATE": f"Change affects approximately {impacted} assets within a single zone",
        "NARROW": f"Change affects approximately {impacted} assets in a targeted segment",
        "MINIMAL": "Change has minimal blast radius — isolated resource modification",
    }
    return {
        "scope": scope,
        "impacted_count": impacted,
        "impacted_services": services,
        "description": desc.get(scope, "Unknown blast radius"),
    }


def normalize_ip(s: str) -> str:
    s = s.strip().lower()
    if s in ("0.0.0.0/0", "0.0.0.0", "*", "any", "internet", "all",
             "::/0", "anyipv4", "anyipv6"):
        return "0.0.0.0/0"
    return s
