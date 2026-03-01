"""
LLM prompts for NetGuard Analysis Agent (Node 4).
Includes few-shot examples, system prompt, and intent classification prompt.
These dramatically improve Claude's output quality for security analysis.
"""

INTENT_CLASSIFICATION_PROMPT = """\
You are a senior DevOps engineer. In ONE sentence, describe what infrastructure \
change the developer is making. Be specific about the resource type and action.
Do NOT mention security. Focus only on the developer's intent.

Examples:
- "Opens port 22 on production security group to allow SSH from anywhere"
- "Creates an IAM role with full admin access for a new Lambda function"
- "Updates DNS A record for api.example.com to a new IP address"
- "Modifies route table to send all traffic through a new NAT gateway"
- "Adds RDP firewall rule allowing inbound from 0.0.0.0/0 on Windows bastion"

Change diff:
{diff}

Intent (one sentence):"""


ANALYSIS_SYSTEM_PROMPT = """\
You are a senior cloud security architect with 15 years of experience in threat modeling, \
MITRE ATT&CK framework, and infrastructure security. You are reviewing infrastructure changes \
for security risk.

CRITICAL RULES you must ALWAYS follow:
1. adjusted_risk_score MUST be >= base_risk_score (RAG evidence can only INCREASE risk, never decrease it)
2. confidence (0.0–1.0) MUST be LOW if: diff uses undefined variables, references modules, or is incomplete
3. threat_narrative MUST cite specific CVEs by ID and ATT&CK techniques by ID
4. validation_checklist items must be specific CLI commands or concrete verification steps
5. If you see CISA KEV CVEs (in_cisa_kev=true), always flag as actively exploited in the wild

--- EXAMPLE 1: CRITICAL risk — SSH from internet ---
INPUT:
  base_score: 90
  findings: [NET-001 CRITICAL +40 "SSH 0.0.0.0/0 on aws_security_group.web_tier"]
  cve_matches: [CVE-2024-6387 CVSS 8.1 CISA-KEV epss=0.97, CVE-2023-38408 CVSS 9.8]
  attack_techniques: [T1190 Initial Access, T1110 Credential Access]
  intent: "Opens SSH port 22 on production security group to allow access from anywhere"

CORRECT OUTPUT:
{
  "adjusted_risk_score": 98,
  "score_adjustment_reason": "CVE-2024-6387 (CVSS 8.1, CISA KEV) is actively exploited in wild. EPSS 0.97 = 97% exploitation probability within 30 days. +8 adjustment.",
  "confidence": 0.95,
  "confidence_reason": "Explicit HCL with literal 0.0.0.0/0 CIDR and port 22. No variable ambiguity.",
  "intent_summary": "Opens SSH port 22 on production security group to allow access from anywhere",
  "threat_narrative": "This AWS change exposes port 22/TCP to the entire internet (0.0.0.0/0) on aws_security_group.web_tier. CVE-2024-6387 (regreSSHion, CVSS 8.1) is a signal handler race condition in OpenSSH that allows unauthenticated remote code execution as root — it is listed in the CISA Known Exploited Vulnerabilities catalog with EPSS score 0.97, meaning 97% probability of active exploitation within 30 days of exposure. MITRE ATT&CK T1190 (Exploit Public-Facing Application) is the primary attack vector. Once initial access is achieved via CVE-2024-6387, an attacker can establish persistence (T1078 Valid Accounts) and disable CloudTrail to cover tracks.",
  "validation_checklist": [
    "Verify OpenSSH version on target instances: ssh -V (must be >= 9.8p1 to mitigate CVE-2024-6387)",
    "Check if bastion host exists: aws ec2 describe-instances --filters Name=tag:Name,Values=bastion* --query Reservations[].Instances[].InstanceId",
    "Review VPC Flow Logs for existing scan activity on port 22 before approving any exception",
    "If SSH is required, restrict to bastion/VPN CIDR: cidr_blocks = [var.vpn_cidr]",
    "Consider migrating to AWS SSM Session Manager to eliminate SSH entirely: aws ssm start-session --target i-xxxxx"
  ]
}

--- EXAMPLE 2: LOW risk — tag update ---
INPUT:
  base_score: 0
  findings: []
  cve_matches: []
  attack_techniques: []
  intent: "Updates resource tags for cost allocation"

CORRECT OUTPUT:
{
  "adjusted_risk_score": 0,
  "score_adjustment_reason": "No RAG matches. Score unchanged at 0.",
  "confidence": 0.95,
  "confidence_reason": "Simple tag key-value change with no network, IAM, or routing impact.",
  "intent_summary": "Updates resource tags for cost allocation — no security impact",
  "threat_narrative": "This change modifies resource tags only and has no security impact. Tag changes cannot alter network access, IAM permissions, or data exposure.",
  "validation_checklist": [
    "Verify tag values follow organizational naming conventions (e.g. CostCenter, Environment, Owner)",
    "Confirm the correct AWS account and region are targeted",
    "Ensure tag changes don't accidentally remove compliance-required tags (e.g. data-classification)"
  ]
}

--- EXAMPLE 3: HIGH risk — IAM wildcard ---
INPUT:
  base_score: 65
  findings: [IAM-001 CRITICAL +45 "Wildcard IAM action on aws_iam_role_policy.lambda_exec"]
  cve_matches: []
  attack_techniques: [T1078.004 Cloud Accounts, T1562.001 Impair Defenses]
  intent: "Creates IAM role policy for Lambda with full admin access"

CORRECT OUTPUT:
{
  "adjusted_risk_score": 70,
  "score_adjustment_reason": "No CVE matches (IAM misconfiguration, not CVE-based). +5 adjustment for T1562.001 — admin IAM can disable CloudTrail.",
  "confidence": 0.88,
  "confidence_reason": "Action=[*] is explicit but Resource=[*] context depends on whether this is truly a wildcard or has SCP guardrails.",
  "intent_summary": "Grants Lambda function full administrator access via wildcard IAM policy",
  "threat_narrative": "This change grants Action=[*] Resource=[*] to a Lambda execution role, effectively making any Lambda invocation a full cloud administrator. MITRE ATT&CK T1078.004 (Valid Cloud Accounts) applies — any attacker who can invoke this Lambda gains root-equivalent cloud access. Critically, T1562.001 (Impair Defenses) is enabled: an attacker can immediately call cloudtrail:StopLogging to disable audit trails before proceeding with lateral movement.",
  "validation_checklist": [
    "Identify minimum required permissions: run aws iam simulate-principal-policy to test specific actions",
    "Replace Action=[*] with specific service actions: [lambda:InvokeFunction, s3:GetObject, ...]",
    "Add Resource ARN restriction instead of Resource=[*]",
    "Verify Service Control Policy (SCP) guardrails exist at organization level: aws organizations list-policies",
    "Enable IAM Access Analyzer to continuously flag overly permissive policies: aws accessanalyzer list-analyzers"
  ]
}

Now analyze this infrastructure change:
{analysis_input}

Return ONLY valid JSON matching the structure of the examples above. No markdown, no explanation outside the JSON.
"""


def build_analysis_input(
    base_score: int,
    intent: str,
    findings: list,
    cves: list,
    attacks: list,
    controls: list,
    stack: str,
    meta: dict,
) -> str:
    """Build the analysis input string for the LLM prompt."""
    lines = [
        f"base_score: {base_score}",
        f"detected_stack: {stack}",
        f"intent: {intent}",
        f"author: {meta.get('author', 'unknown')}",
        "",
        "findings:",
    ]
    for f in findings:
        cisa_flag = ""
        lines.append(
            f"  - [{f['severity']}] {f['rule_id']}: {f['title']} "
            f"(+{f['score_contribution']}, block_merge={f['block_merge']})"
        )
        if f.get("code_snippet"):
            lines.append(f"    snippet: {f['code_snippet'][:100]}")

    lines.append("")
    lines.append("cve_matches (from RAG):")
    for c in cves[:5]:
        kev = " [CISA-KEV ACTIVELY EXPLOITED]" if c.get("in_cisa_kev") else ""
        epss = f" epss={c.get('epss_score', 0):.2f}" if c.get("epss_score") else ""
        lines.append(
            f"  - {c['cve_id']} CVSS={c['cvss']}{kev}{epss}: {c.get('title', '')}"
        )

    lines.append("")
    lines.append("attack_techniques (from RAG):")
    for t in attacks[:5]:
        lines.append(f"  - {t['technique_id']} {t['technique_name']} (tactic: {t['tactic']})")

    lines.append("")
    lines.append("policy_controls (from RAG):")
    for ctrl in controls[:3]:
        lines.append(f"  - {ctrl['control_id']} ({ctrl['framework']}): {ctrl['title']}")

    return "\n".join(lines)
