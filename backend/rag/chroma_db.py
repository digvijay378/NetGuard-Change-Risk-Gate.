"""ChromaDB client, seed data, and retrieval for the NetGuard RAG pipeline."""
import math
import re
import uuid
import hashlib
from collections import Counter
from pathlib import Path
from typing import List
import chromadb

CHROMA_PATH = Path(__file__).parent.parent / "data" / "chroma"


class SimpleEmbeddingFunction(chromadb.EmbeddingFunction):
    """Lightweight keyword-frequency embedding — no model download required."""

    def __call__(self, input: chromadb.Documents) -> chromadb.Embeddings:
        embeddings = []
        for text in input:
            words = re.findall(r'\b\w+\b', str(text).lower())
            freq = Counter(words)
            vec = [0.0] * 256
            for word, count in freq.items():
                idx = int(hashlib.md5(word.encode()).hexdigest(), 16) % 256
                vec[idx] += math.log(1 + count)
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            vec = [v / norm for v in vec]
            embeddings.append(vec)
        return embeddings


_chroma_client = None
_embedding_fn = SimpleEmbeddingFunction()


def get_client() -> chromadb.ClientAPI:
    global _chroma_client
    if _chroma_client is None:
        CHROMA_PATH.mkdir(parents=True, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    return _chroma_client


def get_or_create_collection(name: str):
    return get_client().get_or_create_collection(
        name=name,
        embedding_function=_embedding_fn,
        metadata={"hnsw:space": "cosine"}
    )


# ─── Seed Data ────────────────────────────────────────────────────────────────

SAMPLE_CVES = [
    {"id": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE", "cvss": 8.1,
     "description": "Race condition in OpenSSH sshd allows unauthenticated RCE as root on glibc Linux. Affects versions 8.5p1–9.7p1. SSH port 22 exposure critical.",
     "services": "ssh", "ports": "22"},
    {"id": "CVE-2023-38408", "title": "OpenSSH Agent Forwarding RCE", "cvss": 9.8,
     "description": "OpenSSH ssh-agent remote code execution via malicious agent forwarding. CVSS 9.8 Critical. SSH port 22 RCE via compromised agent.",
     "services": "ssh", "ports": "22"},
    {"id": "CVE-2024-3400", "title": "PAN-OS GlobalProtect RCE", "cvss": 10.0,
     "description": "Command injection in Palo Alto PAN-OS GlobalProtect. Unauthenticated RCE with root. Firewall VPN exposed to internet.",
     "services": "vpn firewall", "ports": "443"},
    {"id": "CVE-2024-21887", "title": "Ivanti Connect Secure RCE", "cvss": 9.1,
     "description": "Command injection vulnerability in Ivanti Connect Secure VPN allows authenticated RCE. VPN gateway internet exposure.",
     "services": "vpn", "ports": "443 8443"},
    {"id": "CVE-2019-0708", "title": "BlueKeep RDP RCE", "cvss": 9.8,
     "description": "Remote Desktop Protocol vulnerability enabling pre-auth RCE. RDP port 3389 exposure to internet. BlueKeep wormable vulnerability.",
     "services": "rdp", "ports": "3389"},
    {"id": "CVE-2023-27997", "title": "FortiGate SSL-VPN Heap Overflow", "cvss": 9.8,
     "description": "Heap overflow in Fortinet FortiOS SSL-VPN. Pre-auth RCE. Affected versions widely deployed. Firewall management interface exposure.",
     "services": "vpn firewall", "ports": "443 10443"},
    {"id": "CVE-2024-1708", "title": "ConnectWise ScreenConnect Path Traversal", "cvss": 8.4,
     "description": "Path traversal leading to RCE in ConnectWise ScreenConnect. Remote access software exposure on internet.",
     "services": "remote-access", "ports": "8040 8041"},
    {"id": "CVE-2023-34362", "title": "MOVEit Transfer SQL Injection", "cvss": 9.8,
     "description": "SQL injection in Progress MOVEit Transfer. Unauthenticated access to sensitive data. File transfer service exposed to internet.",
     "services": "file-transfer", "ports": "80 443"},
    {"id": "CVE-2024-23897", "title": "Jenkins CLI File Read", "cvss": 9.8,
     "description": "Arbitrary file read through Jenkins CLI allows obtaining secrets and credentials. CI/CD pipeline exposure.",
     "services": "cicd jenkins", "ports": "8080 443"},
    {"id": "CVE-2021-44228", "title": "Log4Shell JNDI Injection", "cvss": 10.0,
     "description": "JNDI injection via Log4j allows unauthenticated RCE. Java applications with Log4j exposed to internet. Zero-day.",
     "services": "java webapp", "ports": "80 443 8080"},
    {"id": "CVE-2022-22965", "title": "Spring4Shell RCE", "cvss": 9.8,
     "description": "Remote code execution in Spring Framework via data binding. Spring web application internet exposure.",
     "services": "java webapp spring", "ports": "80 443 8080"},
    {"id": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset DoS", "cvss": 7.5,
     "description": "HTTP/2 rapid reset attack causes denial of service on web servers. Amplification attack via RST_STREAM frames.",
     "services": "webserver http2", "ports": "443 80"},
    {"id": "CVE-2024-49113", "title": "Windows LDAP DoS", "cvss": 7.5,
     "description": "Denial of service vulnerability in Windows LDAP client. Active Directory LDAP exposure.",
     "services": "ldap active-directory", "ports": "389 636"},
    {"id": "CVE-2024-0519", "title": "Chrome V8 Out-of-Bounds", "cvss": 8.8,
     "description": "Out-of-bounds memory access in Chrome V8 engine. Browser-based exploitation via malicious pages.",
     "services": "browser", "ports": ""},
    {"id": "CVE-2023-23397", "title": "Outlook NTLM Hash Leak", "cvss": 9.8,
     "description": "Microsoft Outlook sends NTLM hash to attacker-controlled server via specially crafted calendar invite. No user interaction required.",
     "services": "email outlook", "ports": "445"},
]

SAMPLE_ATTACK_TECHNIQUES = [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access",
     "description": "Exploit weakness in internet-facing software. Includes VPN, web apps, remote desktop, and management interfaces. Primary vector when firewall rules expose services to 0.0.0.0/0."},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "persistence",
     "description": "Use valid credentials to gain access and maintain persistence. Cloud accounts (T1078.004) leveraged when IAM wildcard permissions granted."},
    {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactic": "privilege-escalation",
     "description": "Attacker with any cloud foothold escalates to full admin using wildcard IAM policies or Owner/Contributor role assignments."},
    {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control",
     "description": "C2 over HTTP/HTTPS. Modified NAT rules or unrestricted egress enables covert exfiltration channels."},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration",
     "description": "Exfiltrate data over existing C2 channel. Unrestricted security group egress enables data theft over any protocol."},
    {"id": "T1565.002", "name": "Data Manipulation: Transmitted Data", "tactic": "impact",
     "description": "DNS zone modifications enable man-in-the-middle attacks for credential harvesting and data manipulation."},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "persistence",
     "description": "Manipulate credentials to maintain or elevate access. RBAC Owner/Contributor assignments persist attacker access."},
    {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactic": "defense-evasion",
     "description": "Attacker with admin IAM access can disable CloudTrail, GuardDuty, and other monitoring. Logging disabled configurations."},
    {"id": "T1133", "name": "External Remote Services", "tactic": "initial-access",
     "description": "Leverage external remote services like VPN and RDP. Security group rules exposing port 22/3389 directly enable this technique."},
    {"id": "T1110", "name": "Brute Force", "tactic": "credential-access",
     "description": "Brute force authentication to gain access. SSH/RDP ports open to internet enable automated credential stuffing."},
    {"id": "T1021.001", "name": "Remote Services: RDP", "tactic": "lateral-movement",
     "description": "Use valid RDP sessions for lateral movement. RDP port 3389 exposed to internet or unrestricted internal ACLs."},
    {"id": "T1550.001", "name": "Use Alternate Auth: App Access Token", "tactic": "defense-evasion",
     "description": "Service account keys or long-lived tokens used to bypass MFA. IAM access key creation enables persistent access."},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration",
     "description": "Exfiltrate data via DNS, ICMP, or other protocols. Unrestricted egress and DNS zone changes enable alternative exfil channels."},
    {"id": "T1136", "name": "Create Account", "tactic": "persistence",
     "description": "Create new cloud or local accounts for persistent access. IAM role/user creation with broad permissions."},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation",
     "description": "Exploit software vulnerability to gain higher privileges. Exposed management interfaces and wildcard IAM policies provide escalation paths."},
]

SAMPLE_POLICY_CONTROLS = [
    {"id": "NIST-CA-7", "framework": "NIST SP 800-53", "title": "Continuous Monitoring",
     "description": "Every change assessed at PR/ticket time. RAG keeps threat intelligence current.",
     "remediation": "Implement automated change risk assessment in CI/CD pipeline. Review assessment results before approving changes."},
    {"id": "NIST-AC-3", "framework": "NIST SP 800-53", "title": "Access Enforcement",
     "description": "Flag unrestricted ingress rules; require approval for public exposure changes.",
     "remediation": "Restrict ingress to known CIDR ranges. Use bastion hosts or VPN for administrative access. Avoid 0.0.0.0/0 sources."},
    {"id": "NIST-AC-17", "framework": "NIST SP 800-53", "title": "Remote Access",
     "description": "Monitor and control remote access sessions. SSH/RDP should be via VPN or bastion.",
     "remediation": "Route all SSH/RDP through bastion host. Implement MFA for all remote access. Restrict source IPs."},
    {"id": "CIS-4", "framework": "CIS CSC v8", "title": "Secure Configuration of Enterprise Assets",
     "description": "Validate that changes conform to secure baseline configurations via policy rules.",
     "remediation": "Follow CIS Benchmarks for cloud and OS hardening. Enforce configurations via IaC templates."},
    {"id": "CIS-12", "framework": "CIS CSC v8", "title": "Network Infrastructure Management",
     "description": "Network changes should follow least-privilege and defense-in-depth principles.",
     "remediation": "Segment networks by trust zones. Apply micro-segmentation. Document all firewall rule changes with business justification."},
    {"id": "CIS-13", "framework": "CIS CSC v8", "title": "Network Monitoring and Defense",
     "description": "ATT&CK mapping shows network-level attack paths enabled by proposed changes.",
     "remediation": "Deploy IDS/IPS. Enable VPC Flow Logs / NSG Flow Logs. Set up CloudWatch/Azure Monitor alerts for suspicious traffic."},
    {"id": "SOC2-CC6.6", "framework": "SOC 2 Type II", "title": "Logical and Physical Access Controls",
     "description": "Every IAM/RBAC change triggers assessment with full audit trail of approval decisions.",
     "remediation": "Implement role-based access with least privilege. Review privileged access quarterly. Enforce MFA for all admin roles."},
    {"id": "ISO-A.8.9", "framework": "ISO 27001:2022", "title": "Configuration Management",
     "description": "Change history RAG collection provides evidence of configuration management practices.",
     "remediation": "Maintain IaC version history. Document change justifications. Conduct regular security reviews of critical configurations."},
    {"id": "NIST-SC-7", "framework": "NIST SP 800-53", "title": "Boundary Protection",
     "description": "Monitor and control communications at external network boundaries.",
     "remediation": "Implement network boundary controls. Use WAF for internet-facing services. Deploy NGFW with deep packet inspection."},
    {"id": "NIST-AU-9", "framework": "NIST SP 800-53", "title": "Protection of Audit Information",
     "description": "Protect audit trail from unauthorized access, modification, or deletion.",
     "remediation": "Store logs in separate account/subscription. Enable log integrity validation (CloudTrail log validation). Set retention policies."},
]


def seed_all_collections():
    """Seed all 4 ChromaDB collections with sample data."""
    _seed_cves()
    _seed_attack_techniques()
    _seed_policy_controls()
    # Change history is populated in real-time as assessments are created
    _ensure_change_history_collection()


def _seed_cves():
    col = get_or_create_collection("cve_knowledge")
    if col.count() >= len(SAMPLE_CVES):
        return
    col.upsert(
        ids=[c["id"] for c in SAMPLE_CVES],
        documents=[f"{c['id']}: {c['title']}. CVSS: {c['cvss']}. {c['description']}" for c in SAMPLE_CVES],
        metadatas=[{"cve_id": c["id"], "cvss": c["cvss"], "services": c["services"],
                    "ports": c["ports"], "source": "nvd"} for c in SAMPLE_CVES],
    )


def _seed_attack_techniques():
    col = get_or_create_collection("attack_techniques")
    if col.count() >= len(SAMPLE_ATTACK_TECHNIQUES):
        return
    col.upsert(
        ids=[t["id"] for t in SAMPLE_ATTACK_TECHNIQUES],
        documents=[f"{t['id']}: {t['name']}. Tactic: {t['tactic']}. {t['description']}" for t in SAMPLE_ATTACK_TECHNIQUES],
        metadatas=[{"technique_id": t["id"], "tactic": t["tactic"]} for t in SAMPLE_ATTACK_TECHNIQUES],
    )


def _seed_policy_controls():
    col = get_or_create_collection("policy_controls")
    if col.count() >= len(SAMPLE_POLICY_CONTROLS):
        return
    col.upsert(
        ids=[c["id"] for c in SAMPLE_POLICY_CONTROLS],
        documents=[f"{c['id']}: {c['title']} ({c['framework']}). {c['description']} Remediation: {c['remediation']}" for c in SAMPLE_POLICY_CONTROLS],
        metadatas=[{"control_id": c["id"], "framework": c["framework"]} for c in SAMPLE_POLICY_CONTROLS],
    )


def _ensure_change_history_collection():
    get_or_create_collection("change_history")


def add_to_change_history(assessment_id: str, summary: str, outcome: str, risk_level: str):
    """Add a completed assessment to the change history collection."""
    col = get_or_create_collection("change_history")
    col.upsert(
        ids=[assessment_id],
        documents=[f"Assessment {assessment_id}: {summary}. Outcome: {outcome}. Risk: {risk_level}"],
        metadatas=[{"assessment_id": assessment_id, "outcome": outcome, "risk_level": risk_level}],
    )


# ─── Retrieval ────────────────────────────────────────────────────────────────

def query_cves(query: str, top_k: int = 5) -> list:
    try:
        col = get_or_create_collection("cve_knowledge")
        results = col.query(query_texts=[query], n_results=min(top_k, col.count() or 1))
        return _format_cve_results(results)
    except Exception:
        return []


def query_attack_techniques(query: str, top_k: int = 5) -> list:
    try:
        col = get_or_create_collection("attack_techniques")
        results = col.query(query_texts=[query], n_results=min(top_k, col.count() or 1))
        return _format_attack_results(results)
    except Exception:
        return []


def query_policy_controls(query: str, top_k: int = 5) -> list:
    try:
        col = get_or_create_collection("policy_controls")
        results = col.query(query_texts=[query], n_results=min(top_k, col.count() or 1))
        return _format_policy_results(results)
    except Exception:
        return []


def query_change_history(query: str, top_k: int = 3) -> list:
    try:
        col = get_or_create_collection("change_history")
        if col.count() == 0:
            return []
        results = col.query(query_texts=[query], n_results=min(top_k, col.count()))
        return _format_history_results(results)
    except Exception:
        return []


def get_collection_stats() -> dict:
    """Return stats for all 4 collections (for /health/rag endpoint)."""
    stats = {}
    for name in ["cve_knowledge", "attack_techniques", "policy_controls", "change_history"]:
        try:
            col = get_or_create_collection(name)
            stats[name] = {"count": col.count(), "status": "healthy"}
        except Exception as e:
            stats[name] = {"count": 0, "status": "error", "error": str(e)}
    return stats


# ─── Formatters ───────────────────────────────────────────────────────────────

def _format_cve_results(results: dict) -> list:
    out = []
    if not results or not results.get("ids"):
        return out
    for i, doc_id in enumerate(results["ids"][0]):
        meta = results["metadatas"][0][i] if results.get("metadatas") else {}
        doc = results["documents"][0][i] if results.get("documents") else ""
        # Parse CVE ID and title from document
        parts = doc.split(": ", 1)
        title_rest = parts[1].split(". CVSS: ") if len(parts) > 1 else ["Unknown", "0"]
        out.append({
            "cve_id": doc_id,
            "title": title_rest[0] if title_rest else "Unknown",
            "cvss": float(meta.get("cvss", 0)),
            "description": doc,
            "services": meta.get("services", ""),
            "source": meta.get("source", "nvd"),
        })
    return out


def _format_attack_results(results: dict) -> list:
    out = []
    if not results or not results.get("ids"):
        return out
    for i, doc_id in enumerate(results["ids"][0]):
        meta = results["metadatas"][0][i] if results.get("metadatas") else {}
        doc = results["documents"][0][i] if results.get("documents") else ""
        parts = doc.split(": ", 1)
        name_rest = parts[1].split(". Tactic: ") if len(parts) > 1 else ["Unknown technique"]
        out.append({
            "technique_id": doc_id,
            "technique_name": name_rest[0] if name_rest else "Unknown",
            "tactic": meta.get("tactic", "unknown"),
            "relevance": doc[:200],
            "description": doc,
        })
    return out


def _format_policy_results(results: dict) -> list:
    out = []
    if not results or not results.get("ids"):
        return out
    for i, doc_id in enumerate(results["ids"][0]):
        meta = results["metadatas"][0][i] if results.get("metadatas") else {}
        doc = results["documents"][0][i] if results.get("documents") else ""
        out.append({
            "control_id": doc_id,
            "framework": meta.get("framework", "Unknown"),
            "title": doc.split(": ")[1].split(" (")[0] if ": " in doc else "Unknown",
            "description": doc[:300],
            "remediation": doc.split("Remediation: ")[-1] if "Remediation: " in doc else "",
        })
    return out


def _format_history_results(results: dict) -> list:
    out = []
    if not results or not results.get("ids"):
        return out
    for i, doc_id in enumerate(results["ids"][0]):
        meta = results["metadatas"][0][i] if results.get("metadatas") else {}
        doc = results["documents"][0][i] if results.get("documents") else ""
        out.append({
            "assessment_id": doc_id,
            "summary": doc[:200],
            "outcome": meta.get("outcome", "unknown"),
            "risk_level": meta.get("risk_level", "UNKNOWN"),
            "date": "",
        })
    return out
