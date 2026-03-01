"""
Intermediate Representation (IR) — Vendor-neutral normalized form for all infrastructure changes.
Every parser (AWS, Azure, GCP, Cisco, PAN-OS, FortiGate, Kubernetes) outputs List[NormalizedChange].
The rule engine, RAG query builder, and LLM prompts all operate against this IR — never raw text.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional


INTERNET_CIDRS = frozenset({
    "0.0.0.0/0", "::/0", "*", "any", "internet", "all",
    "0.0.0.0 0.0.0.0", "anyipv4", "anyipv6", "anywhere",
})


@dataclass
class PortRange:
    start: int   # -1 = all ports
    end: int

    @classmethod
    def any(cls) -> "PortRange":
        return cls(-1, -1)

    def is_any(self) -> bool:
        return self.start == -1 or (self.start == 0 and self.end >= 65535)

    def contains_port(self, port: int) -> bool:
        if self.is_any():
            return True
        return self.start <= port <= self.end

    @classmethod
    def from_string(cls, s: str) -> "PortRange":
        s = str(s).strip().lower()
        if s in ("-1", "0", "any", "*", "all", "all traffic", "", "none"):
            return cls(-1, -1)
        if "-" in s and not s.startswith("-"):
            try:
                lo, hi = s.split("-", 1)
                lo_i, hi_i = int(lo.strip()), int(hi.strip())
                if lo_i == 0 and hi_i >= 65535:
                    return cls(-1, -1)
                return cls(lo_i, hi_i)
            except (ValueError, AttributeError):
                return cls(-1, -1)
        try:
            p = int(s)
            return cls(p, p)
        except (ValueError, TypeError):
            return cls(-1, -1)

    def __str__(self) -> str:
        if self.is_any():
            return "ANY"
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"

    def __hash__(self):
        return hash((self.start, self.end))


# Well-known port mappings (used by all parsers)
NAMED_PORT_MAP = {
    "ssh": 22, "telnet": 23, "ftp": 21, "ftp-data": 20,
    "smtp": 25, "dns": 53, "http": 80, "https": 443,
    "rdp": 3389, "snmp": 161, "bgp": 179, "ldap": 389,
    "ldaps": 636, "mysql": 3306, "postgresql": 5432, "postgres": 5432,
    "mssql": 1433, "oracle": 1521, "mongodb": 27017, "redis": 6379,
    "memcached": 11211, "elasticsearch": 9200, "kibana": 5601,
    "kubernetes-api": 6443, "docker": 2375, "docker-tls": 2376,
    "nfs": 2049, "smb": 445, "cifs": 445, "winrm": 5985, "winrm-https": 5986,
    "www": 80, "www-http": 80, "www-https": 443,
}


def resolve_named_port(name: str) -> Optional[int]:
    return NAMED_PORT_MAP.get(name.lower())


def normalize_cidr(s: str) -> str:
    """Normalize various IP representations to CIDR notation."""
    s = s.strip()
    if s.lower() in INTERNET_CIDRS:
        return "0.0.0.0/0"
    if s.lower() in ("internet", "any-ipv4"):
        return "0.0.0.0/0"
    if s.lower() in ("any-ipv6",):
        return "::/0"
    # Add /32 if plain IP
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
        return f"{s}/32"
    return s


def wildcard_to_cidr(ip: str, wildcard: str) -> str:
    """Convert Cisco wildcard mask to CIDR (e.g. 192.168.0.0 0.0.0.255 → 192.168.0.0/24)."""
    try:
        wc_parts = [int(x) for x in wildcard.split(".")]
        mask_parts = [255 - w for w in wc_parts]
        prefix_len = sum(bin(m).count("1") for m in mask_parts)
        return f"{ip}/{prefix_len}"
    except Exception:
        return f"{ip}/32"


@dataclass
class NormalizedChange:
    """
    Vendor-neutral representation of a single infrastructure change.
    All parsers output this. All rules evaluate against this.
    """
    change_type: str = "ADD"            # ADD | REMOVE | MODIFY
    resource_type: str = "unknown"      # firewall_rule | iam_policy | dns_record | route | k8s_network_policy | k8s_rbac
    resource_name: str = ""             # "aws_security_group.web_tier"
    vendor: str = "unknown"             # aws | azure | gcp | cisco_ios | cisco_asa | paloalto | fortigate | kubernetes | onprem

    # Network fields
    direction: str = "UNKNOWN"          # INGRESS | EGRESS | BOTH | LATERAL | UNKNOWN
    source_cidrs: List[str] = field(default_factory=list)
    dest_cidrs: List[str] = field(default_factory=list)
    ports: List[PortRange] = field(default_factory=list)
    protocol: str = "ANY"               # TCP | UDP | ICMP | ANY
    action: str = "ALLOW"               # ALLOW | DENY

    # IAM / RBAC fields
    principals: List[str] = field(default_factory=list)
    iam_actions: List[str] = field(default_factory=list)
    iam_resources: List[str] = field(default_factory=list)

    # Evidence fields (for pinpointed findings)
    raw_snippet: str = ""
    line_start: int = 0
    line_end: int = 0

    # ── Computed property methods ──────────────────────────────────────────

    def is_internet_exposed(self) -> bool:
        has_open = any(normalize_cidr(c).lower() in ("0.0.0.0/0", "::/0")
                       or c.lower() in INTERNET_CIDRS
                       for c in self.source_cidrs)
        return (has_open and
                self.direction in ("INGRESS", "BOTH", "UNKNOWN") and
                self.action == "ALLOW")

    def has_wildcard_iam(self) -> bool:
        return "*" in self.iam_actions or "*" in self.iam_resources

    def exposes_port(self, *ports: int) -> bool:
        if not self.ports:
            return False
        return any(pr.contains_port(p) for p in ports for pr in self.ports)

    def to_dict(self) -> dict:
        return {
            "change_type": self.change_type,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "vendor": self.vendor,
            "direction": self.direction,
            "source_cidrs": self.source_cidrs,
            "dest_cidrs": self.dest_cidrs,
            "ports": [str(p) for p in self.ports],
            "protocol": self.protocol,
            "action": self.action,
            "iam_actions": self.iam_actions,
            "iam_resources": self.iam_resources,
            "line_start": self.line_start,
        }
