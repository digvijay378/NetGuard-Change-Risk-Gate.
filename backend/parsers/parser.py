"""
Multi-vendor infrastructure parsers — all output List[NormalizedChange] IR.
Supports: AWS (HCL/CFn), Azure (Bicep/ARM/azurerm), GCP (Terraform/gcloud),
          Cisco IOS/NX-OS, Palo Alto PAN-OS, FortiGate FortiOS, Kubernetes YAML.
"""
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

import yaml as pyyaml

from parsers.ir import (
    NormalizedChange, PortRange, normalize_cidr, wildcard_to_cidr,
    resolve_named_port, NAMED_PORT_MAP,
)


# ─── Stack Detection ──────────────────────────────────────────────────────────

def detect_stack(raw_diff: str, change_source: str = "") -> str:
    diff_lower = raw_diff.lower()

    scores = {"aws": 0, "azure": 0, "gcp": 0, "cisco_ios": 0,
              "paloalto": 0, "fortigate": 0, "kubernetes": 0, "onprem": 0}

    aws_pats = [r'aws_', r'AWSTemplateFormatVersion', r'arn:aws:', r'ec2', r'vpc',
                r'ami-', r'cloudformation', r'aws_security_group', r'aws_iam']
    azure_pats = [r'azurerm_', r'Microsoft\.', r'subscription_id', r'bicep',
                  r'arm_template', r'azure', r'azurerm']
    gcp_pats = [r'google_compute', r'google_', r'gcp', r'gcloud', r'project_id',
                r'googleapis', r'google-cloud']
    cisco_pats = [r'ip access-list', r'access-list \d+', r'ip access-group',
                  r'interface gigabit', r'interface fastethernet', r'nx-os', r'nxos']
    paloalto_pats = [r'pan-os', r'panos', r'paloalto', r'<entry name=', r'<security>',
                     r'<rulebase>', r'<from><member>', r'panorama']
    fortigate_pats = [r'config firewall policy', r'config firewall vip',
                      r'set srcaddr', r'set dstaddr', r'set srcintf', r'fortigate', r'fortios']
    k8s_pats = [r'kind: networkpolicy', r'kind: clusterrole', r'kind: deployment',
                r'apiversion: networking', r'apiversion: rbac', r'kubectl',
                r'kubernetes.io', r'podselector']
    onprem_pats = [r'iptables', r'permit any', r'deny any', r'pfSense', r'ufw',
                   r'firewall-cmd', r'nftables']

    for p in aws_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["aws"] += 1
    for p in azure_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["azure"] += 1
    for p in gcp_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["gcp"] += 1
    for p in cisco_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["cisco_ios"] += 1
    for p in paloalto_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["paloalto"] += 1
    for p in fortigate_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["fortigate"] += 1
    for p in k8s_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["kubernetes"] += 1
    for p in onprem_pats:
        if re.search(p, diff_lower, re.IGNORECASE):
            scores["onprem"] += 1

    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def parse_to_ir(raw_diff: str, detected_stack: str) -> Tuple[List[NormalizedChange], dict]:
    """
    Parse raw diff to IR + legacy dict.
    Returns (normalized_changes, legacy_dict) for backward compat with blast radius.
    """
    parsers = {
        "aws": AWSParser,
        "azure": AzureParser,
        "gcp": GCPParser,
        "cisco_ios": CiscoIOSParser,
        "paloalto": PaloAltoParser,
        "fortigate": FortiGateParser,
        "kubernetes": KubernetesParser,
        "onprem": CiscoIOSParser,   # Fallback for generic ACL syntax
        "unknown": AWSParser,
    }
    parser_cls = parsers.get(detected_stack, AWSParser)
    changes = parser_cls().parse(raw_diff, detected_stack)
    legacy = _build_legacy_dict(changes, detected_stack, raw_diff)
    return changes, legacy


def _build_legacy_dict(changes: List[NormalizedChange], stack: str, raw_diff: str) -> dict:
    """Generate backward-compatible dict for blast radius calculation."""
    resources = [c.resource_name for c in changes if c.resource_name]
    services = list({c.resource_type for c in changes})
    ports_modified = list({str(p) for c in changes for p in c.ports if not p.is_any()})
    return {
        "stack": stack,
        "resources": resources,
        "has_open_cidr": any(c.is_internet_exposed() for c in changes),
        "ports_modified": ports_modified,
        "has_wildcard_iam": any(c.has_wildcard_iam() for c in changes),
        "has_admin_role": any("admin" in " ".join(c.iam_actions).lower() or
                              "admin" in " ".join(c.iam_resources).lower()
                              for c in changes),
        "resource_count": len(resources),
        "services_detected": services,
        "diff_lines": len(raw_diff.splitlines()),
        "diff_chars": len(raw_diff),
    }


# ─── Variable Resolver ───────────────────────────────────────────────────────

def _resolve_variables(diff: str) -> dict:
    """Extract variable/local defaults from HCL for basic variable resolution."""
    var_map = {}
    # Match: variable "name" { default = "value" }
    for m in re.finditer(
        r'(?:variable|locals?)\s+"?(\w+)"?\s*\{[^}]*?(?:default\s*=\s*"([^"]+)"|(\w+)\s*=\s*"([^"]+)")',
        diff, re.DOTALL
    ):
        name = m.group(1)
        value = m.group(2) or m.group(4)
        if value:
            var_map[f"var.{name}"] = value
            var_map[f"local.{name}"] = value
            var_map[name] = value
    return var_map


def _substitute_vars(text: str, var_map: dict) -> str:
    for k, v in var_map.items():
        text = text.replace(f"${{{k}}}", v)
        text = text.replace(k, v)
    return text


def _extract_added_lines(diff: str) -> str:
    """Extract only added lines (starting with +) for analysis."""
    lines = []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
        elif not line.startswith("-") and not line.startswith("diff ") and not line.startswith("@@"):
            lines.append(line)
    return "\n".join(lines)


# ─── AWS Parser ───────────────────────────────────────────────────────────────

class AWSParser:
    def parse(self, raw_diff: str, vendor: str = "aws") -> List[NormalizedChange]:
        var_map = _resolve_variables(raw_diff)
        diff = _substitute_vars(raw_diff, var_map)
        lines = diff.splitlines()
        changes = []

        # Find resource blocks and extract changes
        resource_pattern = re.compile(
            r'resource\s+"(aws_[\w]+)"\s+"([\w-]+)"\s*\{(.*?)(?=\nresource|\Z)',
            re.DOTALL
        )
        # Also handle CloudFormation
        cfn_pattern = re.compile(r'Type:\s+"?(AWS::\w+::\w+)"?')

        for m in resource_pattern.finditer(diff):
            resource_type = m.group(1)
            resource_name = m.group(2)
            block = m.group(3)
            line_num = diff[:m.start()].count("\n")
            full_name = f"{resource_type}.{resource_name}"

            change = self._parse_resource_block(resource_type, full_name, block, line_num, vendor)
            if change:
                changes.append(change)

        # IAM inline policies - match both JSON ("Statement": [...]) and HCL (Statement = [...])
        for m in re.finditer(
            r'(?:"Statement"|Statement)\s*[=:]\s*\[(.*?)\]', diff, re.DOTALL | re.IGNORECASE
        ):
            stmts = m.group(1)
            changes.extend(self._parse_iam_statements(stmts, diff[:m.start()].count("\n"), vendor))

        # Fallback: raw CIDR detection on full diff
        if not changes:
            changes.extend(self._fallback_parse(diff, vendor))

        return changes

    def _parse_resource_block(self, res_type: str, full_name: str, block: str,
                               line_num: int, vendor: str) -> Optional[NormalizedChange]:
        # Security group rules
        if res_type in ("aws_security_group", "aws_security_group_rule",
                        "aws_security_group_ingress", "aws_security_group_egress"):
            return self._parse_sg_block(res_type, full_name, block, line_num, vendor)

        # IAM
        if res_type in ("aws_iam_policy", "aws_iam_role_policy",
                        "aws_iam_user_policy", "aws_iam_group_policy"):
            return self._parse_iam_block(full_name, block, line_num, vendor)

        # IAM role attachment
        if res_type in ("aws_iam_role_policy_attachment",):
            policy_arn = re.search(r'policy_arn\s*=\s*"([^"]+)"', block)
            if policy_arn and "AdministratorAccess" in policy_arn.group(1):
                return NormalizedChange(
                    change_type="ADD", resource_type="iam_attachment",
                    resource_name=full_name, vendor=vendor,
                    direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="ALLOW",
                    iam_actions=["*"], iam_resources=["*"],
                    raw_snippet=block[:200], line_start=line_num,
                )

        # NAT gateway
        if res_type == "aws_nat_gateway":
            return NormalizedChange(
                change_type="ADD", resource_type="nat_gateway",
                resource_name=full_name, vendor=vendor,
                direction="EGRESS", source_cidrs=["10.0.0.0/8"], dest_cidrs=["0.0.0.0/0"],
                ports=[PortRange.any()], protocol="ANY", action="ALLOW",
                raw_snippet=block[:200], line_start=line_num,
            )

        # Route table
        if res_type in ("aws_route", "aws_route_table"):
            return NormalizedChange(
                change_type="ADD", resource_type="route",
                resource_name=full_name, vendor=vendor,
                direction="EGRESS", source_cidrs=[], dest_cidrs=["0.0.0.0/0"],
                ports=[PortRange.any()], protocol="ANY", action="ALLOW",
                raw_snippet=block[:200], line_start=line_num,
            )

        # DNS zone
        if res_type in ("aws_route53_zone", "aws_route53_record"):
            return NormalizedChange(
                change_type="ADD", resource_type="dns_record",
                resource_name=full_name, vendor=vendor,
                direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                ports=[], protocol="ANY", action="ALLOW",
                raw_snippet=block[:200], line_start=line_num,
            )

        # Logging disabled
        if res_type in ("aws_cloudtrail",):
            is_disabled = bool(re.search(r'enable_logging\s*=\s*false', block, re.IGNORECASE))
            if is_disabled:
                return NormalizedChange(
                    change_type="MODIFY", resource_type="logging_config",
                    resource_name=full_name, vendor=vendor,
                    direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="DENY",  # DENY = disable
                    raw_snippet=block[:200], line_start=line_num,
                )
        return None

    def _parse_sg_block(self, res_type: str, full_name: str, block: str,
                         line_num: int, vendor: str) -> Optional[NormalizedChange]:
        # Extract CIDRs
        cidr_match = re.findall(r'(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[([^\]]+)\]', block)
        cidrs = []
        for cm in cidr_match:
            cidrs.extend([c.strip().strip('"') for c in cm.split(",") if c.strip().strip('"')])
        if not cidrs:
            # No CIDR = probably cross-SG rule, not a risk
            return None

        # Extract ports
        from_port = re.search(r'from_port\s*=\s*"?(-?\d+)"?', block)
        to_port = re.search(r'to_port\s*=\s*"?(-?\d+)"?', block)
        ports = []
        if from_port and to_port:
            fp, tp = int(from_port.group(1)), int(to_port.group(1))
            if fp == -1 or tp == -1:
                ports = [PortRange(-1, -1)]
            else:
                ports = [PortRange(fp, tp)]
        else:
            ports = [PortRange.any()]

        # Direction
        direction_match = re.search(r'type\s*=\s*"(ingress|egress)"', block, re.IGNORECASE)
        if direction_match:
            direction = "INGRESS" if direction_match.group(1).lower() == "ingress" else "EGRESS"
        elif res_type == "aws_security_group_ingress":
            direction = "INGRESS"
        elif res_type == "aws_security_group_egress":
            direction = "EGRESS"
        else:
            direction = "INGRESS"  # Default for SG rules

        # Change type
        change_type = "ADD" if any(l.strip().startswith("+") for l in block.splitlines()
                                    if l.strip()) else "MODIFY"

        return NormalizedChange(
            change_type=change_type, resource_type="firewall_rule",
            resource_name=full_name, vendor=vendor,
            direction=direction, source_cidrs=cidrs, dest_cidrs=["0.0.0.0/0"],
            ports=ports, protocol="TCP", action="ALLOW",
            raw_snippet=block[:300], line_start=line_num, line_end=line_num + block.count("\n"),
        )

    def _parse_iam_block(self, full_name: str, block: str,
                          line_num: int, vendor: str) -> Optional[NormalizedChange]:
        # Match both JSON format ("Action": ...) and HCL format (Action = ...)
        actions = re.findall(r'(?:"Action"|Action)\s*[=:]\s*(?:"([^"]+)"|\[([^\]]+)\])', block, re.IGNORECASE)
        resources = re.findall(r'(?:"Resource"|Resource)\s*[=:]\s*(?:"([^"]+)"|\[([^\]]+)\])', block, re.IGNORECASE)

        action_list = []
        for a, al in actions:
            action_list.extend(([a] if a else [x.strip().strip('"')
                                               for x in al.split(",") if x.strip()]))
        resource_list = []
        for r, rl in resources:
            resource_list.extend(([r] if r else [x.strip().strip('"')
                                                  for x in rl.split(",") if x.strip()]))

        if not action_list:
            return None
        return NormalizedChange(
            change_type="ADD", resource_type="iam_policy",
            resource_name=full_name, vendor=vendor,
            direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
            ports=[], protocol="ANY", action="ALLOW",
            iam_actions=action_list, iam_resources=resource_list or ["*"],
            raw_snippet=block[:300], line_start=line_num,
        )

    def _parse_iam_statements(self, stmts: str, line_num: int, vendor: str) -> List[NormalizedChange]:
        changes = []
        for m in re.finditer(r'\{([^{}]+)\}', stmts):
            stmt = m.group(1)
            action_m = re.search(r'"Action"\s*:\s*"([^"]+)"', stmt)
            if action_m and action_m.group(1) == "*":
                changes.append(NormalizedChange(
                    change_type="ADD", resource_type="iam_policy",
                    resource_name="inline_iam_policy", vendor=vendor,
                    direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="ALLOW",
                    iam_actions=["*"], iam_resources=["*"],
                    raw_snippet=stmt[:200], line_start=line_num,
                ))
        return changes

    def _fallback_parse(self, diff: str, vendor: str) -> List[NormalizedChange]:
        """Last resort: detect CIDRs and ports anywhere in diff."""
        changes = []
        if re.search(r'0\.0\.0\.0/0|::/0', diff):
            ports = []
            for port_kw in ["22", "3389", "80", "443", "3306", "5432", "27017"]:
                if port_kw in diff:
                    ports.append(PortRange.from_string(port_kw))
            if not ports:
                ports = [PortRange.any()]
            changes.append(NormalizedChange(
                change_type="ADD", resource_type="firewall_rule",
                resource_name="unknown_resource", vendor=vendor,
                direction="INGRESS", source_cidrs=["0.0.0.0/0"], dest_cidrs=["0.0.0.0/0"],
                ports=ports, protocol="TCP", action="ALLOW",
                raw_snippet=diff[:300], line_start=0,
            ))
        return changes


# ─── Azure Parser ─────────────────────────────────────────────────────────────

class AzureParser:
    def parse(self, raw_diff: str, vendor: str = "azure") -> List[NormalizedChange]:
        var_map = _resolve_variables(raw_diff)
        diff = _substitute_vars(raw_diff, var_map)
        changes = []

        # azurerm Terraform resources
        for m in re.finditer(
            r'resource\s+"(azurerm_[\w]+)"\s+"([\w-]+)"\s*\{(.*?)(?=\nresource|\Z)',
            diff, re.DOTALL
        ):
            res_type, res_name, block = m.group(1), m.group(2), m.group(3)
            line_num = diff[:m.start()].count("\n")
            full_name = f"{res_type}.{res_name}"

            change = self._parse_azure_resource(res_type, full_name, block, line_num, vendor)
            if change:
                changes.append(change)

        # NSG security rules
        for m in re.finditer(
            r'security_rule\s*\{(.*?)\}',
            diff, re.DOTALL
        ):
            block = m.group(1)
            line_num = diff[:m.start()].count("\n")
            change = self._parse_nsg_rule(block, "azurerm_nsg_inline", line_num, vendor)
            if change:
                changes.append(change)

        if not changes:
            changes.extend(AWSParser()._fallback_parse(diff, vendor))
        return changes

    def _parse_azure_resource(self, res_type: str, full_name: str,
                               block: str, line_num: int, vendor: str) -> Optional[NormalizedChange]:
        if res_type in ("azurerm_network_security_rule", "azurerm_network_security_group"):
            return self._parse_nsg_rule(block, full_name, line_num, vendor)

        if res_type == "azurerm_role_assignment":
            role_m = re.search(r'role_definition_name\s*=\s*"([^"]+)"', block)
            if role_m:
                role = role_m.group(1)
                return NormalizedChange(
                    change_type="ADD", resource_type="iam_rbac",
                    resource_name=full_name, vendor=vendor,
                    direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="ALLOW",
                    iam_actions=[role], iam_resources=["*"],
                    raw_snippet=block[:200], line_start=line_num,
                )

        if "dns" in res_type:
            return NormalizedChange(
                change_type="ADD", resource_type="dns_record",
                resource_name=full_name, vendor=vendor,
                direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                ports=[], protocol="ANY", action="ALLOW",
                raw_snippet=block[:200], line_start=line_num,
            )

        if "nat" in res_type or "route" in res_type:
            return NormalizedChange(
                change_type="ADD", resource_type="route",
                resource_name=full_name, vendor=vendor,
                direction="EGRESS", source_cidrs=["0.0.0.0/0"], dest_cidrs=["0.0.0.0/0"],
                ports=[PortRange.any()], protocol="ANY", action="ALLOW",
                raw_snippet=block[:200], line_start=line_num,
            )
        return None

    def _parse_nsg_rule(self, block: str, full_name: str, line_num: int, vendor: str) -> Optional[NormalizedChange]:
        access = re.search(r'access\s*=\s*"(\w+)"', block)
        if not access:
            return None

        direction_m = re.search(r'direction\s*=\s*"(\w+)"', block)
        source_m = re.search(r'source_address_prefix\s*=\s*"([^"]+)"', block)
        port_m = re.search(r'destination_port_range\s*=\s*"([^"]+)"', block)

        src = source_m.group(1) if source_m else "0.0.0.0/0"
        port_str = port_m.group(1) if port_m else "*"
        direction = "INGRESS" if (direction_m and "inbound" in direction_m.group(1).lower()) else "EGRESS"

        # Normalize Azure source addresses
        if src.lower() in ("internet", "*", "any"):
            src = "0.0.0.0/0"

        ports = [PortRange.from_string(p.strip()) for p in port_str.split(",")]

        return NormalizedChange(
            change_type="ADD", resource_type="firewall_rule",
            resource_name=full_name, vendor=vendor,
            direction=direction,
            source_cidrs=[normalize_cidr(src)],
            dest_cidrs=["0.0.0.0/0"],
            ports=ports, protocol="TCP",
            action="ALLOW" if access.group(1).lower() == "allow" else "DENY",
            raw_snippet=block[:300], line_start=line_num,
        )


# ─── GCP Parser ───────────────────────────────────────────────────────────────

class GCPParser:
    def parse(self, raw_diff: str, vendor: str = "gcp") -> List[NormalizedChange]:
        var_map = _resolve_variables(raw_diff)
        diff = _substitute_vars(raw_diff, var_map)
        changes = []

        for m in re.finditer(
            r'resource\s+"(google_[\w]+)"\s+"([\w-]+)"\s*\{(.*?)(?=\nresource|\Z)',
            diff, re.DOTALL
        ):
            res_type, res_name, block = m.group(1), m.group(2), m.group(3)
            line_num = diff[:m.start()].count("\n")
            full_name = f"{res_type}.{res_name}"

            change = self._parse_gcp_resource(res_type, full_name, block, line_num, vendor)
            if change:
                changes.append(change)

        if not changes:
            changes.extend(AWSParser()._fallback_parse(diff, vendor))
        return changes

    def _parse_gcp_resource(self, res_type: str, full_name: str,
                              block: str, line_num: int, vendor: str) -> Optional[NormalizedChange]:
        if res_type == "google_compute_firewall":
            source_ranges = re.findall(r'"(\d[\d./]+|::/0)"', block)
            if not source_ranges:
                open_m = re.search(r'source_ranges\s*=\s*\[([^\]]+)\]', block)
                if open_m:
                    source_ranges = [x.strip().strip('"') for x in open_m.group(1).split(",")]

            ports = []
            for port_m in re.finditer(r'ports\s*=\s*\[([^\]]+)\]', block):
                ports.extend([PortRange.from_string(p.strip().strip('"'))
                               for p in port_m.group(1).split(",") if p.strip().strip('"')])

            allow_block = re.search(r'allow\s*\{', block)
            direction_m = re.search(r'direction\s*=\s*"(\w+)"', block)
            direction = "INGRESS"
            if direction_m and "egress" in direction_m.group(1).lower():
                direction = "EGRESS"

            return NormalizedChange(
                change_type="ADD", resource_type="firewall_rule",
                resource_name=full_name, vendor=vendor,
                direction=direction,
                source_cidrs=source_ranges or ["0.0.0.0/0"],
                dest_cidrs=["0.0.0.0/0"],
                ports=ports or [PortRange.any()],
                protocol="TCP",
                action="ALLOW" if allow_block else "DENY",
                raw_snippet=block[:300], line_start=line_num,
            )

        if res_type in ("google_project_iam_binding", "google_project_iam_member"):
            role_m = re.search(r'role\s*=\s*"([^"]+)"', block)
            if role_m:
                return NormalizedChange(
                    change_type="ADD", resource_type="iam_binding",
                    resource_name=full_name, vendor=vendor,
                    direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="ALLOW",
                    iam_actions=[role_m.group(1)], iam_resources=["*"],
                    raw_snippet=block[:200], line_start=line_num,
                )

        if "dns" in res_type:
            return NormalizedChange(
                change_type="ADD", resource_type="dns_record",
                resource_name=full_name, vendor=vendor,
                direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                ports=[], protocol="ANY", action="ALLOW",
                raw_snippet=block[:200], line_start=line_num,
            )
        return None


# ─── Cisco IOS / NX-OS Parser ────────────────────────────────────────────────

class CiscoIOSParser:
    # Regex for a single ACE
    ACE_RE = re.compile(
        r'^(?:permit|deny)\s+(ip|tcp|udp|icmp|\d+)\s+'
        r'(any|host\s+\S+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?(?:/\d+)?)\s*'
        r'(?:(any|host\s+\S+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?(?:/\d+)?))?\s*'
        r'(?:eq\s+(\S+))?',
        re.IGNORECASE
    )

    def parse(self, raw_diff: str, vendor: str = "cisco_ios") -> List[NormalizedChange]:
        # Extract only added/modified lines
        lines = []
        for i, line in enumerate(raw_diff.splitlines()):
            stripped = line.lstrip("+- ").strip()
            lines.append((i, stripped, not line.startswith("-")))  # (line_num, text, is_added)

        acl_defs: dict = {}        # acl_name → list of ace dicts
        interface_bindings: dict = {}  # interface → (acl_name, direction)
        current_acl: Optional[str] = None
        current_interface: Optional[str] = None
        changes = []

        for line_num, text, is_added in lines:
            if not text or not is_added:
                continue

            # ACL definition start: "ip access-list extended NAME" or "ip access-list NAME"
            acl_m = re.match(r'ip access-list (?:extended |standard )?(\S+)', text, re.IGNORECASE)
            if acl_m:
                current_acl = acl_m.group(1)
                acl_defs.setdefault(current_acl, [])
                current_interface = None
                continue

            # Old-style numbered ACL: "access-list 101 permit tcp ..."
            old_acl_m = re.match(r'access-list\s+(\d+)\s+(permit|deny)\s+(.*)', text, re.IGNORECASE)
            if old_acl_m:
                acl_name = f"acl_{old_acl_m.group(1)}"
                acl_defs.setdefault(acl_name, [])
                ace = self._parse_ace_inline(old_acl_m.group(2), old_acl_m.group(3), line_num, text)
                if ace:
                    acl_defs[acl_name].append(ace)
                continue

            # ACE within named ACL
            if current_acl and re.match(r'(?:permit|deny)\s+', text, re.IGNORECASE):
                ace = self._parse_ace(text, line_num)
                if ace:
                    acl_defs[current_acl].append(ace)
                continue

            # Interface context
            intf_m = re.match(r'interface\s+(\S+)', text, re.IGNORECASE)
            if intf_m:
                current_interface = intf_m.group(1)
                current_acl = None
                continue

            # ACL binding on interface: "ip access-group NAME in|out"
            if current_interface:
                binding_m = re.match(r'ip access-group\s+(\S+)\s+(in|out)', text, re.IGNORECASE)
                if binding_m:
                    interface_bindings[current_interface] = (
                        binding_m.group(1),
                        "INGRESS" if binding_m.group(2).lower() == "in" else "EGRESS"
                    )
                    continue

            # Standalone permit/deny (not under ACL context)
            if not current_acl and re.match(r'(?:permit|deny)\s+', text, re.IGNORECASE):
                ace = self._parse_ace(text, line_num)
                if ace:
                    acl_defs.setdefault("_standalone", []).append(ace)

        # Build NormalizedChanges from bound ACLs
        bound_acls = {b[0] for b in interface_bindings.values()}
        for intf, (acl_name, direction) in interface_bindings.items():
            for ace in acl_defs.get(acl_name, []):
                changes.append(self._ace_to_nc(ace, direction, f"{intf}:{acl_name}", vendor))

        # Unbound ACLs — direction unknown
        for acl_name, aces in acl_defs.items():
            if acl_name not in bound_acls:
                for ace in aces:
                    changes.append(self._ace_to_nc(ace, "UNKNOWN", f"acl:{acl_name}", vendor))

        return changes

    def _parse_ace(self, text: str, line_num: int) -> Optional[dict]:
        parts = text.strip().split()
        if len(parts) < 3:
            return None
        return self._parse_ace_inline(parts[0], " ".join(parts[1:]), line_num, text)

    def _parse_ace_inline(self, action: str, rest: str, line_num: int, raw: str) -> Optional[dict]:
        parts = rest.split()
        if not parts:
            return None

        protocol = parts[0].upper() if parts[0].lower() not in ("ip",) else "ANY"
        idx = 1
        src, idx = self._parse_addr(parts, idx)
        dst, idx = self._parse_addr(parts, idx)
        port = None
        if idx < len(parts) and parts[idx].lower() == "eq" and idx + 1 < len(parts):
            port_str = parts[idx + 1].lower()
            named = resolve_named_port(port_str)
            if named:
                port = named
            else:
                try:
                    port = int(port_str)
                except ValueError:
                    pass

        return {
            "action": "ALLOW" if action.lower() == "permit" else "DENY",
            "protocol": protocol,
            "source": src,
            "dest": dst,
            "port": port,
            "line_num": line_num,
            "raw": raw,
        }

    def _parse_addr(self, parts: List[str], idx: int):
        if idx >= len(parts):
            return "0.0.0.0/0", idx
        token = parts[idx].lower()
        if token == "any":
            return "0.0.0.0/0", idx + 1
        if token == "host" and idx + 1 < len(parts):
            return parts[idx + 1] + "/32", idx + 2
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", token):
            # Check if next token is a wildcard mask
            if (idx + 1 < len(parts) and
                    re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parts[idx + 1])):
                return wildcard_to_cidr(token, parts[idx + 1]), idx + 2
            if "/" in token:
                return token, idx + 1
            return token + "/32", idx + 1
        return "0.0.0.0/0", idx + 1

    def _ace_to_nc(self, ace: dict, direction: str, context: str, vendor: str) -> NormalizedChange:
        port = ace.get("port")
        ports = [PortRange(port, port)] if port else [PortRange.any()]
        return NormalizedChange(
            change_type="ADD", resource_type="firewall_acl",
            resource_name=context, vendor=vendor,
            direction=direction,
            source_cidrs=[normalize_cidr(ace.get("source", "0.0.0.0/0"))],
            dest_cidrs=[normalize_cidr(ace.get("dest", "0.0.0.0/0"))],
            ports=ports, protocol=ace.get("protocol", "ANY"),
            action=ace.get("action", "ALLOW"),
            raw_snippet=ace.get("raw", ""),
            line_start=ace.get("line_num", 0),
        )


# ─── Palo Alto PAN-OS Parser ─────────────────────────────────────────────────

class PaloAltoParser:
    UNTRUSTED_ZONES = frozenset({"untrust", "external", "internet", "wan", "outside", "dmz-ext"})
    TRUSTED_ZONES = frozenset({"trust", "internal", "corp", "lan", "servers", "prod", "dmz", "dmz-int"})
    SERVICE_PORT_MAP = {
        "service-ssh": [22], "service-http": [80], "service-https": [443],
        "service-rdp": [3389], "service-telnet": [23], "service-ftp": [21],
        "service-smtp": [25], "service-dns": [53], "service-snmp": [161],
    }

    def parse(self, raw_diff: str, vendor: str = "paloalto") -> List[NormalizedChange]:
        added = _extract_added_lines(raw_diff)
        changes = []

        # Try XML parsing
        entry_pattern = re.compile(
            r'<entry name="([^"]+)">(.*?)</entry>', re.DOTALL
        )
        for m in entry_pattern.finditer(added):
            rule_name = m.group(1)
            rule_xml = m.group(0)
            line_num = raw_diff[:raw_diff.find(rule_name)].count("\n") if rule_name in raw_diff else 0
            try:
                root = ET.fromstring(rule_xml)
                change = self._parse_entry_xml(root, rule_name, line_num, vendor)
            except ET.ParseError:
                change = self._parse_entry_regex(rule_xml, rule_name, line_num, vendor)
            if change:
                changes.append(change)

        # Fallback: key-value style (Panorama exports)
        if not changes:
            changes.extend(self._parse_kv_style(added, vendor))

        return changes

    def _get_members(self, element, tag: str) -> List[str]:
        container = element.find(tag)
        if container is None:
            return []
        return [m.text for m in container.findall("member") if m.text]

    def _parse_entry_xml(self, root, rule_name: str, line_num: int, vendor: str) -> Optional[NormalizedChange]:
        frm = self._get_members(root, "from")
        to = self._get_members(root, "to")
        source = self._get_members(root, "source")
        service = self._get_members(root, "service")
        application = self._get_members(root, "application")
        action_elem = root.find("action")
        action = (action_elem.text or "allow").lower()

        # Normalize sources
        src_cidrs = []
        for s in source:
            sl = s.lower()
            if sl in ("any", "any-ipv4", "any-ipv6"):
                src_cidrs.append("0.0.0.0/0")
            elif re.match(r"\d+\.\d+\.\d+\.\d+", s):
                src_cidrs.append(s if "/" in s else s + "/32")
            else:
                src_cidrs.append(s)

        from_untrusted = any(z.lower() in self.UNTRUSTED_ZONES for z in frm)
        to_trusted = any(z.lower() in self.TRUSTED_ZONES for z in to)
        direction = "INGRESS" if (from_untrusted or (not frm)) else (
            "LATERAL" if to_trusted else "EGRESS"
        )

        ports: List[PortRange] = []
        for svc in service:
            if svc.lower() == "any":
                ports = [PortRange.any()]
                break
            for k, port_list in self.SERVICE_PORT_MAP.items():
                if k == svc:
                    ports.extend(PortRange(p, p) for p in port_list)
        if not ports:
            ports = [PortRange.any()]

        return NormalizedChange(
            change_type="ADD", resource_type="firewall_policy",
            resource_name=f"panos:{rule_name}", vendor=vendor,
            direction=direction, source_cidrs=src_cidrs or ["0.0.0.0/0"],
            dest_cidrs=["0.0.0.0/0"], ports=ports,
            protocol="TCP" if "service-" in " ".join(service) else "ANY",
            action="ALLOW" if action == "allow" else "DENY",
            raw_snippet=ET.tostring(root, encoding="unicode")[:300],
            line_start=line_num,
        )

    def _parse_entry_regex(self, xml: str, rule_name: str, line_num: int, vendor: str) -> Optional[NormalizedChange]:
        source_any = bool(re.search(r"<member>any</member>", xml, re.IGNORECASE))
        action_allow = bool(re.search(r"<action>allow</action>", xml, re.IGNORECASE))
        service_any = bool(re.search(r"<service>.*?<member>any</member>", xml, re.DOTALL))
        if source_any and action_allow:
            return NormalizedChange(
                change_type="ADD", resource_type="firewall_policy",
                resource_name=f"panos:{rule_name}", vendor=vendor,
                direction="INGRESS", source_cidrs=["0.0.0.0/0"], dest_cidrs=["0.0.0.0/0"],
                ports=[PortRange.any()] if service_any else [],
                protocol="ANY", action="ALLOW", raw_snippet=xml[:300], line_start=line_num,
            )
        return None

    def _parse_kv_style(self, text: str, vendor: str) -> List[NormalizedChange]:
        changes = []
        if re.search(r"source.*any|srcaddr.*all", text, re.IGNORECASE):
            if re.search(r"action.*allow|accept", text, re.IGNORECASE):
                changes.append(NormalizedChange(
                    change_type="ADD", resource_type="firewall_policy",
                    resource_name="panos_kv_rule", vendor=vendor,
                    direction="INGRESS", source_cidrs=["0.0.0.0/0"], dest_cidrs=["0.0.0.0/0"],
                    ports=[PortRange.any()], protocol="ANY", action="ALLOW",
                    raw_snippet=text[:300], line_start=0,
                ))
        return changes


# ─── FortiGate FortiOS Parser ─────────────────────────────────────────────────

class FortiGateParser:
    ADDR_MAP = {"all": "0.0.0.0/0", "any": "0.0.0.0/0", "all traffic": "0.0.0.0/0"}
    WAN_INTERFACES = frozenset({"wan1", "wan2", "port1", "internet", "external",
                                 "outside", "wan", "uplink", "untrust"})
    SERVICE_MAP = {
        "ALL": PortRange.any(), "HTTP": PortRange(80, 80), "HTTPS": PortRange(443, 443),
        "SSH": PortRange(22, 22), "TELNET": PortRange(23, 23), "RDP": PortRange(3389, 3389),
        "FTP": PortRange(21, 21), "DNS": PortRange(53, 53), "SMTP": PortRange(25, 25),
        "IMAP": PortRange(143, 143), "POP3": PortRange(110, 110),
        "MYSQL": PortRange(3306, 3306), "MS-SQL": PortRange(1433, 1433),
    }

    def parse(self, raw_diff: str, vendor: str = "fortigate") -> List[NormalizedChange]:
        added = _extract_added_lines(raw_diff)
        changes = []

        # Parse policy blocks
        for m in re.finditer(r'edit\s+(\d+)(.*?)(?=edit\s+\d+|^end\s*$)', added, re.DOTALL | re.MULTILINE):
            policy_id, block = m.group(1), m.group(2)
            line_num = raw_diff.find(f"edit {policy_id}")
            line_num = raw_diff[:line_num].count("\n") if line_num >= 0 else 0
            change = self._parse_policy_block(policy_id, block, line_num, vendor)
            if change:
                changes.append(change)

        # VIP definitions = high risk (port forwarding to internal)
        for m in re.finditer(r'config\s+firewall\s+vip(.*?)^end', added, re.DOTALL | re.MULTILINE):
            for vip_m in re.finditer(r'edit\s+"([^"]+)"(.*?)(?=edit\s+"|^end)', m.group(1), re.DOTALL | re.MULTILINE):
                vip_name = vip_m.group(1)
                changes.append(NormalizedChange(
                    change_type="ADD", resource_type="firewall_vip",
                    resource_name=f"fortigate_vip:{vip_name}", vendor=vendor,
                    direction="INGRESS", source_cidrs=["0.0.0.0/0"], dest_cidrs=["0.0.0.0/0"],
                    ports=[PortRange.any()], protocol="TCP", action="ALLOW",
                    raw_snippet=vip_m.group(0)[:200], line_start=0,
                ))

        # SSL-VPN settings changes = HIGH
        if re.search(r"config\s+vpn\s+ssl\s+settings", added, re.IGNORECASE):
            changes.append(NormalizedChange(
                change_type="MODIFY", resource_type="vpn_config",
                resource_name="fortigate_sslvpn", vendor=vendor,
                direction="INGRESS", source_cidrs=["0.0.0.0/0"], dest_cidrs=["0.0.0.0/0"],
                ports=[PortRange(443, 443)], protocol="TCP", action="ALLOW",
                raw_snippet="SSL-VPN settings change", line_start=0,
            ))

        if not changes:
            changes.extend(AWSParser()._fallback_parse(added, vendor))
        return changes

    def _parse_policy_block(self, policy_id: str, block: str, line_num: int, vendor: str) -> Optional[NormalizedChange]:
        def get_field(field: str) -> str:
            m = re.search(rf'\bset\s+{field}\s+"?([^"\n]+)"?', block, re.IGNORECASE)
            return m.group(1).strip().strip('"') if m else ""

        srcintf = get_field("srcintf")
        srcaddr = get_field("srcaddr")
        dstaddr = get_field("dstaddr")
        service = get_field("service")
        action = get_field("action")

        if not action:
            return None

        src_cidr = self.ADDR_MAP.get(srcaddr.lower(), srcaddr if srcaddr else "10.0.0.0/8")
        if re.match(r"\d+\.\d+\.\d+\.\d+", src_cidr) and "/" not in src_cidr:
            src_cidr += "/32"

        port = self.SERVICE_MAP.get(service.upper(), PortRange.any() if service.upper() in ("ALL", "ANY") else None)
        is_from_internet = (srcintf.lower() in self.WAN_INTERFACES or
                            srcaddr.lower() in ("all", "any", "0.0.0.0/0"))
        direction = "INGRESS" if is_from_internet else "EGRESS"

        return NormalizedChange(
            change_type="ADD", resource_type="firewall_policy",
            resource_name=f"fortigate_policy:{policy_id}", vendor=vendor,
            direction=direction, source_cidrs=[src_cidr], dest_cidrs=["0.0.0.0/0"],
            ports=[port] if port else [PortRange.any()],
            protocol="TCP", action="ALLOW" if action.lower() == "accept" else "DENY",
            raw_snippet=block[:300], line_start=line_num,
        )


# ─── Kubernetes Parser ─────────────────────────────────────────────────────────

class KubernetesParser:
    def parse(self, raw_diff: str, vendor: str = "kubernetes") -> List[NormalizedChange]:
        added = _extract_added_lines(raw_diff)
        changes = []
        docs = []

        # Parse all YAML documents
        for block in (added + "\n---\n").split("---"):
            block = block.strip()
            if not block:
                continue
            try:
                doc = pyyaml.safe_load(block)
                if isinstance(doc, dict):
                    docs.append((doc, block))
            except Exception:
                pass

        for doc, raw_block in docs:
            kind = doc.get("kind", "")
            name = doc.get("metadata", {}).get("name", "unknown")
            line_num = raw_diff.find(name) if name in raw_diff else 0
            line_num = raw_diff[:line_num].count("\n") if line_num > 0 else 0

            if kind == "NetworkPolicy":
                changes.extend(self._parse_netpol(doc, name, raw_block, line_num, vendor))
            elif kind == "ClusterRole":
                changes.extend(self._parse_cluster_role(doc, name, raw_block, line_num, vendor))
            elif kind == "ClusterRoleBinding":
                changes.extend(self._parse_crb(doc, name, raw_block, line_num, vendor))
            elif kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet"):
                changes.extend(self._parse_workload(doc, name, kind, raw_block, line_num, vendor))

        if not changes:
            changes.extend(AWSParser()._fallback_parse(raw_diff, vendor))
        return changes

    def _parse_netpol(self, doc: dict, name: str, raw: str, line_num: int, vendor: str) -> List[NormalizedChange]:
        spec = doc.get("spec", {})
        pod_selector = spec.get("podSelector", {})
        ingress_rules = spec.get("ingress", [])
        pod_selector_all = pod_selector == {} or pod_selector is None
        changes = []

        for rule in ingress_rules:
            if rule == {} or rule is None:
                # Empty rule = allow all ingress
                changes.append(NormalizedChange(
                    change_type="ADD", resource_type="k8s_network_policy",
                    resource_name=f"k8s_netpol:{name}", vendor=vendor,
                    direction="INGRESS", source_cidrs=["0.0.0.0/0"],
                    dest_cidrs=["ALL_PODS" if pod_selector_all else "SELECTED_PODS"],
                    ports=[PortRange.any()], protocol="ANY", action="ALLOW",
                    raw_snippet=f"NetworkPolicy {name}: empty ingress rule allows all",
                    line_start=line_num,
                ))
            else:
                for from_entry in rule.get("from", []):
                    ip_block = from_entry.get("ipBlock", {})
                    cidr = ip_block.get("cidr", "")
                    if cidr in ("0.0.0.0/0", "::/0"):
                        port_entries = rule.get("ports", [])
                        ports = [PortRange.from_string(str(p.get("port", -1)))
                                 for p in port_entries] or [PortRange.any()]
                        changes.append(NormalizedChange(
                            change_type="ADD", resource_type="k8s_network_policy",
                            resource_name=f"k8s_netpol:{name}", vendor=vendor,
                            direction="INGRESS", source_cidrs=[cidr], dest_cidrs=["k8s_pods"],
                            ports=ports, protocol="TCP", action="ALLOW",
                            raw_snippet=f"NetworkPolicy {name}: ipBlock.cidr={cidr}",
                            line_start=line_num,
                        ))
        return changes

    def _parse_cluster_role(self, doc: dict, name: str, raw: str, line_num: int, vendor: str) -> List[NormalizedChange]:
        rules = doc.get("rules", [])
        changes = []
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            if "*" in verbs and "*" in resources:
                changes.append(NormalizedChange(
                    change_type="ADD", resource_type="k8s_rbac",
                    resource_name=f"k8s_clusterrole:{name}", vendor=vendor,
                    direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="ALLOW",
                    iam_actions=verbs, iam_resources=resources,
                    raw_snippet=f"ClusterRole {name}: verbs=[*], resources=[*]",
                    line_start=line_num,
                ))
        return changes

    def _parse_crb(self, doc: dict, name: str, raw: str, line_num: int, vendor: str) -> List[NormalizedChange]:
        subjects = doc.get("subjects", [])
        role_ref = doc.get("roleRef", {})
        dangerous_subjects = {"system:unauthenticated", "system:anonymous"}
        dangerous_roles = {"cluster-admin", "admin"}
        changes = []
        has_dangerous = (any(s.get("name", "") in dangerous_subjects for s in subjects) or
                         role_ref.get("name", "") in dangerous_roles)
        if has_dangerous:
            changes.append(NormalizedChange(
                change_type="ADD", resource_type="k8s_rbac",
                resource_name=f"k8s_crb:{name}", vendor=vendor,
                direction="UNKNOWN", source_cidrs=[], dest_cidrs=[],
                ports=[], protocol="ANY", action="ALLOW",
                iam_actions=["*"], iam_resources=["*"],
                raw_snippet=f"ClusterRoleBinding {name} → {role_ref.get('name')} for {[s.get('name') for s in subjects]}",
                line_start=line_num,
            ))
        return changes

    def _parse_workload(self, doc: dict, name: str, kind: str,
                         raw: str, line_num: int, vendor: str) -> List[NormalizedChange]:
        spec = doc.get("spec", {})
        pod_spec = spec if kind == "Pod" else spec.get("template", {}).get("spec", {})
        if not pod_spec:
            return []
        changes = []

        if pod_spec.get("hostNetwork", False):
            changes.append(NormalizedChange(
                change_type="ADD", resource_type="k8s_workload",
                resource_name=f"k8s_{kind.lower()}:{name}", vendor=vendor,
                direction="BOTH", source_cidrs=["0.0.0.0/0"], dest_cidrs=["host_network"],
                ports=[PortRange.any()], protocol="ANY", action="ALLOW",
                raw_snippet=f"{kind} {name}: hostNetwork=true",
                line_start=line_num,
            ))

        for container in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
            sc = container.get("securityContext", {})
            if sc.get("privileged", False) or sc.get("allowPrivilegeEscalation", False):
                changes.append(NormalizedChange(
                    change_type="ADD", resource_type="k8s_workload",
                    resource_name=f"k8s_container:{container.get('name', 'unknown')}",
                    vendor=vendor,
                    direction="BOTH", source_cidrs=[], dest_cidrs=[],
                    ports=[], protocol="ANY", action="ALLOW",
                    iam_actions=["*"], iam_resources=["host"],
                    raw_snippet=f"{kind}/{name}/{container.get('name')}: privileged=true",
                    line_start=line_num,
                ))
        return changes
