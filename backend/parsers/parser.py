"""Stack-specific parsers for AWS, Azure, GCP, and on-prem infrastructure changes."""
import re
from typing import Optional


def detect_stack(raw_diff: str, change_source: str) -> str:
    """Detect the infrastructure stack from the raw diff content."""
    diff_lower = raw_diff.lower()

    aws_patterns = [
        r'aws_', r'resource "aws_', r'AWSTemplateFormatVersion',
        r'cloudformation', r'amazon', r'ec2', r's3', r'vpc', r'ami-', r'arn:aws:'
    ]
    azure_patterns = [
        r'azurerm_', r'resource "azurerm_', r'Microsoft\.', r'azure',
        r'subscription_id', r'bicep', r'arm_template', r'azure-pipelines'
    ]
    gcp_patterns = [
        r'google_compute', r'google_', r'resource "google_', r'gcp',
        r'gcloud', r'project_id', r'google-cloud', r'googleapis'
    ]
    onprem_patterns = [
        r'iptables', r'permit ', r'deny ', r'access-list', r'pfsense',
        r'cisco', r'acl ', r'ip access', r'firewall-cmd', r'ufw '
    ]

    scores = {'aws': 0, 'azure': 0, 'gcp': 0, 'onprem': 0}
    for p in aws_patterns:
        if re.search(p, diff_lower):
            scores['aws'] += 1
    for p in azure_patterns:
        if re.search(p, diff_lower):
            scores['azure'] += 1
    for p in gcp_patterns:
        if re.search(p, diff_lower):
            scores['gcp'] += 1
    for p in onprem_patterns:
        if re.search(p, diff_lower):
            scores['onprem'] += 1

    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else 'unknown'


def parse_aws(raw_diff: str) -> dict:
    """Parse AWS Terraform / CloudFormation changes."""
    findings = []
    resources = []

    # Extract resource names
    tf_resources = re.findall(r'resource\s+"(aws_\w+)"\s+"(\w+)"', raw_diff)
    cf_resources = re.findall(r'Type:\s+"?(AWS::\w+::\w+)"?', raw_diff)
    resources = [f"{r[0]}.{r[1]}" for r in tf_resources] + cf_resources

    # Check for 0.0.0.0/0
    has_open_cidr = bool(re.search(r'0\.0\.0\.0/0|::/0', raw_diff))
    # Check ports
    port_matches = re.findall(r'(?:from_port|to_port|port)\s*[=:]\s*"?(\d+|-1)"?', raw_diff)
    # Check IAM
    has_wildcard_action = bool(re.search(r'"Action"\s*:\s*"\*"|\bactions\s*=\s*\["\*"\]', raw_diff))
    has_admin_role = bool(re.search(
        r'AdministratorAccess|PowerUserAccess|FullAccess|"Resource"\s*:\s*"\*"', raw_diff))

    return {
        "stack": "aws",
        "resources": resources,
        "has_open_cidr": has_open_cidr,
        "ports_modified": list(set(port_matches)),
        "has_wildcard_iam": has_wildcard_action,
        "has_admin_role": has_admin_role,
        "resource_count": len(resources),
        "services_detected": _extract_aws_services(resources),
    }


def parse_azure(raw_diff: str) -> dict:
    """Parse Azure Bicep / ARM / Terraform azurerm changes."""
    resources = re.findall(r'resource\s+"(azurerm_\w+)"\s+"(\w+)"', raw_diff)
    resource_names = [f"{r[0]}.{r[1]}" for r in resources]

    has_internet_source = bool(re.search(r'Internet|0\.0\.0\.0/0|AzureLoadBalancer', raw_diff))
    has_owner_role = bool(re.search(
        r'\b(Owner|Contributor|Administrator)\b', raw_diff, re.IGNORECASE))
    has_dns_zone = bool(re.search(r'azurerm_dns_zone|azurerm_dns_', raw_diff))

    return {
        "stack": "azure",
        "resources": resource_names,
        "has_internet_source": has_internet_source,
        "has_owner_role": has_owner_role,
        "has_dns_zone": has_dns_zone,
        "resource_count": len(resource_names),
        "services_detected": [r[0] for r in resources],
    }


def parse_gcp(raw_diff: str) -> dict:
    """Parse GCP Terraform / gcloud JSON changes."""
    resources = re.findall(r'resource\s+"(google_\w+)"\s+"(\w+)"', raw_diff)
    resource_names = [f"{r[0]}.{r[1]}" for r in resources]

    has_open_cidr = bool(re.search(r'0\.0\.0\.0/0|::/0', raw_diff))
    # GCP allows all TCP/UDP
    has_allow_all = bool(re.search(r'allow.*all|source_ranges.*0\.0\.0\.0', raw_diff, re.DOTALL))
    has_iam_binding = bool(re.search(r'google_project_iam_binding|google_.*_iam_member', raw_diff))

    return {
        "stack": "gcp",
        "resources": resource_names,
        "has_open_cidr": has_open_cidr,
        "has_allow_all": has_allow_all,
        "has_iam_binding": has_iam_binding,
        "resource_count": len(resource_names),
        "services_detected": list({r[0] for r in resources}),
    }


def parse_onprem(raw_diff: str) -> dict:
    """Parse Cisco ACL, iptables, pfSense configs."""
    has_permit_any = bool(re.search(r'permit\s+any\s+any|\-j ACCEPT.*(?!--source)', raw_diff))
    has_pfsense_pass = bool(re.search(r'<type>pass</type>.*<source>.*<any/>', raw_diff, re.DOTALL))
    has_no_source_restrict = bool(re.search(r'\-A.*\-j ACCEPT(?!.*\-\-source)', raw_diff))

    acl_rules = re.findall(r'access-list \d+ (permit|deny) .+', raw_diff)
    iptables_rules = re.findall(r'\-A \w+ .+', raw_diff)

    return {
        "stack": "onprem",
        "has_permit_any": has_permit_any,
        "has_pfsense_pass_any": has_pfsense_pass,
        "has_unrestricted_accept": has_no_source_restrict,
        "acl_rules": acl_rules,
        "iptables_rules": iptables_rules,
        "rule_count": len(acl_rules) + len(iptables_rules),
    }


def parse_change(raw_diff: str, detected_stack: str) -> dict:
    """Route to the appropriate parser based on detected stack."""
    parsers = {
        'aws': parse_aws,
        'azure': parse_azure,
        'gcp': parse_gcp,
        'onprem': parse_onprem,
    }
    parser_fn = parsers.get(detected_stack, parse_aws)
    result = parser_fn(raw_diff)
    result['diff_lines'] = len(raw_diff.splitlines())
    result['diff_chars'] = len(raw_diff)
    return result


def _extract_aws_services(resources: list) -> list:
    services = set()
    for r in resources:
        r_lower = r.lower()
        if 'security_group' in r_lower:
            services.add('ec2-sg')
        if 's3' in r_lower:
            services.add('s3')
        if 'iam' in r_lower:
            services.add('iam')
        if 'nat' in r_lower:
            services.add('nat')
        if 'route' in r_lower:
            services.add('vpc-routing')
        if 'vpc' in r_lower:
            services.add('vpc')
        if 'rds' in r_lower:
            services.add('rds')
        if 'lambda' in r_lower:
            services.add('lambda')
    return list(services)
