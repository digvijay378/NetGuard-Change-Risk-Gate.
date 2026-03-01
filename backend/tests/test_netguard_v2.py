"""
NetGuard v2 Comprehensive API Tests
Tests all features from the v2 IR-based pipeline including:
- AWS Terraform (SSH 0.0.0.0/0 → CRITICAL, ESCALATE_TO_HUMAN)
- Cisco IOS ACL (SSH/RDP from any → CRITICAL, cisco_ios stack)
- Kubernetes NetworkPolicy (0.0.0.0/0 CIDR → CRITICAL, kubernetes stack)
- IAM wildcard Action=* (→ CRITICAL, IAM-001 finding)
- Low-risk changes (route table → MEDIUM/HIGH, not CRITICAL)
- Stats endpoint (correct counts)
- Assessments list (_id excluded)
- Assessment detail (rule_findings with code_snippet, suggested_fix, line_number, resource_name)
- RAG health (4 collections)
"""
import pytest
import requests
import os

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://netguard-v2-1.preview.emergentagent.com").rstrip("/")

# Test diff samples
AWS_SSH_DIFF = """
+ resource "aws_security_group_rule" "allow_ssh" {
+   type        = "ingress"
+   from_port   = 22
+   to_port     = 22
+   protocol    = "tcp"
+   cidr_blocks = ["0.0.0.0/0"]
+   description = "SSH from anywhere - DANGEROUS"
+ }
"""

CISCO_IOS_ACL_DIFF = """
ip access-list extended OUTSIDE-IN
  permit tcp any any eq 22
  permit tcp any any eq 3389
  permit tcp any any eq 23
  deny ip any any

interface GigabitEthernet0/0
  description WAN uplink
  ip access-group OUTSIDE-IN in
"""

KUBERNETES_NETPOL_DIFF = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: production
spec:
  podSelector: {}
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
  policyTypes:
  - Ingress
"""

IAM_WILDCARD_DIFF = """
+ resource "aws_iam_role_policy" "wildcard_policy" {
+   role = aws_iam_role.lambda_role.id
+   policy = jsonencode({
+     Version = "2012-10-17"
+     Statement = [{
+       Effect   = "Allow"
+       Action   = ["*"]
+       Resource = "*"
+     }]
+   })
+ }
"""

LOW_RISK_ROUTE_DIFF = """
+ resource "aws_route" "default_route" {
+   route_table_id         = aws_route_table.private.id
+   destination_cidr_block = "10.0.0.0/8"
+   nat_gateway_id         = aws_nat_gateway.main.id
+ }
"""


class TestRAGHealth:
    """Tests for RAG health endpoint - should return 4 collections"""
    
    def test_rag_health_returns_healthy_status(self):
        """RAG health should return healthy status with 4 collections"""
        r = requests.get(f"{BASE_URL}/api/v1/health/rag")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        
        data = r.json()
        assert data.get("status") == "healthy", f"Expected healthy status, got {data.get('status')}"
        
        # Verify 4 collections exist
        collections = data.get("collections", {})
        expected_collections = {"cve_knowledge", "attack_techniques", "policy_controls", "change_history"}
        actual_collections = set(collections.keys())
        
        assert expected_collections == actual_collections, f"Expected collections {expected_collections}, got {actual_collections}"
        assert len(collections) == 4, f"Expected 4 collections, got {len(collections)}"
        
        # Each collection should have documents
        for col_name, stats in collections.items():
            assert stats.get("count", 0) > 0, f"Collection {col_name} has 0 documents"
            assert stats.get("status") == "healthy", f"Collection {col_name} is not healthy"
        
        print(f"✓ RAG health: 4 collections, all healthy with counts > 0")


class TestStatsEndpoint:
    """Tests for stats endpoint"""
    
    def test_stats_returns_correct_structure(self):
        """Stats should return correct counts for total, by_risk_level, by_source"""
        r = requests.get(f"{BASE_URL}/api/v1/stats")
        assert r.status_code == 200
        
        data = r.json()
        
        # Required fields
        assert "total" in data, "Missing 'total' in stats"
        assert "auto_approved" in data, "Missing 'auto_approved' in stats"
        assert "escalated" in data, "Missing 'escalated' in stats"
        assert "blocked" in data, "Missing 'blocked' in stats"
        assert "by_risk_level" in data, "Missing 'by_risk_level' in stats"
        assert "by_source" in data, "Missing 'by_source' in stats"
        assert "recent_assessments" in data, "Missing 'recent_assessments' in stats"
        
        # Validate by_risk_level structure
        by_risk = data["by_risk_level"]
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            assert level in by_risk, f"Missing {level} in by_risk_level"
            assert isinstance(by_risk[level], int), f"{level} should be int"
        
        # Validate by_source structure
        by_source = data["by_source"]
        for source in ["github_pr", "firewall_api", "servicenow", "jira"]:
            assert source in by_source, f"Missing {source} in by_source"
        
        print(f"✓ Stats endpoint: total={data['total']}, by_risk_level={by_risk}, by_source={by_source}")


class TestAssessmentsList:
    """Tests for listing assessments"""
    
    def test_assessments_list_excludes_mongo_id(self):
        """GET /api/v1/assessments should return list with _id excluded"""
        r = requests.get(f"{BASE_URL}/api/v1/assessments?limit=10")
        assert r.status_code == 200
        
        data = r.json()
        assert isinstance(data, list), "Expected list response"
        
        # Check that no item has MongoDB _id field
        for assessment in data:
            assert "_id" not in assessment, f"MongoDB _id should be excluded but found in {assessment.get('assessment_id')}"
            assert "assessment_id" in assessment, "Missing assessment_id field"
        
        print(f"✓ Assessments list: {len(data)} items returned, _id excluded from all")


class TestAWSSSHAssessment:
    """Tests for AWS Terraform SSH from 0.0.0.0/0"""
    
    def test_aws_ssh_returns_critical(self):
        """AWS Terraform diff with SSH from 0.0.0.0/0 should return CRITICAL risk, ESCALATE_TO_HUMAN"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": AWS_SSH_DIFF,
            "change_metadata": {"author": "test-aws-ssh"}
        })
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        
        data = r.json()
        
        # Verify CRITICAL risk level
        assert data["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {data['risk_level']}"
        
        # Verify ESCALATE_TO_HUMAN decision
        assert data["final_decision"] == "ESCALATE_TO_HUMAN", f"Expected ESCALATE_TO_HUMAN, got {data['final_decision']}"
        
        # Verify block_merge is True
        assert data["block_merge"] == True, f"Expected block_merge=True, got {data['block_merge']}"
        
        # Verify detected stack is AWS
        assert data["detected_stack"] == "aws", f"Expected aws stack, got {data['detected_stack']}"
        
        # Verify rule findings exist
        assert len(data["rule_findings"]) > 0, "Expected rule findings"
        
        print(f"✓ AWS SSH from 0.0.0.0/0: risk={data['risk_level']}, decision={data['final_decision']}, findings={len(data['rule_findings'])}")
        return data["assessment_id"]


class TestCiscoIOSAssessment:
    """Tests for Cisco IOS ACL with SSH/RDP from any"""
    
    def test_cisco_ios_acl_returns_critical(self):
        """Cisco IOS ACL diff with SSH/RDP from any should return CRITICAL, detect cisco_ios stack"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": CISCO_IOS_ACL_DIFF,
            "change_metadata": {"author": "test-cisco", "device": "core-rtr-01"}
        })
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        
        data = r.json()
        
        # Verify CRITICAL risk level
        assert data["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {data['risk_level']}"
        
        # Verify detected stack is cisco_ios
        assert data["detected_stack"] == "cisco_ios", f"Expected cisco_ios stack, got {data['detected_stack']}"
        
        # Verify ESCALATE_TO_HUMAN
        assert data["final_decision"] == "ESCALATE_TO_HUMAN", f"Expected ESCALATE_TO_HUMAN, got {data['final_decision']}"
        
        # Verify block_merge
        assert data["block_merge"] == True, f"Expected block_merge=True"
        
        # Verify rule findings exist with SSH/RDP tags
        findings = data["rule_findings"]
        assert len(findings) > 0, "Expected rule findings"
        
        all_tags = [tag for f in findings for tag in f.get("tags", [])]
        has_ssh_or_rdp = "ssh" in all_tags or "rdp" in all_tags or "port_exposure" in all_tags
        assert has_ssh_or_rdp, f"Expected SSH/RDP-related tags, got {all_tags}"
        
        print(f"✓ Cisco IOS ACL: risk={data['risk_level']}, stack={data['detected_stack']}, decision={data['final_decision']}")
        return data["assessment_id"]


class TestKubernetesNetworkPolicy:
    """Tests for Kubernetes NetworkPolicy with 0.0.0.0/0 CIDR"""
    
    def test_kubernetes_netpol_returns_critical(self):
        """Kubernetes NetworkPolicy with 0.0.0.0/0 CIDR should return CRITICAL, detect kubernetes stack"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": KUBERNETES_NETPOL_DIFF,
            "change_metadata": {"author": "test-k8s", "cluster": "prod-us-east-1"}
        })
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        
        data = r.json()
        
        # Verify CRITICAL risk level
        assert data["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {data['risk_level']}"
        
        # Verify detected stack is kubernetes
        assert data["detected_stack"] == "kubernetes", f"Expected kubernetes stack, got {data['detected_stack']}"
        
        # Verify ESCALATE_TO_HUMAN
        assert data["final_decision"] == "ESCALATE_TO_HUMAN", f"Expected ESCALATE_TO_HUMAN, got {data['final_decision']}"
        
        # Check for K8S findings
        findings = data["rule_findings"]
        assert len(findings) > 0, "Expected rule findings"
        
        rule_ids = [f["rule_id"] for f in findings]
        has_k8s_rule = any(rid.startswith("K8S-") for rid in rule_ids)
        assert has_k8s_rule, f"Expected K8S-* rule findings, got {rule_ids}"
        
        print(f"✓ Kubernetes NetworkPolicy: risk={data['risk_level']}, stack={data['detected_stack']}, rules={rule_ids}")
        return data["assessment_id"]


class TestIAMWildcard:
    """Tests for IAM wildcard Action=* policy"""
    
    def test_iam_wildcard_returns_critical_with_iam001(self):
        """IAM wildcard Action=* policy should return CRITICAL, IAM-001 finding"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": IAM_WILDCARD_DIFF,
            "change_metadata": {"author": "test-iam"}
        })
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        
        data = r.json()
        
        # Verify CRITICAL risk level
        assert data["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {data['risk_level']}"
        
        # Verify ESCALATE_TO_HUMAN
        assert data["final_decision"] == "ESCALATE_TO_HUMAN", f"Expected ESCALATE_TO_HUMAN, got {data['final_decision']}"
        
        # Check for IAM-001 finding
        findings = data["rule_findings"]
        rule_ids = [f["rule_id"] for f in findings]
        
        assert "IAM-001" in rule_ids, f"Expected IAM-001 finding, got {rule_ids}"
        
        # Verify IAM-001 is CRITICAL
        iam001_finding = next(f for f in findings if f["rule_id"] == "IAM-001")
        assert iam001_finding["severity"] == "CRITICAL", f"IAM-001 should be CRITICAL"
        
        print(f"✓ IAM wildcard: risk={data['risk_level']}, IAM-001 found with severity={iam001_finding['severity']}")
        return data["assessment_id"]


class TestLowRiskChange:
    """Tests for low-risk changes like route table"""
    
    def test_route_table_not_critical(self):
        """Low-risk change (e.g. route table) should return MEDIUM or HIGH, not CRITICAL"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": LOW_RISK_ROUTE_DIFF,
            "change_metadata": {"author": "test-route"}
        })
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        
        data = r.json()
        
        # Should NOT be CRITICAL - route table changes are lower risk
        # Route table changes should be LOW/MEDIUM/HIGH but not CRITICAL
        assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH"], f"Expected LOW/MEDIUM/HIGH for route table, got {data['risk_level']}"
        
        # Verify it's detected as AWS
        assert data["detected_stack"] == "aws", f"Expected aws stack, got {data['detected_stack']}"
        
        print(f"✓ Route table change: risk={data['risk_level']} (correctly NOT CRITICAL), decision={data['final_decision']}")


class TestAssessmentDetailFields:
    """Tests for assessment detail - rule_findings should include code_snippet, suggested_fix, line_number, resource_name"""
    
    def test_assessment_detail_has_finding_fields(self):
        """GET /api/v1/assessments/{id} should return full assessment details with rule_findings containing required fields"""
        
        # First create an assessment
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": AWS_SSH_DIFF,
            "change_metadata": {"author": "test-detail"}
        })
        assert r.status_code == 200
        assessment_id = r.json()["assessment_id"]
        
        # Get the assessment detail
        r2 = requests.get(f"{BASE_URL}/api/v1/assessments/{assessment_id}")
        assert r2.status_code == 200, f"Expected 200, got {r2.status_code}"
        
        data = r2.json()
        
        # Verify _id is not in response
        assert "_id" not in data, "MongoDB _id should be excluded"
        
        # Verify rule_findings have required fields
        findings = data.get("rule_findings", [])
        assert len(findings) > 0, "Expected at least one finding"
        
        for i, finding in enumerate(findings):
            # code_snippet field
            assert "code_snippet" in finding, f"Finding {i} missing code_snippet field"
            
            # suggested_fix field
            assert "suggested_fix" in finding, f"Finding {i} missing suggested_fix field"
            
            # line_number field
            assert "line_number" in finding, f"Finding {i} missing line_number field"
            
            # resource_name field
            assert "resource_name" in finding, f"Finding {i} missing resource_name field"
        
        # Print sample finding for verification
        sample = findings[0]
        print(f"✓ Assessment detail fields verified:")
        print(f"  - code_snippet: '{sample['code_snippet'][:50]}...' (len={len(sample['code_snippet'])})")
        print(f"  - suggested_fix present: {len(sample['suggested_fix']) > 0}")
        print(f"  - line_number: {sample['line_number']}")
        print(f"  - resource_name: {sample['resource_name']}")


class TestAgentPipeline:
    """Tests for 6-node agent pipeline execution"""
    
    def test_agent_trace_has_6_nodes(self):
        """Agent trace should have 6 nodes: Ingestion → Rule Engine → RAG → Analysis → Decision → Output"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": AWS_SSH_DIFF,
            "change_metadata": {"author": "test-pipeline"}
        })
        assert r.status_code == 200
        
        data = r.json()
        trace = data.get("agent_trace", [])
        
        assert len(trace) == 6, f"Expected 6 pipeline nodes, got {len(trace)}"
        
        # Verify node names
        expected_nodes = [
            "Node 1: Ingestion",
            "Node 2: Rule Engine",
            "Node 3: RAG Retrieval",
            "Node 4: Analysis Agent",
            "Node 5: Decision Agent",
            "Node 6: Output Agent"
        ]
        
        for i, expected_node in enumerate(expected_nodes):
            actual_node = trace[i]["node"]
            assert expected_node in actual_node, f"Expected '{expected_node}', got '{actual_node}'"
        
        print(f"✓ Agent pipeline: 6 nodes executed - {[t['node'] for t in trace]}")


class TestRAGEnrichment:
    """Tests for RAG enrichment results"""
    
    def test_assessment_has_rag_results(self):
        """Assessment should include CVE matches, ATT&CK techniques, policy controls"""
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": AWS_SSH_DIFF,
            "change_metadata": {}
        })
        assert r.status_code == 200
        
        data = r.json()
        
        # Verify RAG enrichment flag
        assert data["llm_rag_enriched"] == True, "Expected llm_rag_enriched=True"
        
        # Verify CVE matches exist
        assert len(data["cve_matches"]) > 0, "Expected CVE matches from RAG"
        
        # Verify ATT&CK techniques exist
        assert len(data["attack_techniques"]) > 0, "Expected ATT&CK techniques from RAG"
        
        # Verify policy controls exist
        assert len(data["policy_controls"]) > 0, "Expected policy controls from RAG"
        
        # Verify rag_sources tracking
        assert len(data["rag_sources"]) == 4, "Expected 4 RAG source entries"
        
        print(f"✓ RAG enrichment: cve={len(data['cve_matches'])}, attack={len(data['attack_techniques'])}, controls={len(data['policy_controls'])}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
