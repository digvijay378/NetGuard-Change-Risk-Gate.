"""NetGuard API backend tests"""
import pytest
import requests
import os

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")

TERRAFORM_DIFF = """
+ resource "aws_security_group_rule" "allow_ssh" {
+   type        = "ingress"
+   from_port   = 22
+   to_port     = 22
+   protocol    = "tcp"
+   cidr_blocks = ["0.0.0.0/0"]
+ }
"""


class TestHealth:
    def test_root(self):
        r = requests.get(f"{BASE_URL}/api/")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "running"

    def test_rag_health(self):
        r = requests.get(f"{BASE_URL}/api/v1/health/rag")
        assert r.status_code == 200
        data = r.json()
        assert "status" in data
        assert "collections" in data
        # Verify collections have docs
        for col, stats in data["collections"].items():
            assert stats.get("count", 0) > 0, f"Collection {col} has 0 documents"

    def test_stats(self):
        r = requests.get(f"{BASE_URL}/api/v1/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "by_risk_level" in data
        assert "recent_assessments" in data


class TestAssessments:
    def test_list_assessments(self):
        r = requests.get(f"{BASE_URL}/api/v1/assessments")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_assessment_github_pr(self):
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": TERRAFORM_DIFF,
            "change_metadata": {"author": "test-user"}
        })
        assert r.status_code == 200
        data = r.json()
        assert "assessment_id" in data
        assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert data["risk_level"] in ["HIGH", "CRITICAL"], f"Expected HIGH/CRITICAL for port 22 open, got {data['risk_level']}"
        assert data["block_merge"] == True
        assert len(data["rule_findings"]) > 0
        assert len(data["agent_trace"]) == 6  # 6-node pipeline
        return data["assessment_id"]

    def test_assessment_has_rag_results(self):
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": TERRAFORM_DIFF,
            "change_metadata": {}
        })
        assert r.status_code == 200
        data = r.json()
        assert data["llm_rag_enriched"] == True
        assert len(data["cve_matches"]) > 0
        assert len(data["attack_techniques"]) > 0

    def test_get_assessment_by_id(self):
        # Create one first
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": TERRAFORM_DIFF,
            "change_metadata": {}
        })
        assessment_id = r.json()["assessment_id"]

        # Get by ID
        r2 = requests.get(f"{BASE_URL}/api/v1/assessments/{assessment_id}")
        assert r2.status_code == 200
        data = r2.json()
        assert data["assessment_id"] == assessment_id

    def test_get_nonexistent_assessment(self):
        r = requests.get(f"{BASE_URL}/api/v1/assessments/nonexistent-id-12345")
        assert r.status_code == 404

    def test_empty_diff_returns_400(self):
        r = requests.post(f"{BASE_URL}/api/v1/assess", json={
            "change_source": "github_pr",
            "raw_diff": "   ",
            "change_metadata": {}
        })
        assert r.status_code == 400


class TestAuditLog:
    def test_audit_log(self):
        r = requests.get(f"{BASE_URL}/api/v1/audit")
        assert r.status_code == 200
        data = r.json()
        assert "entries" in data
        assert "total" in data
        assert isinstance(data["entries"], list)
