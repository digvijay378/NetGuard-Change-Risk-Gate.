import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import PipelineViz from "@/components/netguard/PipelineViz";
import { GitPullRequest, Shield, Ticket, LayoutList, Router, Server } from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const SOURCES = [
  { id: "github_pr", label: "GitHub PR", icon: GitPullRequest },
  { id: "firewall_api", label: "Firewall Rule", icon: Shield },
  { id: "network_device", label: "Network Device", icon: Router },
  { id: "kubernetes", label: "Kubernetes", icon: Server },
  { id: "servicenow", label: "ServiceNow", icon: Ticket },
  { id: "jira", label: "Jira", icon: LayoutList },
];

const SAMPLE_DIFFS = {
  github_pr: `--- a/terraform/aws/security_groups.tf
+++ b/terraform/aws/security_groups.tf
@@ -1,10 +1,15 @@
 resource "aws_security_group" "web_tier" {
   name        = "web-tier-sg"
   description = "Security group for web tier"
   vpc_id      = aws_vpc.main.id

+  ingress {
+    from_port   = 22
+    to_port     = 22
+    protocol    = "tcp"
+    cidr_blocks = ["0.0.0.0/0"]
+    description = "SSH from anywhere"
+  }
+
   egress {
     from_port   = 0
     to_port     = 0
     protocol    = "-1"
     cidr_blocks = ["0.0.0.0/0"]
   }
 }`,
  firewall_api: `resource "aws_security_group_rule" "admin_rdp" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.bastion.id
}`,
  servicenow: `Change Request: Modify production NSG to allow RDP ingress from Internet source for emergency admin access. 
Resource: azurerm_network_security_group.prod_nsg
Priority rule: 100, Direction: Inbound, Protocol: TCP, Port: 3389, Source: Internet, Destination: VirtualNetwork, Action: Allow`,
  jira: `[INFRA-4421] Add IAM role for Lambda deployment

Changes:
- resource "aws_iam_role_policy" "lambda_policy" {
+   policy = jsonencode({
+     Statement = [{
+       Action = ["*"]
+       Effect = "Allow"  
+       Resource = "*"
+     }]
+   })
+ }`,
};

const SAMPLE_META = {
  github_pr: { author: "john.doe", pr_url: "https://github.com/acme/infra/pull/442", pr_number: 442, base_branch: "main" },
  firewall_api: { author: "ops-bot", rule_id: "FW-992", ticket: "CHG-1204" },
  servicenow: { ticket_id: "CHG0012045", requester: "jane.smith", priority: "2 - High" },
  jira: { issue_key: "INFRA-4421", reporter: "dev-pipeline", sprint: "2026-Q1-Sprint-3" },
};

export default function NewAssessment() {
  const navigate = useNavigate();
  const [source, setSource] = useState("github_pr");
  const [diff, setDiff] = useState(SAMPLE_DIFFS.github_pr);
  const [meta, setMeta] = useState(JSON.stringify(SAMPLE_META.github_pr, null, 2));
  const [loading, setLoading] = useState(false);
  const [trace, setTrace] = useState([]);
  const [error, setError] = useState(null);

  const handleSourceChange = (src) => {
    setSource(src);
    setDiff(SAMPLE_DIFFS[src]);
    setMeta(JSON.stringify(SAMPLE_META[src], null, 2));
    setError(null);
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    setTrace([]);

    // Simulate node-by-node progress
    const nodeNames = ["Node 1: Ingestion", "Node 2: Rule Engine", "Node 3: RAG Retrieval",
                       "Node 4: Analysis", "Node 5: Decision", "Node 6: Output"];
    for (let i = 0; i < nodeNames.length; i++) {
      await new Promise(r => setTimeout(r, 280));
      setTrace(t => [...t, { node: nodeNames[i], status: i < nodeNames.length - 1 ? "completed" : "running" }]);
    }

    try {
      let metaObj = {};
      try { metaObj = JSON.parse(meta); } catch (_) {}

      const res = await axios.post(`${API}/v1/assess`, {
        change_source: source,
        raw_diff: diff,
        change_metadata: metaObj,
      });
      setTrace(Array(6).fill(null).map((_, i) => ({ status: "completed" })));
      navigate(`/assessments/${res.data.assessment_id}`);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
      setTrace(t => t.map((s, i) => i === t.length - 1 ? { ...s, status: "failed" } : s));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "24px 28px" }} data-testid="new-assessment-page">
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 20, fontWeight: 700, color: "#fafafa", margin: 0 }}>
          NEW ASSESSMENT
        </h1>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#0ea5e9", marginTop: 2, letterSpacing: "0.08em" }}>
          SUBMIT INFRASTRUCTURE CHANGE FOR AI RISK ANALYSIS
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 16, alignItems: "start" }}>
        {/* Left: Form */}
        <div>
          {/* Source Tabs */}
          <div className="ng-card" style={{ padding: 16, marginBottom: 14 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.08em" }}>Change Source</div>
            <div style={{ display: "flex", gap: 6 }}>
              {SOURCES.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  data-testid={`source-tab-${id}`}
                  onClick={() => handleSourceChange(id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    padding: "7px 14px", borderRadius: 2, cursor: "pointer",
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600,
                    border: source === id ? "1px solid #0ea5e9" : "1px solid rgba(255,255,255,0.08)",
                    background: source === id ? "rgba(14,165,233,0.1)" : "transparent",
                    color: source === id ? "#0ea5e9" : "#71717a",
                    transition: "all 0.15s",
                  }}
                >
                  <Icon size={12} />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Diff Input */}
          <div className="ng-card" style={{ padding: 16, marginBottom: 14 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              {source === "github_pr" ? "Git Diff / Terraform HCL" :
               source === "firewall_api" ? "Firewall Rule Content" :
               source === "servicenow" ? "Change Request Description" :
               "Jira Issue Description"}
            </div>
            <textarea
              data-testid="diff-input"
              className="ng-input"
              rows={16}
              value={diff}
              onChange={(e) => setDiff(e.target.value)}
              placeholder="Paste your infrastructure change diff here..."
              style={{ resize: "vertical", lineHeight: 1.6 }}
            />
          </div>

          {/* Metadata */}
          <div className="ng-card" style={{ padding: 16, marginBottom: 14 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Change Metadata (JSON)
            </div>
            <textarea
              data-testid="meta-input"
              className="ng-input"
              rows={5}
              value={meta}
              onChange={(e) => setMeta(e.target.value)}
              style={{ resize: "vertical", lineHeight: 1.6 }}
            />
          </div>

          {error && (
            <div data-testid="assessment-error" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 2, padding: "10px 14px", color: "#ef4444", fontFamily: "JetBrains Mono", fontSize: 12, marginBottom: 14 }}>
              Error: {error}
            </div>
          )}

          <button
            data-testid="submit-assessment-btn"
            className="ng-btn-primary"
            onClick={handleSubmit}
            disabled={loading || !diff.trim()}
            style={{ width: "100%", padding: "12px 20px" }}
          >
            {loading ? "RUNNING AGENT PIPELINE..." : "EXECUTE RISK ASSESSMENT"}
          </button>
        </div>

        {/* Right: Pipeline status + info */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Pipeline Visualization */}
          <div className="ng-card" style={{ padding: 16 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", marginBottom: 12, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Agent Pipeline Status
            </div>
            <PipelineViz trace={trace} compact={true} />
            {loading && (
              <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8 }}>
                <div className="ng-spinner" />
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#0ea5e9" }}>Running analysis...</span>
              </div>
            )}
            {!loading && trace.length === 0 && (
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#52525b", marginTop: 10 }}>
                Pipeline idle — submit a change to begin
              </div>
            )}
          </div>

          {/* Info Cards */}
          <div className="ng-card" style={{ padding: 16 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Analysis Includes
            </div>
            {[
              { label: "CVE Lookup", desc: "NVD database via RAG" },
              { label: "ATT&CK Mapping", desc: "MITRE technique retrieval" },
              { label: "Policy Check", desc: "CIS/NIST control validation" },
              { label: "History Correlation", desc: "Past incident matching" },
              { label: "AI Analysis", desc: "Claude 3.5 Sonnet [PLACEHOLDER]" },
            ].map(item => (
              <div key={item.label} style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, paddingBottom: 8, borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#fafafa" }}>{item.label}</span>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>{item.desc}</span>
              </div>
            ))}
          </div>

          {/* Decision Rules */}
          <div className="ng-card" style={{ padding: 16 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Decision Rules
            </div>
            {[
              { range: "0–39", level: "LOW", decision: "AUTO-APPROVE", color: "#10b981" },
              { range: "40–69", level: "MEDIUM", decision: "AUTO-APPROVE + FLAG", color: "#0ea5e9" },
              { range: "70–89", level: "HIGH", decision: "ESCALATE", color: "#f59e0b" },
              { range: "90–100", level: "CRITICAL", decision: "ESCALATE + LOCK", color: "#ef4444" },
            ].map(d => (
              <div key={d.range} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: d.color }}>{d.range} → {d.level}</span>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>{d.decision}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
