import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import RiskBadge from "@/components/netguard/RiskBadge";
import PipelineViz from "@/components/netguard/PipelineViz";
import { ArrowLeft, CheckCircle, XCircle, Shield, AlertTriangle, Clock, ExternalLink, Code, Wrench, MapPin, ChevronDown, ChevronUp } from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const SEVERITY_COLOR = { CRITICAL: "#ef4444", HIGH: "#f59e0b", MEDIUM: "#0ea5e9", LOW: "#10b981" };

function Section({ title, children, testId }) {
  return (
    <div className="ng-card" style={{ marginBottom: 14 }} data-testid={testId}>
      <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.06)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {title}
      </div>
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  );
}

export default function AssessmentDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`${API}/v1/assessments/${id}`)
      .then(r => setData(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return (
    <div style={{ display: "flex", justifyContent: "center", padding: 80 }}>
      <div className="ng-spinner" />
    </div>
  );

  if (!data) return (
    <div style={{ padding: 40, textAlign: "center", color: "#52525b", fontFamily: "JetBrains Mono" }}>
      Assessment {id} not found.
    </div>
  );

  const isEscalated = data.final_decision === "ESCALATE_TO_HUMAN";

  return (
    <div style={{ padding: "24px 28px" }} data-testid="assessment-detail">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <button className="ng-btn-ghost" onClick={() => navigate(-1)} data-testid="back-btn">
          <ArrowLeft size={12} /> Back
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 18, fontWeight: 700, color: "#fafafa" }}>
              {data.assessment_id}
            </span>
            <RiskBadge level={data.risk_level} size="lg" />
            <span style={{
              fontFamily: "JetBrains Mono", fontSize: 11, fontWeight: 700, padding: "3px 10px",
              borderRadius: 2, border: `1px solid ${isEscalated ? "rgba(239,68,68,0.4)" : "rgba(16,185,129,0.4)"}`,
              background: isEscalated ? "rgba(239,68,68,0.1)" : "rgba(16,185,129,0.1)",
              color: isEscalated ? "#ef4444" : "#10b981",
            }}>
              {isEscalated ? "ESCALATED TO HUMAN" : "AUTO-APPROVED"}
            </span>
            {data.block_merge && (
              <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#ef4444", display: "flex", alignItems: "center", gap: 4 }}>
                <XCircle size={12} /> MERGE BLOCKED
              </span>
            )}
          </div>
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#52525b" }}>
            {data.change_source?.replace("_", " ").toUpperCase()} · {data.detected_stack?.toUpperCase()} · {new Date(data.created_at).toLocaleString()}
          </div>
        </div>
      </div>

      {/* Hero Risk Score Row */}
      <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 14, marginBottom: 14 }}>
        {/* Risk Gauge */}
        <div className="ng-card" style={{ padding: 20, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em" }}>Risk Score</div>
          <RiskGauge score={data.adjusted_risk_score} level={data.risk_level} />
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginTop: 8, textAlign: "center" }}>
            base: {data.base_risk_score} → adj: {data.adjusted_risk_score}
          </div>
        </div>

        {/* Intent + Narrative */}
        <div className="ng-card" style={{ padding: 16 }}>
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.08em" }}>Intent Summary</div>
          <div style={{ fontSize: 14, color: "#fafafa", marginBottom: 12, lineHeight: 1.6 }}>{data.intent_summary}</div>
          {data.score_adjustment_reason && (
            <div style={{ background: "rgba(14,165,233,0.06)", border: "1px solid rgba(14,165,233,0.2)", borderRadius: 2, padding: "8px 12px", fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a", marginBottom: 10 }}>
              Score Adjustment: {data.score_adjustment_reason}
            </div>
          )}
          {data.required_approvers?.length > 0 && (
            <div style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 2, padding: "8px 12px" }}>
              <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#ef4444" }}>REQUIRED APPROVERS: </span>
              <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#fafafa" }}>{data.required_approvers.join(" · ")}</span>
            </div>
          )}
        </div>
      </div>

      {/* Agent Pipeline */}
      <Section title="Agent Pipeline Execution Trace" testId="pipeline-section">
        <PipelineViz trace={data.agent_trace || []} />
        <div style={{ marginTop: 12 }}>
          {(data.agent_trace || []).map((step, i) => (
            <div key={i} style={{ display: "flex", gap: 12, marginBottom: 6, alignItems: "flex-start" }}>
              <CheckCircle size={12} color="#10b981" style={{ marginTop: 3, flexShrink: 0 }} />
              <div>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#0ea5e9" }}>{step.node}</span>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginLeft: 8 }}>{step.duration_ms}ms</span>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#71717a", marginTop: 2 }}>{step.output_summary}</div>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Rule Findings */}
      {data.rule_findings?.length > 0 && (
        <Section title={`Rule Findings (${data.rule_findings.length})`} testId="rule-findings-section">
          {data.rule_findings.map((f) => (
            <FindingCard key={`${f.rule_id}-${f.resource_name}`} finding={f} />
          ))}
        </Section>
      )}

      {/* CVE Matches */}
      {data.cve_matches?.length > 0 && (
        <Section title={`CVE Intelligence — NVD RAG Matches (${data.cve_matches.length})`} testId="cve-section">
          <table className="ng-table">
            <thead><tr><th>CVE ID</th><th>Title</th><th>CVSS</th><th>Description</th></tr></thead>
            <tbody>
              {data.cve_matches.map((c) => (
                <tr key={c.cve_id}>
                  <td><span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#ef4444" }}>{c.cve_id}</span></td>
                  <td><span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#fafafa" }}>{c.title}</span></td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 700, color: c.cvss >= 9 ? "#ef4444" : c.cvss >= 7 ? "#f59e0b" : "#10b981" }}>
                      {c.cvss}
                    </span>
                  </td>
                  <td><span style={{ fontSize: 11, color: "#71717a", lineHeight: 1.5 }}>{(c.description || "").slice(0, 180)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {/* ATT&CK Techniques */}
      {data.attack_techniques?.length > 0 && (
        <Section title={`MITRE ATT&CK Technique Mapping (${data.attack_techniques.length})`} testId="attack-section">
          <table className="ng-table">
            <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Relevance</th></tr></thead>
            <tbody>
              {data.attack_techniques.map((t) => (
                <tr key={t.technique_id}>
                  <td><span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#f59e0b" }}>{t.technique_id}</span></td>
                  <td><span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#fafafa" }}>{t.technique_name}</span></td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, textTransform: "capitalize", color: "#0ea5e9" }}>
                      {t.tactic?.replace(/-/g, " ")}
                    </span>
                  </td>
                  <td><span style={{ fontSize: 11, color: "#71717a", lineHeight: 1.5 }}>{(t.relevance || "").slice(0, 160)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      {/* Policy Controls */}
      {data.policy_controls?.length > 0 && (
        <Section title={`Applicable CIS/NIST Controls (${data.policy_controls.length})`} testId="controls-section">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {data.policy_controls.map((c) => (
              <div key={c.control_id} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 2, padding: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#10b981", fontWeight: 700 }}>{c.control_id}</span>
                  <span style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: "#52525b" }}>{c.framework}</span>
                </div>
                <div style={{ fontSize: 12, color: "#fafafa", marginBottom: 6 }}>{c.title}</div>
                {c.remediation && (
                  <div style={{ fontSize: 11, color: "#52525b", lineHeight: 1.5 }}>
                    <span style={{ color: "#71717a" }}>Remediation: </span>{c.remediation.slice(0, 150)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Blast Radius */}
      {data.blast_radius && (
        <Section title="Blast Radius Analysis" testId="blast-radius-section">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginBottom: 4 }}>SCOPE</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 20, fontWeight: 700, color: "#f59e0b" }}>{data.blast_radius.scope}</div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginBottom: 4 }}>IMPACTED ASSETS</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 20, fontWeight: 700, color: "#fafafa" }}>~{data.blast_radius.impacted_count}</div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginBottom: 4 }}>SERVICES</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#0ea5e9" }}>
                {(data.blast_radius.impacted_services || []).join(", ") || "—"}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 10, fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a" }}>{data.blast_radius.description}</div>
        </Section>
      )}

      {/* Validation Checklist */}
      {data.validation_checklist?.length > 0 && (
        <Section title="Validation Checklist" testId="checklist-section">
          {data.validation_checklist.map((item, i) => (
            <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
              <div style={{ width: 18, height: 18, border: "1px solid rgba(255,255,255,0.2)", borderRadius: 2, flexShrink: 0, marginTop: 2 }} />
              <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#d4d4d8", lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </Section>
      )}

      {/* Threat Narrative */}
      {data.threat_narrative && (
        <Section title="Threat Narrative (AI Analysis — PLACEHOLDER)" testId="narrative-section">
          <div style={{ fontSize: 13, color: "#a1a1aa", lineHeight: 1.8, whiteSpace: "pre-wrap" }}>
            {data.threat_narrative}
          </div>
        </Section>
      )}

      {/* Similar Incidents */}
      {data.similar_incidents?.length > 0 && (
        <Section title={`Similar Past Incidents (${data.similar_incidents.length})`} testId="incidents-section">
          {data.similar_incidents.map((inc) => (
            <div key={inc.assessment_id} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
              <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#0ea5e9" }}>{inc.assessment_id}</span>
              <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a" }}>{inc.outcome}</span>
              <RiskBadge level={inc.risk_level} />
            </div>
          ))}
        </Section>
      )}

      {/* Metadata */}
      <Section title="Change Metadata" testId="metadata-section">
        <pre style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a", margin: 0, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
          {JSON.stringify(data.change_metadata, null, 2)}
        </pre>
      </Section>
    </div>
  );
}

function RiskGauge({ score, level }) {
  const LEVEL_COLORS = { LOW: "#10b981", MEDIUM: "#0ea5e9", HIGH: "#f59e0b", CRITICAL: "#ef4444" };
  const color = LEVEL_COLORS[level] || "#52525b";
  const pct = Math.min(score / 100, 1);
  const r = 52;
  const circ = 2 * Math.PI * r;
  const dashoffset = circ * (1 - pct * 0.75);
  const strokeDasharray = `${circ * 0.75} ${circ * 0.25}`;

  return (
    <div className="risk-gauge-wrap" data-testid="risk-gauge">
      <svg width="120" height="80" viewBox="0 0 120 90">
        <circle cx="60" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"
          strokeDasharray={strokeDasharray} strokeLinecap="round"
          transform="rotate(-135, 60, 70)" />
        <circle cx="60" cy="70" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${circ * 0.75 * pct} ${circ * (1 - 0.75 * pct)}`} strokeLinecap="round"
          transform="rotate(-135, 60, 70)"
          style={{ transition: "stroke-dasharray 0.6s ease-out", filter: `drop-shadow(0 0 6px ${color})` }} />
        <text x="60" y="68" textAnchor="middle" fill={color}
          style={{ fontFamily: "JetBrains Mono", fontSize: 22, fontWeight: 700 }}>{score}</text>
      </svg>
    </div>
  );
}
