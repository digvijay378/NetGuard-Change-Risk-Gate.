import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import RiskBadge from "@/components/netguard/RiskBadge";
import { Search, Filter } from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const RISK_LEVELS = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const DECISIONS = ["ALL", "AUTO_APPROVE", "ESCALATE_TO_HUMAN"];

export default function AuditLog() {
  const navigate = useNavigate();
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterRisk, setFilterRisk] = useState("ALL");
  const [filterDecision, setFilterDecision] = useState("ALL");

  useEffect(() => {
    const load = async () => {
      try {
        const res = await axios.get(`${API}/v1/audit`);
        setEntries(res.data.entries || []);
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    };
    load();
  }, []);

  const filtered = entries.filter(e => {
    const matchSearch = !search ||
      e.assessment_id?.toLowerCase().includes(search.toLowerCase()) ||
      e.intent_summary?.toLowerCase().includes(search.toLowerCase()) ||
      e.change_source?.toLowerCase().includes(search.toLowerCase()) ||
      e.detected_stack?.toLowerCase().includes(search.toLowerCase());
    const matchRisk = filterRisk === "ALL" || e.risk_level === filterRisk;
    const matchDec = filterDecision === "ALL" || e.final_decision === filterDecision;
    return matchSearch && matchRisk && matchDec;
  });

  return (
    <div style={{ padding: "24px 28px" }} data-testid="audit-log-page">
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 20, fontWeight: 700, color: "#fafafa", margin: 0 }}>
            AUDIT LOG
          </h1>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#0ea5e9", marginTop: 2, letterSpacing: "0.08em" }}>
            FULL ASSESSMENT HISTORY · {entries.length} TOTAL ENTRIES
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="ng-card" style={{ padding: "12px 16px", marginBottom: 14, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 200 }}>
          <Search size={13} color="#52525b" />
          <input
            data-testid="audit-search"
            className="ng-input"
            placeholder="Search assessments..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ flex: 1, height: 34 }}
          />
        </div>

        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <Filter size={12} color="#52525b" />
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>Risk:</span>
          {RISK_LEVELS.map(r => (
            <button key={r}
              data-testid={`filter-risk-${r}`}
              onClick={() => setFilterRisk(r)}
              style={{
                fontFamily: "JetBrains Mono", fontSize: 10, padding: "3px 8px", borderRadius: 2, cursor: "pointer",
                border: filterRisk === r ? "1px solid #0ea5e9" : "1px solid rgba(255,255,255,0.08)",
                background: filterRisk === r ? "rgba(14,165,233,0.1)" : "transparent",
                color: filterRisk === r ? "#0ea5e9" : "#71717a",
              }}
            >{r}</button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>Decision:</span>
          {["ALL", "AUTO", "ESCALATED"].map((d, i) => {
            const val = ["ALL", "AUTO_APPROVE", "ESCALATE_TO_HUMAN"][i];
            return (
              <button key={d}
                data-testid={`filter-decision-${d}`}
                onClick={() => setFilterDecision(val)}
                style={{
                  fontFamily: "JetBrains Mono", fontSize: 10, padding: "3px 8px", borderRadius: 2, cursor: "pointer",
                  border: filterDecision === val ? "1px solid #0ea5e9" : "1px solid rgba(255,255,255,0.08)",
                  background: filterDecision === val ? "rgba(14,165,233,0.1)" : "transparent",
                  color: filterDecision === val ? "#0ea5e9" : "#71717a",
                }}
              >{d}</button>
            );
          })}
        </div>
      </div>

      {/* Table */}
      <div className="ng-card">
        {loading ? (
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}><div className="ng-spinner" /></div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 60, textAlign: "center", color: "#52525b" }}>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 13 }}>No audit entries found</div>
            {entries.length === 0 && (
              <div style={{ fontSize: 12, marginTop: 4 }}>Run your first assessment to populate the audit log</div>
            )}
          </div>
        ) : (
          <table className="ng-table" data-testid="audit-table">
            <thead>
              <tr>
                <th>Assessment ID</th>
                <th>Source</th>
                <th>Stack</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Decision</th>
                <th>RAG</th>
                <th>Outputs</th>
                <th>Timestamp</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.assessment_id}
                  style={{ cursor: "pointer" }}
                  data-testid={`audit-row-${e.assessment_id}`}
                  onClick={() => navigate(`/assessments/${e.assessment_id}`)}>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#0ea5e9" }}>{e.assessment_id}</span>
                  </td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#71717a", textTransform: "uppercase" }}>
                      {e.change_source?.replace("_", " ")}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#71717a", textTransform: "uppercase" }}>
                      {e.detected_stack}
                    </span>
                  </td>
                  <td><RiskBadge level={e.risk_level} /></td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 700, color: "#fafafa" }}>
                      {e.adjusted_risk_score}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontFamily: "JetBrains Mono", fontSize: 10, fontWeight: 700,
                      color: e.final_decision === "AUTO_APPROVE" ? "#10b981" : "#ef4444"
                    }}>
                      {e.final_decision === "AUTO_APPROVE" ? "AUTO" : "ESCALATED"}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: e.llm_rag_enriched ? "#10b981" : "#52525b" }}>
                      {e.llm_rag_enriched ? "YES" : "NO"}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {(e.output_targets || []).slice(0, 2).map(t => (
                        <span key={t} style={{ fontFamily: "JetBrains Mono", fontSize: 9, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 2, padding: "1px 4px", color: "#52525b" }}>{t.replace("_", " ")}</span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>
                      {new Date(e.created_at).toLocaleString()}
                    </span>
                  </td>
                  <td><span style={{ color: "#0ea5e9", fontSize: 12 }}>→</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Summary stats */}
      {filtered.length > 0 && (
        <div style={{ marginTop: 12, display: "flex", gap: 16, fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>
          <span>Showing {filtered.length} of {entries.length} entries</span>
          <span>Blocked: {filtered.filter(e => e.final_decision === "ESCALATE_TO_HUMAN").length}</span>
          <span>Auto-approved: {filtered.filter(e => e.final_decision === "AUTO_APPROVE").length}</span>
        </div>
      )}
    </div>
  );
}
