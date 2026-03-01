import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from "recharts";
import RiskBadge from "@/components/netguard/RiskBadge";
import PipelineViz from "@/components/netguard/PipelineViz";
import { Shield, AlertTriangle, CheckCircle, XCircle, Activity, TrendingUp, Zap } from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const RISK_COLORS = { LOW: "#10b981", MEDIUM: "#0ea5e9", HIGH: "#f59e0b", CRITICAL: "#ef4444" };
const DECISION_COLORS = { AUTO_APPROVE: "#10b981", ESCALATE_TO_HUMAN: "#ef4444" };

function StatCard({ label, value, sub, color, icon: Icon, testId }) {
  return (
    <div className="ng-card animate-fade-in" data-testid={testId} style={{ padding: "16px 20px", flex: 1, minWidth: 140 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</span>
        {Icon && <Icon size={14} color={color || "#52525b"} />}
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 28, fontWeight: 700, color: color || "#fafafa" }} className="animate-count">{value}</div>
      {sub && <div style={{ fontSize: 11, color: "#52525b", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload?.length) {
    return (
      <div style={{ background: "#121214", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 2, padding: "8px 12px" }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#71717a", marginBottom: 4 }}>{label}</div>
        {payload.map((p) => (
          <div key={p.name} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: p.color }}>
            {p.name}: {p.value}
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await axios.get(`${API}/v1/stats`);
        setStats(res.data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    load();
    const interval = setInterval(load, 15000); // poll every 15s
    return () => clearInterval(interval);
  }, []);

  const riskData = stats ? [
    { name: "LOW", value: stats.by_risk_level?.LOW || 0 },
    { name: "MEDIUM", value: stats.by_risk_level?.MEDIUM || 0 },
    { name: "HIGH", value: stats.by_risk_level?.HIGH || 0 },
    { name: "CRITICAL", value: stats.by_risk_level?.CRITICAL || 0 },
  ] : [];

  const recentScores = stats?.recent_assessments?.slice().reverse().map((a, i) => ({
    name: `#${i + 1}`, score: a.adjusted_risk_score, level: a.risk_level
  })) || [];

  const sourceData = stats ? [
    { name: "github_pr", value: stats.by_source?.github_pr || 0 },
    { name: "firewall_api", value: stats.by_source?.firewall_api || 0 },
    { name: "servicenow", value: stats.by_source?.servicenow || 0 },
    { name: "jira", value: stats.by_source?.jira || 0 },
  ].filter(d => d.value > 0) : [];

  return (
    <div style={{ padding: "24px 28px" }} data-testid="dashboard">
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 20, fontWeight: 700, color: "#fafafa", margin: 0 }}>
            SECURITY DASHBOARD
          </h1>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#0ea5e9", marginTop: 2, letterSpacing: "0.08em" }}>
            NETGUARD CHANGE-RISK GATE v2.0 · AI-ENHANCED EDITION
          </div>
        </div>
        <button
          data-testid="new-assessment-btn"
          className="ng-btn-primary"
          onClick={() => navigate("/assess")}
        >
          + New Assessment
        </button>
      </div>

      {loading ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 80 }}>
          <div className="ng-spinner" />
        </div>
      ) : (
        <>
          {/* Stats Row */}
          <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
            <StatCard label="Total Assessments" value={stats?.total || 0} icon={Activity} testId="stat-total" />
            <StatCard label="Auto-Approved" value={stats?.auto_approved || 0} color="#10b981" icon={CheckCircle} sub="LOW + MEDIUM" testId="stat-approved" />
            <StatCard label="Escalated" value={stats?.escalated || 0} color="#f59e0b" icon={AlertTriangle} sub="HIGH + CRITICAL" testId="stat-escalated" />
            <StatCard label="Blocked" value={stats?.blocked || 0} color="#ef4444" icon={XCircle} sub="Merge blocked" testId="stat-blocked" />
          </div>

          {/* Charts Row */}
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12, marginBottom: 20 }}>
            {/* Risk Score Trend */}
            <div className="ng-card" style={{ padding: 16 }}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 14 }}>
                Risk Score Trend — Recent Assessments
              </div>
              <ResponsiveContainer width="100%" height={140}>
                <LineChart data={recentScores}>
                  <XAxis dataKey="name" tick={{ fill: "#52525b", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fill: "#52525b", fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Line type="monotone" dataKey="score" stroke="#0ea5e9" strokeWidth={2} dot={{ fill: "#0ea5e9", r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Risk Distribution Pie */}
            <div className="ng-card" style={{ padding: 16 }}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>
                Risk Distribution
              </div>
              {riskData.some(d => d.value > 0) ? (
                <ResponsiveContainer width="100%" height={140}>
                  <PieChart>
                    <Pie data={riskData} dataKey="value" cx="50%" cy="50%" outerRadius={50} innerRadius={25}>
                      {riskData.map((entry) => (
                        <Cell key={entry.name} fill={RISK_COLORS[entry.name]} />
                      ))}
                    </Pie>
                    <Legend iconType="circle" iconSize={8} formatter={(v) => (
                      <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: RISK_COLORS[v] }}>{v}</span>
                    )} />
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: 140, color: "#52525b", gap: 8 }}>
                  <Shield size={24} />
                  <span style={{ fontFamily: "JetBrains Mono", fontSize: 11 }}>No assessments yet</span>
                </div>
              )}
            </div>
          </div>

          {/* Pipeline Visualization */}
          <div className="ng-card" style={{ padding: 16, marginBottom: 20 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
              Agent Pipeline — 6-Node LangGraph Architecture
            </div>
            <PipelineViz
              trace={stats?.recent_assessments?.[0] ? Array(6).fill(null).map((_, i) => ({ status: "completed" })) : []}
            />
          </div>

          {/* Recent Assessments Table */}
          <div className="ng-card">
            <div style={{ padding: "12px 16px", borderBottom: "1px solid rgba(255,255,255,0.08)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#52525b", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Recent Assessments
              </span>
              <button className="ng-btn-ghost" onClick={() => navigate("/audit")}>View All</button>
            </div>
            {stats?.recent_assessments?.length > 0 ? (
              <table className="ng-table" data-testid="recent-assessments-table">
                <thead>
                  <tr>
                    <th>Assessment ID</th>
                    <th>Source</th>
                    <th>Stack</th>
                    <th>Risk</th>
                    <th>Score</th>
                    <th>Decision</th>
                    <th>Time</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_assessments.map((a) => (
                    <tr key={a.assessment_id} style={{ cursor: "pointer" }}
                      onClick={() => navigate(`/assessments/${a.assessment_id}`)}>
                      <td>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: "#0ea5e9" }}>
                          {a.assessment_id}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a" }}>
                          {a.change_source?.replace("_", " ")}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a", textTransform: "uppercase" }}>
                          {a.detected_stack}
                        </span>
                      </td>
                      <td><RiskBadge level={a.risk_level} /></td>
                      <td>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 700, color: "#fafafa" }}>
                          {a.adjusted_risk_score}
                        </span>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>/100</span>
                      </td>
                      <td>
                        <span style={{
                          fontFamily: "JetBrains Mono", fontSize: 10, fontWeight: 600,
                          color: a.final_decision === "AUTO_APPROVE" ? "#10b981" : "#ef4444"
                        }}>
                          {a.final_decision === "AUTO_APPROVE" ? "AUTO-APPROVED" : "ESCALATED"}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>
                          {new Date(a.created_at).toLocaleString()}
                        </span>
                      </td>
                      <td>
                        <span style={{ color: "#0ea5e9", fontSize: 12 }}>→</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ padding: 40, textAlign: "center" }}>
                <img
                  src="https://images.unsplash.com/photo-1680992046617-e2e35451bcdb?w=120&q=60"
                  alt="All clear"
                  style={{ width: 80, height: 80, objectFit: "cover", borderRadius: 2, marginBottom: 16, opacity: 0.5 }}
                />
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 13, color: "#52525b" }}>No assessments yet</div>
                <div style={{ fontSize: 12, color: "#3f3f46", marginTop: 4, marginBottom: 16 }}>Submit your first infrastructure change to begin</div>
                <button className="ng-btn-primary" onClick={() => navigate("/assess")}>
                  Submit Change
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
