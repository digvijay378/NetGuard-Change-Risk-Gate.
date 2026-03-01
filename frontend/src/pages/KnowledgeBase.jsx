import { useState, useEffect } from "react";
import axios from "axios";
import { Database, RefreshCw, CheckCircle, AlertCircle } from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const COLLECTION_META = {
  cve_knowledge: { label: "CVE Knowledge", desc: "NIST NVD CVE database", icon: "🔴", update: "Nightly (NVD API v2.0)" },
  attack_techniques: { label: "ATT&CK Techniques", desc: "MITRE ATT&CK STIX 2.1", icon: "⚔️", update: "Monthly (MITRE CTI GitHub)" },
  policy_controls: { label: "Policy Controls", desc: "CIS Benchmarks + NIST 800-53", icon: "📋", update: "Quarterly (on release)" },
  change_history: { label: "Change History", desc: "Internal audit log", icon: "📈", update: "Real-time (every assessment)" },
};

export default function KnowledgeBase() {
  const [health, setHealth] = useState(null);
  const [seeding, setSeeding] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadHealth = async () => {
    try {
      const res = await axios.get(`${API}/v1/health/rag`);
      setHealth(res.data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadHealth(); }, []);

  const handleSeed = async () => {
    setSeeding(true);
    try {
      await axios.post(`${API}/v1/knowledge-base/seed`);
      await loadHealth();
    } catch (e) { console.error(e); }
    finally { setSeeding(false); }
  };

  return (
    <div style={{ padding: "24px 28px" }} data-testid="knowledge-base-page">
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 20, fontWeight: 700, color: "#fafafa", margin: 0 }}>
            KNOWLEDGE BASE
          </h1>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#0ea5e9", marginTop: 2, letterSpacing: "0.08em" }}>
            RAG PIPELINE · CHROMADB VECTOR STORE
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="ng-btn-ghost" onClick={loadHealth} data-testid="refresh-rag-btn">
            <RefreshCw size={12} /> Refresh
          </button>
          <button className="ng-btn-primary" onClick={handleSeed} disabled={seeding} data-testid="seed-kb-btn">
            {seeding ? "SEEDING..." : "SEED DATA"}
          </button>
        </div>
      </div>

      {/* Overall status */}
      {health && (
        <div className="ng-card" style={{ padding: 16, marginBottom: 20, display: "flex", alignItems: "center", gap: 12 }}>
          {health.status === "healthy"
            ? <CheckCircle size={18} color="#10b981" />
            : <AlertCircle size={18} color="#f59e0b" />}
          <div>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 700, color: health.status === "healthy" ? "#10b981" : "#f59e0b", textTransform: "uppercase" }}>
              {health.status} — All ChromaDB Collections {health.status === "healthy" ? "Online" : "Degraded"}
            </div>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginTop: 2 }}>
              Embedding: {health.embedding_model} · Last checked: {new Date(health.last_checked).toLocaleString()}
            </div>
          </div>
        </div>
      )}

      {/* Collection Cards */}
      {loading ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 60 }}><div className="ng-spinner" /></div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          {Object.entries(COLLECTION_META).map(([key, meta]) => {
            const col = health?.collections?.[key];
            const count = col?.count || 0;
            const status = col?.status || "unknown";
            return (
              <div key={key} className="ng-card animate-fade-in" data-testid={`collection-${key}`} style={{ padding: 20 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
                  <div>
                    <div style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 700, color: "#fafafa", marginBottom: 4 }}>
                      {meta.label}
                    </div>
                    <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b" }}>{meta.desc}</div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span className={`status-dot ${status === "healthy" ? "live" : "warning"}`} />
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: status === "healthy" ? "#10b981" : "#f59e0b", textTransform: "uppercase" }}>
                      {status}
                    </span>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
                  <div style={{ textAlign: "center", background: "rgba(255,255,255,0.02)", borderRadius: 2, padding: "10px 8px" }}>
                    <div style={{ fontFamily: "JetBrains Mono", fontSize: 22, fontWeight: 700, color: "#0ea5e9" }}>{count}</div>
                    <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: "#52525b", textTransform: "uppercase" }}>Documents</div>
                  </div>
                  <div style={{ textAlign: "center", background: "rgba(255,255,255,0.02)", borderRadius: 2, padding: "10px 8px" }}>
                    <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, fontWeight: 700, color: "#fafafa" }}>256-dim</div>
                    <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: "#52525b", textTransform: "uppercase" }}>Embeddings</div>
                  </div>
                </div>

                <div style={{ background: "rgba(255,255,255,0.02)", borderRadius: 2, padding: "8px 12px" }}>
                  <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: "#52525b", marginBottom: 2, textTransform: "uppercase" }}>Update Schedule</div>
                  <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#71717a" }}>{meta.update}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Architecture Info */}
      <div className="ng-card" style={{ padding: 20, marginTop: 14 }}>
        <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#52525b", marginBottom: 14, textTransform: "uppercase", letterSpacing: "0.08em" }}>
          RAG Pipeline Architecture
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          {[
            { label: "Embedding Model", value: "SimpleEmbeddingFunction", sub: "256-dim keyword-frequency · No download required" },
            { label: "Similarity Metric", value: "Cosine", sub: "ChromaDB default · hnsw:space=cosine" },
            { label: "Top-k Retrieval", value: "5 per query", sub: "Balanced context vs. precision" },
            { label: "Chunk Size", value: "800 tokens", sub: "100 token overlap · PRD spec" },
            { label: "Vector DB", value: "ChromaDB 1.5", sub: "Persistent local storage" },
            { label: "LLM Enrichment", value: "Claude 3.5 Sonnet", sub: "PLACEHOLDER — not connected" },
          ].map(item => (
            <div key={item.label} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 2, padding: 12 }}>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: "#52525b", marginBottom: 4, textTransform: "uppercase" }}>{item.label}</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 700, color: "#fafafa", marginBottom: 4 }}>{item.value}</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#71717a" }}>{item.sub}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
