import { CheckCircle, Loader, Circle, XCircle } from "lucide-react";

const NODES = [
  { label: "Ingestion", short: "01" },
  { label: "Rule Engine", short: "02" },
  { label: "RAG Retrieval", short: "03" },
  { label: "Analysis", short: "04" },
  { label: "Decision", short: "05" },
  { label: "Output", short: "06" },
];

function getNodeStatus(trace, idx) {
  if (!trace || trace.length === 0) return "pending";
  if (idx < trace.length) {
    return trace[idx]?.status || "completed";
  }
  return "pending";
}

export default function PipelineViz({ trace = [], compact = false }) {
  return (
    <div data-testid="pipeline-viz" style={{ display: "flex", alignItems: "flex-start", gap: 0, width: "100%", overflowX: "auto", paddingBottom: 4 }}>
      {NODES.map((node, idx) => {
        const status = getNodeStatus(trace, idx);
        const isLast = idx === NODES.length - 1;
        const step = trace[idx];
        return (
          <div key={node.short} style={{ display: "flex", alignItems: "flex-start", flex: 1, minWidth: compact ? 60 : 80 }}>
            <div className="pipeline-node" title={step?.output_summary || node.label}>
              <div className={`pipeline-node-circle ${status}`}>
                {status === "completed" ? <CheckCircle size={14} /> :
                 status === "running" ? <Loader size={14} className="animate-spin" /> :
                 status === "failed" ? <XCircle size={14} /> :
                 <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9 }}>{node.short}</span>}
              </div>
              {!compact && (
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 9, color: status === "completed" ? "#10b981" : status === "running" ? "#0ea5e9" : "#52525b",
                  textAlign: "center", letterSpacing: "0.04em", lineHeight: 1.3,
                  textTransform: "uppercase"
                }}>
                  {node.label}
                </span>
              )}
            </div>
            {!isLast && (
              <div className={`pipeline-connector ${idx < trace.length - 1 ? "active" : ""}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}
