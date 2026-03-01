export const RISK_COLORS = {
  LOW: { bg: "rgba(16,185,129,0.15)", text: "#10b981", border: "rgba(16,185,129,0.3)" },
  MEDIUM: { bg: "rgba(14,165,233,0.15)", text: "#0ea5e9", border: "rgba(14,165,233,0.3)" },
  HIGH: { bg: "rgba(245,158,11,0.15)", text: "#f59e0b", border: "rgba(245,158,11,0.3)" },
  CRITICAL: { bg: "rgba(239,68,68,0.15)", text: "#ef4444", border: "rgba(239,68,68,0.4)" },
};

export default function RiskBadge({ level, size = "sm" }) {
  const c = RISK_COLORS[level] || RISK_COLORS.LOW;
  const pad = size === "lg" ? "4px 14px" : "2px 8px";
  const fs = size === "lg" ? 12 : 10;
  return (
    <span
      data-testid={`risk-badge-${level}`}
      style={{
        display: "inline-flex", alignItems: "center",
        padding: pad, borderRadius: 9999,
        background: c.bg, color: c.text,
        border: `1px solid ${c.border}`,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: fs, fontWeight: 700,
        letterSpacing: "0.08em", textTransform: "uppercase",
        boxShadow: level === "CRITICAL" ? `0 0 8px ${c.border}` : "none",
      }}
    >
      {level}
    </span>
  );
}
