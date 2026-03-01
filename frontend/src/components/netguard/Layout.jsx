import { NavLink, useLocation } from "react-router-dom";
import { Shield, LayoutDashboard, Plus, Database, ScrollText, Settings, Activity } from "lucide-react";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/assess", label: "New Assessment", icon: Plus },
  { to: "/knowledge-base", label: "Knowledge Base", icon: Database },
  { to: "/audit", label: "Audit Log", icon: ScrollText },
];

export default function Layout({ children }) {
  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#09090b" }}>
      {/* Sidebar */}
      <aside className="ng-sidebar">
        {/* Logo */}
        <div style={{ padding: "20px 16px 16px", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 4,
              background: "linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 16px rgba(14,165,233,0.4)"
            }}>
              <Shield size={18} color="#000" strokeWidth={2.5} />
            </div>
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: 13, color: "#fafafa", letterSpacing: "0.04em" }}>NETGUARD</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#0ea5e9", letterSpacing: "0.1em" }}>CHANGE-RISK GATE v2</div>
            </div>
          </div>
        </div>

        {/* Status bar */}
        <div style={{ padding: "8px 16px", display: "flex", alignItems: "center", gap: 6, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <span className="status-dot live" />
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#10b981" }}>SYSTEM ONLINE</span>
        </div>

        {/* Nav */}
        <nav style={{ padding: "8px 8px", flex: 1 }}>
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              data-testid={`nav-${label.toLowerCase().replace(/\s+/g, "-")}`}
              style={({ isActive }) => ({
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "9px 12px",
                borderRadius: 2,
                marginBottom: 2,
                color: isActive ? "#0ea5e9" : "#71717a",
                background: isActive ? "rgba(14,165,233,0.08)" : "transparent",
                borderLeft: isActive ? "2px solid #0ea5e9" : "2px solid transparent",
                fontFamily: "'Inter', sans-serif",
                fontSize: 13,
                fontWeight: isActive ? 600 : 400,
                textDecoration: "none",
                transition: "all 0.15s",
              })}
            >
              <Icon size={15} strokeWidth={1.8} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding: "12px 16px", borderTop: "1px solid rgba(255,255,255,0.08)" }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#52525b", letterSpacing: "0.05em" }}>
            AI: PLACEHOLDER MODE
          </div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#52525b" }}>
            RAG: ChromaDB Active
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="ng-main" style={{ flex: 1, padding: 0 }}>
        {children}
      </main>
    </div>
  );
}
