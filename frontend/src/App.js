import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "@/components/netguard/Layout";
import Dashboard from "@/pages/Dashboard";
import NewAssessment from "@/pages/NewAssessment";
import AssessmentDetail from "@/pages/AssessmentDetail";
import KnowledgeBase from "@/pages/KnowledgeBase";
import AuditLog from "@/pages/AuditLog";

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/assess" element={<NewAssessment />} />
          <Route path="/assessments/:id" element={<AssessmentDetail />} />
          <Route path="/knowledge-base" element={<KnowledgeBase />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
