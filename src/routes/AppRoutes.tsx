import { Link, Navigate, Route, Routes } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';
import NewAnalysis from '../pages/NewAnalysis';
import AnalysisResults from '../pages/AnalysisResults';
import History from '../pages/History';
import About from '../pages/About';
import Settings from '../pages/Settings';
import EmptyState from '../components/common/EmptyState';

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<About />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/new" element={<NewAnalysis />} />
      <Route path="/analysis/:id" element={<AnalysisResults />} />
      <Route path="/history" element={<History />} />
      <Route path="/about" element={<Navigate to="/" replace />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="*" element={<EmptyState title="Page not found" description="This page does not exist." action={<Link to="/" className="btn">Go to home</Link>} />} />
    </Routes>
  );
}
