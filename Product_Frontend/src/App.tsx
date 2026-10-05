import { useState, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { TopNav } from './pages/ATLAS/components/TopNav';
import { ApprovalModal } from './pages/ATLAS/components/ApprovalModal';
import { Dashboard } from './pages/ATLAS/Dashboard/Dashboard';
import { AssessmentWorkspace } from './pages/ATLAS/AssessmentWorkspace/VulnerabilityAssessment';
import { RiskAnalysis } from './pages/ATLAS/RiskAnalysis/RiskAnalysis';
import { Reports } from './pages/ATLAS/Reports/Reports';
import { mockVulnerabilities } from './pages/ATLAS/data';
import type { View, Vulnerability } from './pages/ATLAS/types';
import type { Synthesis } from './pages/ATLAS/services/orchestrationApi';

function App() {
  const [view, setView] = useState<View>('dashboard');
  const [assessmentActive, setAssessmentActive] = useState(false);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [vulns, setVulns] = useState<Vulnerability[]>(mockVulnerabilities);
  // Holds the executive_summary / remediation_plan / attackGraph / attackPath
  // returned by Stage 2 (/api/orchestration/assess or /finalize).
  const [synthesis, setSynthesis] = useState<Synthesis | null>(null);

  // Resolves the Promise<boolean> that AssessmentWorkspace is awaiting on
  // "Request Approval". Set right before opening the modal, called (and
  // cleared) by either the grant or deny path — never left dangling, so
  // the awaiting call in AssessmentWorkspace can't hang forever.
  const approvalResolverRef = useRef<((approved: boolean) => void) | null>(null);

  const handleStartAssessment = () => {
    setAssessmentActive(true);
    setView('assessment');
  };

  const handleAssessmentComplete = (results: Vulnerability[], resultSynthesis?: Synthesis) => {
    setVulns(results);
    if (resultSynthesis) setSynthesis(resultSynthesis);
    // Real Stage 2 data (from either exploit_mode or skip_pentest_and_finalize)
    // is what should drive Risk Analysis — not a separate fake console.
    setView('risk');
  };

  /**
   * Matches AssessmentWorkspace's `onPentestChoice: (choice) => Promise<boolean>`.
   * 'skip' needs no human approval — resolves true immediately.
   * 'request' opens the real approval modal and blocks until the person
   * actually grants or denies it; nothing exploitation-related runs until
   * this resolves true.
   */
  const handlePentestChoice = (choice: 'request' | 'skip'): Promise<boolean> => {
    if (choice === 'skip') {
      return Promise.resolve(true);
    }
    setApprovalOpen(true);
    return new Promise<boolean>((resolve) => {
      approvalResolverRef.current = resolve;
    });
  };

  const handleApprovalGranted = () => {
    setApprovalOpen(false);
    approvalResolverRef.current?.(true);
    approvalResolverRef.current = null;
    // Deliberately NOT navigating to a separate pentest page here.
    // AssessmentWorkspace stays mounted and now makes the real
    // runAssessPhase() call itself, with its own live progress UI —
    // that's the actual exploitation run, not a canned animation.
  };

  const handleApprovalDenied = () => {
    setApprovalOpen(false);
    approvalResolverRef.current?.(false);
    approvalResolverRef.current = null;
    // Resolves false -> AssessmentWorkspace stays at the approval gate
    // so the user can pick again instead of the request silently hanging.
  };

  const handleNavigate = (next: View) => {
    if (next === 'pentest') return; // no longer a standalone routable page
    setView(next);
  };

  return (
    <div className="min-h-screen bg-surface-900 text-crimson-100">
      <TopNav
        view={view}
        onNavigate={handleNavigate}
        assessmentActive={assessmentActive}
        pentestActive={false}
      />

      <main>
        <AnimatePresence mode="wait">
          <motion.div
            key={view}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
          >
            {view === 'dashboard' && (
              <Dashboard
                onStartAssessment={handleStartAssessment}
                onNavigate={handleNavigate}
                onSelectAssessment={() => setView('risk')}
              />
            )}
            {view === 'assessment' && (
              <AssessmentWorkspace
                onComplete={handleAssessmentComplete}
                onPentestChoice={handlePentestChoice}
              />
            )}
            {view === 'risk' && (
              <RiskAnalysis vulnerabilities={vulns} />
            )}
            {view === 'reports' && <Reports />}
          </motion.div>
        </AnimatePresence>
      </main>

      <ApprovalModal
        open={approvalOpen}
        onClose={handleApprovalDenied}
        onGranted={handleApprovalGranted}
      />
    </div>
  );
}

export default App;