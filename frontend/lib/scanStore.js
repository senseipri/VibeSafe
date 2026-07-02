// In-process scan store. Lives for the lifetime of the Next.js dev/server.
// Acceptable for an MVP; will be replaced with MongoDB persistence in P2.
import { buildMockReport } from './mockReport';

const g = globalThis;
if (!g.__vibesafe_scans) {
  g.__vibesafe_scans = new Map();
}
const store = g.__vibesafe_scans;

export function createScan(repoUrl) {
  const scanId = 'vs_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
  const report = buildMockReport(repoUrl, scanId);
  store.set(scanId, report);
  return report;
}

export function getScan(scanId) {
  return store.get(scanId) || null;
}
