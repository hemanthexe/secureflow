import { severityWeight, type Finding } from '@secureflow/shared';
export function securityScore(findings: Finding[]): number {
  const penalty = findings.reduce((sum, finding) => sum + severityWeight[finding.severity], 0);
  return Math.max(0, Math.round(100 - Math.min(100, penalty * 2)));
}
export function riskSummary(findings: Finding[]) {
  return findings.reduce<Record<string, number>>(
    (acc, finding) => ({ ...acc, [finding.severity]: (acc[finding.severity] ?? 0) + 1 }),
    {},
  );
}
