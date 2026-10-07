import type { Finding, Severity } from '@secureflow/shared';
export interface Policy {
  maxSeverity?: Severity;
  maxFindings?: number;
  blockedScanners?: string[];
}
const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export function evaluatePolicy(
  findings: Finding[],
  policy: Policy = {},
): { passed: boolean; reasons: string[] } {
  const reasons = [
    ...(policy.maxFindings !== undefined && findings.length > policy.maxFindings
      ? [`findings ${findings.length} exceeds ${policy.maxFindings}`]
      : []),
    ...(policy.maxSeverity && findings.some((f) => rank[f.severity] > rank[policy.maxSeverity!])
      ? [`severity exceeds ${policy.maxSeverity}`]
      : []),
    ...(policy.blockedScanners
      ? findings
          .filter((f) => policy.blockedScanners?.includes(f.scanner))
          .map((f) => `scanner blocked: ${f.scanner}`)
      : []),
  ];
  return { passed: reasons.length === 0, reasons };
}
