import { createHash } from 'node:crypto';

export const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof severities)[number];
export type ScannerKind = 'sast' | 'secret' | 'dependency' | 'iac' | 'docker' | 'kubernetes';
export type Role = 'admin' | 'analyst' | 'viewer';

export interface Finding {
  fingerprint: string;
  scanner: ScannerKind;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  file?: string;
  line?: number;
  evidence?: string;
  remediation?: string;
  cwe?: string;
  packageName?: string;
}

export interface ScanResult {
  findings: Finding[];
  durationMs: number;
  scannedFiles: number;
}

export interface ScanRequest {
  target: string;
  scanners?: ScannerKind[];
  commitSha?: string;
}

export const fingerprint = (...parts: string[]): string =>
  createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 32);

export const makeFinding = (input: Omit<Finding, 'fingerprint'>): Finding => ({
  ...input,
  fingerprint: fingerprint(
    input.scanner,
    input.ruleId,
    input.file ?? '',
    input.line?.toString() ?? '',
    input.evidence ?? '',
  ),
});

export const dedupeFindings = (findings: Finding[]): Finding[] => [
  ...new Map(findings.map((finding) => [finding.fingerprint, finding])).values(),
];

export const severityWeight: Record<Severity, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

export { toSarif } from './sarif.js';
