import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  dedupeFindings,
  makeFinding,
  type Finding,
  type ScanRequest,
  type ScanResult,
  type ScannerKind,
} from '@secureflow/shared';

const textExtensions = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.py',
  '.go',
  '.java',
  '.cs',
  '.php',
  '.rb',
  '.yml',
  '.yaml',
  '.json',
  '.tf',
  '.dockerfile',
]);
const ignored = new Set(['node_modules', '.git', 'dist', 'coverage']);

function files(root: string): string[] {
  if (!existsSync(root)) return [];
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) return ignored.has(entry.name) ? [] : walk(path);
      return textExtensions.has(
        entry.name.toLowerCase().startsWith('dockerfile')
          ? '.dockerfile'
          : entry.name.slice(entry.name.lastIndexOf('.')),
      )
        ? [path]
        : [];
    });
  return statSync(root).isDirectory() ? walk(root) : [root];
}

function scanFile(path: string, kind: ScannerKind, root: string): Finding[] {
  let content = '';
  try {
    content = readFileSync(path, 'utf8');
  } catch {
    return [];
  }
  const rel = relative(root, path) || path;
  const result: Finding[] = [];
  const add = (
    ruleId: string,
    title: string,
    severity: Finding['severity'],
    description: string,
    line: number,
    evidence: string,
    remediation: string,
  ) =>
    result.push(
      makeFinding({
        scanner: kind,
        ruleId,
        title,
        severity,
        description,
        file: rel,
        line,
        evidence,
        remediation,
      }),
    );
  content.split(/\r?\n/).forEach((line, index) => {
    const n = index + 1;
    if (
      kind === 'secret' &&
      /(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----|(?:password|token|secret)\s*[:=]\s*["'][^"']{8,})/i.test(
        line,
      )
    )
      add(
        'hardcoded-secret',
        'Potential hardcoded secret',
        'critical',
        'A credential-like value is present in source.',
        n,
        line.trim().slice(0, 120),
        'Remove it, rotate the credential, and use a secret manager.',
      );
    if (kind === 'sast' && /(eval\s*\(|child_process\.exec\s*\(|innerHTML\s*=)/.test(line))
      add(
        'unsafe-execution',
        'Unsafe dynamic execution',
        'high',
        'Dynamic execution can enable code injection.',
        n,
        line.trim(),
        'Use safe APIs and validate untrusted input.',
      );
    if (kind === 'dependency' && /"(lodash|express|axios|jsonwebtoken)"\s*:\s*"\^?0\./.test(line))
      add(
        'outdated-dependency',
        'Potentially outdated dependency',
        'medium',
        'A dependency is pinned to a legacy major/minor version.',
        n,
        line.trim(),
        'Upgrade and review changelog/security advisories.',
      );
    if (
      (kind === 'iac' || kind === 'docker' || kind === 'kubernetes') &&
      /(privileged:\s*true|0\.0\.0\.0\/0|ADD\s+http:|latest["'\s]|runAsUser:\s*0)/i.test(line)
    )
      add(
        'insecure-config',
        'Insecure infrastructure configuration',
        'high',
        'Configuration weakens isolation or supply-chain guarantees.',
        n,
        line.trim(),
        'Pin versions, restrict network access, and enforce least privilege.',
      );
  });
  return result;
}

export function scan(request: ScanRequest): ScanResult {
  const started = Date.now();
  const selected = request.scanners ?? [
    'sast',
    'secret',
    'dependency',
    'iac',
    'docker',
    'kubernetes',
  ];
  const root = request.target;
  const targetFiles = files(root);
  const findings = dedupeFindings(
    selected.flatMap((kind) => targetFiles.flatMap((path) => scanFile(path, kind, root))),
  );
  return { findings, durationMs: Date.now() - started, scannedFiles: targetFiles.length };
}
