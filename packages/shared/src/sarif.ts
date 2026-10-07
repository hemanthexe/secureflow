import type { Finding } from './index.js';
export function toSarif(findings: Finding[]) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: { driver: { name: 'SecureFlow', version: '0.1.0' } },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: f.severity === 'info' ? 'note' : f.severity === 'low' ? 'warning' : 'error',
          message: { text: f.description },
          locations: f.file
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.file },
                    region: { startLine: f.line ?? 1 },
                  },
                },
              ]
            : undefined,
        })),
      },
    ],
  };
}
