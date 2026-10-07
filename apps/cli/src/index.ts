import { writeFileSync } from 'node:fs';
import { scan } from '@secureflow/scanners';
import { securityScore } from '@secureflow/risk';
import { toSarif } from '@secureflow/shared';
const [command, target = '.'] = process.argv.slice(2);
if (command !== 'scan') {
  console.log('Usage: secureflow scan <path>');
  process.exit(0);
}
const result = scan({ target });
console.log(
  `SecureFlow: ${result.scannedFiles} files, ${result.findings.length} findings, score ${securityScore(result.findings)}/100`,
);
for (const finding of result.findings)
  console.log(
    `${finding.severity.toUpperCase()} ${finding.file ?? ''}:${finding.line ?? ''} ${finding.title}`,
  );
if (process.env.SARIF_OUT)
  writeFileSync(process.env.SARIF_OUT, JSON.stringify(toSarif(result.findings), null, 2));
process.exitCode = result.findings.some((f) => f.severity === 'critical') ? 1 : 0;
