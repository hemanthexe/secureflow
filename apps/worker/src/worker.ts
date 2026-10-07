import { Worker } from 'bullmq';
import { PrismaClient } from '@prisma/client';
import { scan } from '@secureflow/scanners';
import { securityScore } from '@secureflow/risk';
import type { ScanRequest } from '@secureflow/shared';
const prisma = new PrismaClient();
const connection = { url: process.env.REDIS_URL ?? 'redis://localhost:6379' };
new Worker(
  'secureflow-scans',
  async (job) => {
    const { scanId, request } = job.data as { scanId: string; request: ScanRequest };
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'RUNNING' } });
    try {
      const result = scan(request);
      await prisma.finding.createMany({
        data: result.findings.map((f) => ({
          scanId,
          fingerprint: f.fingerprint,
          scanner: f.scanner,
          ruleId: f.ruleId,
          title: f.title,
          description: f.description,
          severity: f.severity,
          file: f.file ?? null,
          line: f.line ?? null,
          evidence: f.evidence ?? null,
        })),
        skipDuplicates: true,
      });
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          score: securityScore(result.findings),
          completedAt: new Date(),
        },
      });
      return result;
    } catch (error) {
      await prisma.scan.update({ where: { id: scanId }, data: { status: 'FAILED' } });
      throw error;
    }
  },
  { connection },
);
