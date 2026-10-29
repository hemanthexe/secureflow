import Fastify from 'fastify';
import cors from '@fastify/cors';
import sensible from '@fastify/sensible';
import jwt from '@fastify/jwt';
import { PrismaClient } from '@prisma/client';
import { Queue } from 'bullmq';
import { evaluatePolicy } from '@secureflow/policy';
import { securityScore } from '@secureflow/risk';
import { toSarif, type Finding, type ScanRequest } from '@secureflow/shared';

type PersistedFinding = {
  fingerprint: string;
  scanner: string;
  ruleId: string;
  title: string;
  description: string;
  severity: string;
  file: string | null;
  line: number | null;
  evidence: string | null;
};

const toSharedFinding = (finding: PersistedFinding): Finding => ({
  ...finding,
  file: finding.file ?? '',
  line: finding.line ?? 0,
  evidence: finding.evidence ?? '',
  scanner: finding.scanner as Finding['scanner'],
  severity: finding.severity as Finding['severity'],
});

const app = Fastify({ logger: true });
const prisma = new PrismaClient();
const redisUrl = process.env.REDIS_URL ?? 'redis://localhost:6379';
const queue = new Queue('secureflow-scans', { connection: { url: redisUrl } });
await app.register(cors, { origin: true });
await app.register(sensible);
await app.register(jwt, { secret: process.env.JWT_SECRET ?? 'development-only-change-me' });

app.get('/health', async () => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return { ok: true, dependencies: { postgres: 'up', redis: 'configured' } };
  } catch {
    throw app.httpErrors.serviceUnavailable(
      'Postgres is unavailable; start docker compose or configure DATABASE_URL',
    );
  }
});
app.post<{ Body: ScanRequest }>('/scans', async (request, reply) => {
  try {
    const project = await prisma.project.create({
      data: { name: request.body.target, repoUrl: request.body.target },
    });
    const scan = await prisma.scan.create({
      data: { projectId: project.id, target: request.body.target },
    });
    await queue.add('scan', { scanId: scan.id, request: request.body });
    return reply.code(202).send({ id: scan.id, status: scan.status });
  } catch (error) {
    request.log.error(error);
    throw app.httpErrors.serviceUnavailable(
      'Persistence or Redis unavailable; run docker compose up -d postgres redis',
    );
  }
});
app.get<{ Params: { id: string } }>('/scans/:id', async (request) => {
  const scan = await prisma.scan.findUnique({
    where: { id: request.params.id },
    include: { findings: true },
  });
  if (!scan) throw app.httpErrors.notFound();
  return {
    ...scan,
    policy: evaluatePolicy(scan.findings.map((f: PersistedFinding) => toSharedFinding(f))),
    score: scan.score,
  };
});
app.get<{ Params: { id: string } }>('/scans/:id/sarif', async (request, reply) => {
  const scan = await prisma.scan.findUnique({
    where: { id: request.params.id },
    include: { findings: true },
  });
  if (!scan) throw app.httpErrors.notFound();
  return reply.type('application/sarif+json').send(
    toSarif(scan.findings.map((f: PersistedFinding) => toSharedFinding(f))),
  );
});
app.get('/dashboard', async () => {
  const scans = await prisma.scan.findMany({
    orderBy: { createdAt: 'desc' },
    take: 20,
    include: { findings: true },
  });
  return {
    scans: scans.map((s: { id: string; status: string; score: number | null; findings: unknown[]; createdAt: Date }) => ({
      id: s.id,
      status: s.status,
      score: s.score,
      findings: s.findings.length,
      createdAt: s.createdAt,
    })),
  };
});
const port = Number(process.env.API_PORT ?? 3000);
app.listen({ port, host: '0.0.0.0' }).catch((error) => {
  app.log.error(error);
  process.exit(1);
});
