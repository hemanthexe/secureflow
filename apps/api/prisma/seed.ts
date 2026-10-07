import { PrismaClient, Role } from '@prisma/client';
const prisma = new PrismaClient();
await prisma.user.upsert({
  where: { email: 'demo@secureflow.local' },
  update: {},
  create: { email: 'demo@secureflow.local', passwordHash: 'demo-only', role: Role.ADMIN },
});
await prisma.$disconnect();
