import { describe, expect, it } from 'vitest';
import { scan } from './index.js';
import { join } from 'node:path';
describe('scanner engine', () => {
  it('handles missing targets without external services', () => {
    expect(scan({ target: join(process.cwd(), 'missing-target') }).findings).toEqual([]);
  });
});
