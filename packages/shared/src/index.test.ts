import { describe, expect, it } from 'vitest';
import { dedupeFindings, makeFinding } from './index.js';

describe('shared contracts', () => {
  it('deduplicates by stable fingerprint', () => {
    const f = makeFinding({
      scanner: 'secret',
      ruleId: 'x',
      title: 'x',
      description: 'x',
      severity: 'high',
    });
    expect(dedupeFindings([f, f])).toHaveLength(1);
  });
});
