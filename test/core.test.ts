import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { appendEvent, buildEvent, verifyChain } from '../src/index.js';

test('verifyChain should detect valid chain', () => {
  const dir = mkdtempSync(join(tmpdir(), 'proof-trail-core-'));
  const file = join(dir, 'events.jsonl');

  const e1 = buildEvent({
    sessionId: 's',
    taskId: 't',
    stepIndex: 0,
    timestamp: new Date().toISOString(),
    agentId: 'a',
    modelName: 'm',
    inputHash: 'i1',
    outputHash: 'o1',
    previousHash: 'GENESIS'
  });

  const e2 = buildEvent({
    sessionId: 's',
    taskId: 't',
    stepIndex: 1,
    timestamp: new Date().toISOString(),
    agentId: 'a',
    modelName: 'm',
    inputHash: 'i2',
    outputHash: 'o2',
    previousHash: e1.currentHash
  });

  appendEvent(file, e1);
  appendEvent(file, e2);

  const result = verifyChain(file);
  assert.equal(result.ok, true);

  rmSync(dir, { recursive: true, force: true });
});
