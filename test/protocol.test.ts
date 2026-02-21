import test from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPairPem } from '../src/index.js';
import { eventHash, signEnvelope, verifyEnvelopeSignature, type CustodyEnvelope } from '../src/protocol.js';

test('protocol helpers should hash/sign/verify deterministically', () => {
  const { privateKeyPem, publicKeyPem } = generateEd25519KeyPairPem();

  const envelope: CustodyEnvelope = {
    schema_version: '1.0',
    stream_id: 'run_1',
    seq: 1,
    event_type: 'skill.call',
    ts: new Date().toISOString(),
    actor: { agent_id: 'a', key_id: 'ed25519:agent-main:v1' },
    body: { input_hash: 'sha256:abc' },
    chain: { prev_event_hash: 'GENESIS' },
    signature: { alg: 'ed25519' }
  };

  const h1 = eventHash(envelope);
  const sig = signEnvelope(envelope, privateKeyPem);
  envelope.signature.sig = sig;

  assert.equal(verifyEnvelopeSignature(envelope, publicKeyPem), true);
  assert.equal(h1.startsWith('sha256:'), true);
});
