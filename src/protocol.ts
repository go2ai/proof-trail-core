import crypto from 'node:crypto';

export interface CustodyEnvelope {
  schema_version: string;
  stream_id: string;
  seq: number;
  event_type: string;
  ts: string;
  actor: {
    agent_id: string;
    tenant_id?: string;
    key_id: string;
  };
  context?: Record<string, unknown>;
  body: Record<string, unknown>;
  chain: {
    prev_event_hash: string;
    event_hash?: string;
  };
  signature: {
    alg: 'ed25519' | string;
    sig?: string;
    signed_bytes?: string;
  };
}

export function sortDeep<T>(value: T): T {
  if (Array.isArray(value)) return value.map((v) => sortDeep(v)) as T;
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj).sort()) out[k] = sortDeep(obj[k]);
    return out as T;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

export function envelopeForSignOrHash(envelope: CustodyEnvelope): CustodyEnvelope {
  const cloned = JSON.parse(JSON.stringify(envelope)) as CustodyEnvelope;
  if (cloned.signature) delete cloned.signature.sig;
  if (cloned.chain) delete cloned.chain.event_hash;
  return cloned;
}

export function eventHash(envelope: CustodyEnvelope): string {
  const canonical = canonicalJson(envelopeForSignOrHash(envelope));
  return `sha256:${crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex')}`;
}

export function signEnvelope(envelope: CustodyEnvelope, privateKeyPem: string): string {
  const bytes = canonicalJson(envelopeForSignOrHash(envelope));
  const sig = crypto.sign(null, Buffer.from(bytes, 'utf8'), privateKeyPem).toString('base64');
  return `base64:${sig}`;
}

export function verifyEnvelopeSignature(envelope: CustodyEnvelope, publicKeyPem: string): boolean {
  const rawSig = envelope.signature?.sig ?? '';
  const sig = rawSig.startsWith('base64:') ? rawSig.slice(7) : rawSig;
  const bytes = canonicalJson(envelopeForSignOrHash(envelope));
  return crypto.verify(null, Buffer.from(bytes, 'utf8'), publicKeyPem, Buffer.from(sig, 'base64'));
}

export function validateEnvelopeBasics(envelope: Partial<CustodyEnvelope>): string | null {
  const required: Array<keyof CustodyEnvelope> = [
    'schema_version',
    'stream_id',
    'seq',
    'event_type',
    'ts',
    'actor',
    'body',
    'chain',
    'signature'
  ];

  for (const key of required) {
    if (!(key in envelope)) return `missing field: ${String(key)}`;
  }

  if (!envelope.actor?.key_id) return 'missing field: actor.key_id';
  if (!envelope.chain || !('prev_event_hash' in envelope.chain)) return 'missing field: chain.prev_event_hash';
  if (!envelope.signature || !envelope.signature.sig) return 'missing field: signature.sig';
  if (!Number.isInteger(envelope.seq) || (envelope.seq ?? 0) < 1) return 'seq must be an integer >= 1';

  return null;
}
