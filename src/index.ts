import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';

export interface CustodyEvent {
  sessionId: string;
  taskId: string;
  stepIndex: number;
  timestamp: string;
  agentId: string;
  modelName: string;
  toolName?: string;
  inputHash: string;
  outputHash: string;
  previousHash: string;
  currentHash: string;
  signature?: string;
}

export interface VerificationResult {
  ok: boolean;
  firstCorruptedIndex: number | null;
  reason?: string;
}

export type UnsignedEvent = Omit<CustodyEvent, 'currentHash' | 'signature'>;

export function computeCurrentHash(input: UnsignedEvent): string {
  const payload = {
    sessionId: input.sessionId,
    taskId: input.taskId,
    stepIndex: input.stepIndex,
    timestamp: input.timestamp,
    agentId: input.agentId,
    modelName: input.modelName,
    toolName: input.toolName,
    inputHash: input.inputHash,
    outputHash: input.outputHash,
    previousHash: input.previousHash
  };
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

export function buildEvent(input: UnsignedEvent): CustodyEvent {
  return { ...input, currentHash: computeCurrentHash(input) };
}

export function appendEvent(filePath: string, event: CustodyEvent): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const line = JSON.stringify(event) + '\n';
  appendFileSync(filePath, line, { encoding: 'utf8', flag: 'a' });
}

export function verifyChain(filePath: string): VerificationResult {
  if (!existsSync(filePath)) {
    return { ok: false, firstCorruptedIndex: 0, reason: 'file not found' };
  }

  const lines = readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
  let prevHash = 'GENESIS';

  for (let i = 0; i < lines.length; i++) {
    const event = JSON.parse(lines[i]) as CustodyEvent;

    if (event.previousHash !== prevHash) {
      return { ok: false, firstCorruptedIndex: i, reason: 'previousHash mismatch' };
    }

    const recomputed = computeCurrentHash({
      sessionId: event.sessionId,
      taskId: event.taskId,
      stepIndex: event.stepIndex,
      timestamp: event.timestamp,
      agentId: event.agentId,
      modelName: event.modelName,
      toolName: event.toolName,
      inputHash: event.inputHash,
      outputHash: event.outputHash,
      previousHash: event.previousHash
    });

    if (recomputed !== event.currentHash) {
      return { ok: false, firstCorruptedIndex: i, reason: 'currentHash mismatch' };
    }

    prevHash = event.currentHash;
  }

  return { ok: true, firstCorruptedIndex: null };
}

export function generateEd25519KeyPairPem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
  };
}

export function signEventHash(currentHashHex: string, privateKeyPem: string): string {
  const signature = sign(null, Buffer.from(currentHashHex, 'hex'), privateKeyPem);
  return signature.toString('base64');
}

export function verifyEventSignature(currentHashHex: string, signatureBase64: string, publicKeyPem: string): boolean {
  return verify(
    null,
    Buffer.from(currentHashHex, 'hex'),
    publicKeyPem,
    Buffer.from(signatureBase64, 'base64')
  );
}
