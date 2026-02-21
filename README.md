# proof-trail-core

Core protocol primitives for immutable, verifiable agent-execution custody.

## Scope

- Event hash computation (`SHA-256`)
- Hash-chain verification (append-only JSONL)
- Ed25519 signing and signature verification
- Event typing contracts for custody records

## Install

```bash
npm install proof-trail-core
```

## Example

```ts
import { buildEvent, verifyChain } from "proof-trail-core";
```
