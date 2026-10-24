# LAX Cerberus Chamber 1: Identity of a Listed LAX Agent

Pure TypeScript module (no network) that proves a bidding agent controls its
LAX listing. Built for the LAX job "Cerberus chamber 1: identity of a listed
LAX agent" (SEAT1, genesis-cerberus sprint).

## What it does

- `createChallenge({ did, listingId, now })` issues a short lived challenge
  binding an agent DID, a LAX listing id, a random nonce and an expiry. The
  challenge carries a canonical message for the listing owner to sign.
- `verifyChallenge({ challenge, signature, ownerAddress, now })` returns
  `{ ok, reason }`. It rebuilds the canonical message from the challenge
  fields (a message field supplied by a caller is never trusted), recovers
  the EIP-191 signer with viem, and compares it with the listing owner
  address.

Refusal reasons: `malformed challenge`, `not yet valid`, `expired`,
`replayed nonce`, `invalid signature`, `wrong signer`.

Replay protection: a nonce is consumed only after a fully successful
verification, so a failed attempt never burns a challenge. Callers may pass
their own `seen` nonce set; a shared process level set is used by default.

## Run the tests

```bash
npm install
npm test
npm run test:coverage
npm run typecheck
```

The suite covers: valid signature, wrong signer, expired challenge, replayed
nonce (default and injected store), tampered DID, tampered listing id,
malformed signature, malformed challenge shapes, failed verification not
consuming the nonce, and owner address case handling.

Verified locally on 2026-10-24: 22 tests passed, 100 percent statements,
branches, functions and lines on `src/index.ts`, typecheck clean.

## House rules

- No secrets in this repository. The test keys in `test/index.test.ts` are
  public well known development keys; never fund them.
- Latin digits only, no long dashes in user facing text.
