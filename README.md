# LAX Cerberus Chamber 1: Identity of a Listed LAX Agent

Pure TypeScript module (no network) that proves a bidding agent controls its
LAX listing. Built for the LAX job "Cerberus chamber 1: identity of a listed
LAX agent" (SEAT1, genesis-cerberus sprint).

The formats follow the chamber interfaces kit that Kognai publishes for the
Cerberus seats ("pact-chambers" kit, version 1,
<https://www.kognai.ai/docs/kits/pact-chambers/>), so the module can be dropped
in where the kit's reference chamber 1 is.

## What it does

- `createChallenge({ did, listingId, now })` issues a short lived challenge
  binding an agent DID, a LAX listing id, a random nonce and an expiry.
  `now` is milliseconds since the epoch. It throws on a bad DID, an empty
  listing id or a non finite clock. Optional `ttlMs` (1 to 15 minutes) and
  `nonce` (16 or more random bytes in lowercase hex) exist for tests.
- `challengeMessage(challenge)` is the exact text the listing owner signs.
- `verifyChallenge({ challenge, signature, ownerAddress, now })` resolves to
  `{ ok, reason }` and never throws. It rebuilds the message from the
  challenge fields (a `message` supplied by a caller is never trusted),
  recovers the EIP-191 personal signature signer with viem and compares it
  with the listing owner address. `ok: false` always carries a reason.

## Formats

```text
LAX identity challenge
did: <did>
listing: <listing id>
nonce: <nonce>
issued: <issuedAt>
expires: <expiresAt>
```

- Six lines joined by a line feed, no trailing line feed.
- `issuedAt` and `expiresAt` are ISO 8601 UTC strings exactly as
  `Date.prototype.toISOString` writes them (for example
  `2026-10-27T12:00:00.000Z`).
- Default lifetime 10 minutes; accepted lifetime 1 to 15 minutes.
- Nonce: 16 random bytes in lowercase hex (32 characters); verification
  accepts 32 or more lowercase hex characters.

## Verification order and refusal reasons

1. no challenge, or a malformed one (DID or listing id not a string, bad
   nonce, times that are not ISO strings)
2. the message differs from the text rebuilt from the fields (tampered)
3. the lifetime is outside 1 to 15 minutes
4. `now` is not a finite number
5. the challenge expired (`now` at or after `expiresAt`)
6. the nonce was already used (replay)
7. the signature or the owner address is malformed
8. the signature is unrecoverable or the signer is not the listing owner

Anything unexpected, including hostile input objects, ends in an `ok: false`
verdict ("the input is malformed") instead of an exception.

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

The suite covers: the exact message and ISO times, nonce freshness and
format, lifetime bounds, input validation of `createChallenge`, valid
signature, owner address letter case, wrong signer, wrong owner, malformed
and unrecoverable signatures, expiry at the exact instant, bad clocks,
tampering of each field and of the message text, rebuilt but unsigned
messages, malformed challenge shapes, replay (default and injected store),
a failed attempt not burning the nonce, and hostile input.

Verified locally on 2026-11-05: 33 tests passed, 100 percent statements,
branches, functions and lines on `src/index.ts`, typecheck clean. The kit's own
chamber 1 assertions (exact six line message, fresh nonces, 10 minute
lifetime, valid once, wrong signer, wrong owner, expired, tampered, malformed)
pass against this module, and a differential run of 102 input variants
(204 verifications) against the kit's reference chamber 1 gave the same
verdict every time, with challenges verifying in both directions.

## House rules

- No secrets in this repository. The test keys in `test/index.test.ts` are
  public well known development keys; never fund them.
- Latin digits only, no long dashes in user facing text.
