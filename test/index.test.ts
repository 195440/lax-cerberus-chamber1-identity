import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  CHALLENGE_TTL_MS,
  MAX_TTL_MS,
  MIN_TTL_MS,
  challengeMessage,
  createChallenge,
  verifyChallenge,
  type Challenge,
} from "../src/index.js";

// Fixed public test keys of local Ethereum dev chains (anvil accounts 0 and 1). Never fund them.
const owner = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const stranger = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);

const NOW = Date.parse("2026-10-27T12:00:00.000Z");
const DID = "did:pkh:eip155:8453:0x8cc9bd34b5ee8e828C54b84d0520CdCF4FA9C078";
const LISTING = "lax-ext-097fae235b3f";

function fresh(overrides: Partial<Parameters<typeof createChallenge>[0]> = {}): Challenge {
  return createChallenge({ did: DID, listingId: LISTING, now: NOW, ...overrides });
}

/** Sign the text rebuilt from the fields, the way a listing owner signs what the format prescribes. */
const sign = (c: Challenge, who = owner) => who.signMessage({ message: challengeMessage(c) });

/** Verify with sensible defaults; `over` replaces any field, including with deliberately wrong values. */
async function verify(c: Challenge, over: Record<string, unknown> = {}) {
  return verifyChallenge({
    challenge: c,
    signature: await sign(c),
    ownerAddress: owner.address,
    now: NOW + 1_000,
    ...over,
  } as never);
}

/** Rebuild the message after editing fields, so only the field under test is wrong. */
function edited(c: Challenge, patch: Partial<Challenge>): Challenge {
  const next = { ...c, ...patch };
  next.message = challengeMessage(next);
  return next;
}

describe("createChallenge", () => {
  it("carries the exact six line message of the SEAT1 PACT format with ISO times and a 10 minute lifetime", () => {
    const a = fresh();
    expect(a.message).toBe(
      `LAX identity challenge\ndid: ${DID}\nlisting: ${LISTING}\nnonce: ${a.nonce}\nissued: 2026-10-27T12:00:00.000Z\nexpires: 2026-10-27T12:10:00.000Z`,
    );
    expect(a.issuedAt).toBe("2026-10-27T12:00:00.000Z");
    expect(a.expiresAt).toBe("2026-10-27T12:10:00.000Z");
    expect(a.did).toBe(DID);
    expect(a.listingId).toBe(LISTING);
    expect(CHALLENGE_TTL_MS).toBe(600_000);
    expect(MIN_TTL_MS).toBe(60_000);
    expect(MAX_TTL_MS).toBe(900_000);
  });

  it("has no trailing newline and exactly six lines", () => {
    const lines = fresh().message.split("\n");
    expect(lines).toHaveLength(6);
    expect(fresh().message.endsWith("\n")).toBe(false);
  });

  it("uses a fresh nonce of 16 random bytes in lowercase hex every time", () => {
    const nonces = new Set(Array.from({ length: 50 }, () => fresh().nonce));
    expect(nonces.size).toBe(50);
    for (const nonce of nonces) expect(nonce).toMatch(/^[0-9a-f]{32}$/);
  });

  it("stores the message that challengeMessage rebuilds from the fields", () => {
    const a = fresh();
    expect(challengeMessage(a)).toBe(a.message);
  });

  it("honours a custom lifetime from 1 to 15 minutes and refuses anything else", () => {
    expect(Date.parse(fresh({ ttlMs: 60_000 }).expiresAt) - NOW).toBe(60_000);
    expect(Date.parse(fresh({ ttlMs: 900_000 }).expiresAt) - NOW).toBe(900_000);
    expect(() => fresh({ ttlMs: 59_999 })).toThrow(RangeError);
    expect(() => fresh({ ttlMs: 900_001 })).toThrow(RangeError);
    expect(() => fresh({ ttlMs: Number.NaN })).toThrow(RangeError);
  });

  it("accepts a caller supplied nonce only when it is 16 or more random bytes in lowercase hex", () => {
    const nonce = "ab".repeat(20);
    expect(fresh({ nonce }).nonce).toBe(nonce);
    expect(() => fresh({ nonce: "short" })).toThrow(TypeError);
    expect(() => fresh({ nonce: "AB".repeat(16) })).toThrow(TypeError);
  });

  it("refuses a bad DID, a bad listing id or a bad clock", () => {
    expect(() => fresh({ did: "nope" })).toThrow(TypeError);
    expect(() => fresh({ did: "" })).toThrow(TypeError);
    expect(() => fresh({ did: 42 as never })).toThrow(TypeError);
    expect(() => fresh({ listingId: "" })).toThrow(TypeError);
    expect(() => fresh({ listingId: "   " })).toThrow(TypeError);
    expect(() => fresh({ listingId: "two words" })).toThrow(TypeError);
    expect(() => fresh({ listingId: 7 as never })).toThrow(TypeError);
    expect(() => fresh({ now: Number.NaN })).toThrow(TypeError);
    expect(() => fresh({ now: "soon" as never })).toThrow(TypeError);
    expect(() => createChallenge({ did: DID, listingId: LISTING } as never)).toThrow(TypeError);
  });
});

describe("verifyChallenge: accepted", () => {
  it("accepts the listing owner's EIP-191 signature once and says why", async () => {
    const c = fresh();
    const verdict = await verify(c);
    expect(verdict.ok).toBe(true);
    expect(verdict.reason).toBe("signed by the listing owner");
  });

  it("accepts the owner address in any letter case", async () => {
    const lower = await verify(fresh(), { ownerAddress: owner.address.toLowerCase() });
    const checksum = await verify(fresh(), { ownerAddress: owner.address });
    expect(lower.ok).toBe(true);
    expect(checksum.ok).toBe(true);
  });

  it("accepts a challenge up to one millisecond before it expires", async () => {
    const verdict = await verify(fresh(), { now: NOW + CHALLENGE_TTL_MS - 1 });
    expect(verdict.ok).toBe(true);
  });

  it("does not look at the clock before the issue time, like the reference chamber", async () => {
    const verdict = await verify(fresh(), { now: NOW - 5_000 });
    expect(verdict.ok).toBe(true);
  });
});

describe("verifyChallenge: replay", () => {
  it("lets a nonce verify once and refuses the second time with a replay reason", async () => {
    const c = fresh();
    expect((await verify(c)).ok).toBe(true);
    const again = await verify(c);
    expect(again.ok).toBe(false);
    expect(again.reason).toMatch(/replay/);
  });

  it("does not burn the nonce on a failed attempt", async () => {
    const c = fresh();
    const bad = await verify(c, { signature: await sign(c, stranger) });
    expect(bad.ok).toBe(false);
    expect((await verify(c)).ok).toBe(true);
  });

  it("keeps an injected nonce store apart from the shared one", async () => {
    const c = fresh();
    const mine = new Set<string>();
    expect((await verify(c, { seen: mine })).ok).toBe(true);
    expect(mine.has(c.nonce)).toBe(true);
    expect((await verify(c, { seen: mine })).reason).toMatch(/replay/);
    // the shared store never saw it
    expect((await verify(c)).ok).toBe(true);
    expect((await verify(c)).reason).toMatch(/replay/);
  });
});

describe("verifyChallenge: wrong key, address or signature", () => {
  it("refuses a signature by another key", async () => {
    const c = fresh();
    const verdict = await verify(c, { signature: await sign(c, stranger) });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).not.toBe("");
  });

  it("refuses when the expected owner is another address", async () => {
    const verdict = await verify(fresh(), { ownerAddress: stranger.address });
    expect(verdict.ok).toBe(false);
  });

  it("refuses a malformed owner address", async () => {
    expect((await verify(fresh(), { ownerAddress: "x" })).ok).toBe(false);
    expect((await verify(fresh(), { ownerAddress: 12 })).ok).toBe(false);
  });

  it("refuses a malformed signature", async () => {
    expect((await verify(fresh(), { signature: "0x12" })).ok).toBe(false);
    expect((await verify(fresh(), { signature: 12 })).ok).toBe(false);
  });

  it("refuses a signature of the right length that cannot be recovered", async () => {
    const verdict = await verify(fresh(), { signature: `0x${"ff".repeat(65)}` });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).not.toBe("");
  });
});

describe("verifyChallenge: time", () => {
  it("refuses at the exact expiry instant and after it", async () => {
    const at = await verify(fresh(), { now: NOW + CHALLENGE_TTL_MS });
    expect(at.ok).toBe(false);
    expect(at.reason).toMatch(/expired/);
    expect((await verify(fresh(), { now: NOW + 20 * 60_000 })).ok).toBe(false);
  });

  it("refuses a clock that is not a number of milliseconds", async () => {
    expect((await verify(fresh(), { now: "soon" })).ok).toBe(false);
    expect((await verify(fresh(), { now: Number.NaN })).ok).toBe(false);
  });

  it("refuses a lifetime over 15 minutes even when the message is rebuilt and signed", async () => {
    const long = edited(fresh(), { expiresAt: new Date(NOW + 60 * 60_000).toISOString() });
    const verdict = await verify(long);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/lifetime/);
  });

  it("refuses a lifetime under one minute", async () => {
    const short = edited(fresh(), { expiresAt: new Date(NOW + 30_000).toISOString() });
    expect((await verify(short)).ok).toBe(false);
  });
});

describe("verifyChallenge: tampering and malformed challenges", () => {
  it("refuses a changed DID whose message was left alone", async () => {
    const c = fresh();
    const verdict = await verify({ ...c, did: "did:web:evil.example" });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/tampered/);
  });

  it("refuses a changed listing id, nonce or time whose message was left alone", async () => {
    const c = fresh();
    expect((await verify({ ...c, listingId: "lax-ext-other" })).ok).toBe(false);
    expect((await verify({ ...c, nonce: "cd".repeat(16) })).ok).toBe(false);
    expect((await verify({ ...c, issuedAt: "2026-10-27T12:00:01.000Z" })).ok).toBe(false);
  });

  it("refuses an edited message text", async () => {
    const c = fresh();
    expect((await verify({ ...c, message: `${c.message}\nextra` })).ok).toBe(false);
  });

  it("refuses a rebuilt message that the owner never signed", async () => {
    const c = fresh();
    const evil = edited(c, { did: "did:web:evil.example" });
    const verdict = await verify(evil, { signature: await sign(c) });
    expect(verdict.ok).toBe(false);
  });

  it("refuses a nonce that is short or not lowercase hex", async () => {
    expect((await verify(edited(fresh(), { nonce: "short" }))).ok).toBe(false);
    expect((await verify(edited(fresh(), { nonce: "AB".repeat(16) }))).ok).toBe(false);
  });

  it("refuses times that are not ISO 8601 strings from toISOString", async () => {
    expect((await verify(edited(fresh(), { issuedAt: NOW as never }))).ok).toBe(false);
    expect((await verify(edited(fresh(), { issuedAt: "garbage" }))).ok).toBe(false);
    expect((await verify(edited(fresh(), { issuedAt: "2026-10-27" }))).ok).toBe(false);
    expect((await verify(edited(fresh(), { expiresAt: "2026-10-27T12:10:00Z" }))).ok).toBe(false);
  });

  it("refuses a DID or listing id that is not a string", async () => {
    expect((await verify({ ...fresh(), did: 1 as never })).ok).toBe(false);
    expect((await verify({ ...fresh(), listingId: null as never })).ok).toBe(false);
  });

  it("refuses a missing or non object challenge with a reason", async () => {
    for (const challenge of [null, undefined, "text", 5]) {
      const verdict = await verify(fresh(), { challenge });
      expect(verdict.ok).toBe(false);
      expect(verdict.reason).not.toBe("");
    }
  });

  it("answers instead of throwing on missing input", async () => {
    const none = await verifyChallenge(undefined as never);
    expect(none.ok).toBe(false);
    expect(none.reason).not.toBe("");
    expect((await verifyChallenge(null as never)).ok).toBe(false);
  });

  it("answers instead of throwing when the input fights back", async () => {
    const hostile = {
      get challenge(): Challenge {
        throw new Error("no peeking");
      },
    };
    const verdict = await verifyChallenge(hostile as never);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe("the input is malformed");
  });
});
