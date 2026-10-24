import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  challengeMessage,
  createChallenge,
  verifyChallenge,
  type Challenge,
} from "../src/index.js";

// Fixed test keys only. Never use these accounts for real funds.
const owner = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const stranger = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);

const NOW = 1_800_000_000_000;

function freshChallenge(overrides: Partial<Parameters<typeof createChallenge>[0]> = {}): Challenge {
  return createChallenge({
    did: "did:pkh:eip155:8453:0x8cc9bd34b5ee8e828C54b84d0520CdCF4FA9C078",
    listingId: "lax-ext-097fae235b3f",
    now: NOW,
    ...overrides,
  });
}

describe("createChallenge", () => {
  it("issues a challenge with nonce, issued time, expiry and a signable message", () => {
    const challenge = freshChallenge({ nonce: "nonce-1" });
    expect(challenge.did).toContain("did:pkh:eip155:8453:");
    expect(challenge.listingId).toBe("lax-ext-097fae235b3f");
    expect(challenge.nonce).toBe("nonce-1");
    expect(challenge.issuedAt).toBe(NOW);
    expect(challenge.expiresAt).toBe(NOW + 300_000);
    expect(challenge.message).toBe(challengeMessage(challenge));
    expect(challenge.message).toContain("nonce-1");
  });

  it("generates a random nonce and uses the current time by default", () => {
    const a = createChallenge({ did: "did:example:1", listingId: "lax-ext-1" });
    const b = createChallenge({ did: "did:example:1", listingId: "lax-ext-1" });
    expect(a.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(a.nonce).not.toBe(b.nonce);
    expect(Math.abs(a.issuedAt - Date.now())).toBeLessThan(5_000);
  });

  it("honours a custom ttl", () => {
    const challenge = freshChallenge({ ttlMs: 60_000 });
    expect(challenge.expiresAt - challenge.issuedAt).toBe(60_000);
  });

  it("rejects an empty did or listing id", () => {
    expect(() => createChallenge({ did: "", listingId: "x", now: NOW })).toThrow("did is required");
    expect(() => createChallenge({ did: "did:example:1", listingId: "", now: NOW })).toThrow(
      "listingId is required",
    );
  });
});

describe("verifyChallenge", () => {
  it("accepts a valid EIP-191 signature from the listing owner", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: true, reason: "ok", signer: owner.address });
  });

  it("accepts the owner address in lower case", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address.toLowerCase() as `0x${string}`,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result.ok).toBe(true);
  });

  it("refuses a signature from the wrong signer", async () => {
    const challenge = freshChallenge();
    const signature = await stranger.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: false, reason: "wrong signer" });
  });

  it("refuses an expired challenge", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: challenge.expiresAt,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: false, reason: "expired" });
  });

  it("refuses a challenge before its issued time", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: NOW - 1,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: false, reason: "not yet valid" });
  });

  it("refuses a replayed nonce, with the default store and with an injected store", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const first = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
    });
    expect(first.ok).toBe(true);
    const second = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: NOW + 2_000,
    });
    expect(second).toEqual({ ok: false, reason: "replayed nonce" });

    const seen = new Set<string>([challenge.nonce]);
    const injected = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen,
    });
    expect(injected).toEqual({ ok: false, reason: "replayed nonce" });
  });

  it("does not consume the nonce when verification fails", async () => {
    const challenge = freshChallenge();
    const seen = new Set<string>();
    const badSignature = await stranger.signMessage({ message: challenge.message });
    await verifyChallenge({
      challenge,
      signature: badSignature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen,
    });
    expect(seen.has(challenge.nonce)).toBe(false);
    const goodSignature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature: goodSignature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen,
    });
    expect(result.ok).toBe(true);
    expect(seen.has(challenge.nonce)).toBe(true);
  });

  it("refuses when the DID was tampered with after signing", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const tampered: Challenge = { ...challenge, did: "did:pkh:eip155:8453:0x0000000000000000000000000000000000000000" };
    const result = await verifyChallenge({
      challenge: tampered,
      signature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("wrong signer");
  });

  it("refuses when the listing id was tampered with after signing", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const tampered: Challenge = { ...challenge, listingId: "lax-ext-0000000000000" };
    const result = await verifyChallenge({
      challenge: tampered,
      signature,
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result.ok).toBe(false);
  });

  it("refuses a malformed signature instead of throwing", async () => {
    const challenge = freshChallenge();
    const result = await verifyChallenge({
      challenge,
      signature: "0x1234",
      ownerAddress: owner.address,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: false, reason: "invalid signature" });
  });

  it("refuses an owner address that is not an address", async () => {
    const challenge = freshChallenge();
    const signature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: "not-an-address" as `0x${string}`,
      now: NOW + 1_000,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: false, reason: "wrong signer" });
  });

  it("uses the current time by default", async () => {
    const challenge = createChallenge({
      did: "did:example:now",
      listingId: "lax-ext-now",
      ttlMs: 60_000,
    });
    const signature = await owner.signMessage({ message: challenge.message });
    const result = await verifyChallenge({
      challenge,
      signature,
      ownerAddress: owner.address,
      seen: new Set<string>(),
    });
    expect(result.ok).toBe(true);
  });

  const malformedCases: Array<[string, unknown]> = [
    ["null challenge", null],
    ["missing did", { listingId: "x", nonce: "n", issuedAt: NOW, expiresAt: NOW + 1 }],
    ["missing listingId", { did: "d", nonce: "n", issuedAt: NOW, expiresAt: NOW + 1 }],
    ["missing nonce", { did: "d", listingId: "x", issuedAt: NOW, expiresAt: NOW + 1 }],
    ["missing issuedAt", { did: "d", listingId: "x", nonce: "n", expiresAt: NOW + 1 }],
    ["missing expiresAt", { did: "d", listingId: "x", nonce: "n", issuedAt: NOW }],
  ];
  it.each(malformedCases)("refuses a malformed challenge: %s", async (_name, challenge) => {
    const result = await verifyChallenge({
      challenge: challenge as Challenge,
      signature: "0x1234",
      ownerAddress: owner.address,
      now: NOW,
      seen: new Set<string>(),
    });
    expect(result).toEqual({ ok: false, reason: "malformed challenge" });
  });
});
