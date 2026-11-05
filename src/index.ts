import { randomBytes } from "node:crypto";
import { recoverMessageAddress, type Address, type Hex } from "viem";

/**
 * Cerberus chamber 1: identity of a listed LAX agent.
 *
 * A pure TypeScript module (no network) that issues a short lived challenge
 * binding an agent DID and a LAX listing id, and verifies that the listing
 * owner address signed that challenge with an EIP-191 personal signature.
 *
 * Formats follow the chamber interfaces kit that Kognai publishes for the
 * Cerberus seats (https://www.kognai.ai/docs/kits/pact-chambers/, version 1):
 * the six line message, ISO 8601 times, a lifetime of 1 to 15 minutes
 * (10 by default) and a nonce of at least 16 random bytes in lowercase hex.
 * The module can be dropped in where the kit's reference chamber is.
 */

/** Lifetime bounds of a challenge in milliseconds: 1 to 15 minutes. */
export const MIN_TTL_MS = 60_000;
export const MAX_TTL_MS = 15 * 60_000;
/** Default lifetime of a challenge: 10 minutes. */
export const CHALLENGE_TTL_MS = 10 * 60_000;

export interface Challenge {
  did: string;
  listingId: string;
  /** at least 16 random bytes in lowercase hex (32 or more characters), never reused */
  nonce: string;
  /** ISO 8601 UTC, exactly as Date.prototype.toISOString writes it */
  issuedAt: string;
  /** 1 to 15 minutes after issuedAt, same format */
  expiresAt: string;
  /** challengeMessage(this): the exact text the listing owner signs */
  message: string;
}

/** A chamber's answer. ok false always comes with a non empty reason. */
export interface Verdict {
  ok: boolean;
  reason: string;
}

export interface CreateChallengeInput {
  did: string;
  listingId: string;
  /** milliseconds since the epoch */
  now: number;
  /** optional lifetime in milliseconds, from 1 to 15 minutes (default 10) */
  ttlMs?: number;
  /** optional nonce, mainly for tests: 16 or more random bytes in lowercase hex */
  nonce?: string;
}

export interface VerifyChallengeInput {
  challenge: Challenge;
  signature: string;
  ownerAddress: string;
  /** milliseconds since the epoch */
  now: number;
  /**
   * Nonce store used for replay protection. A shared module level store is
   * used when none is passed, so a nonce verified once in this process can
   * never verify twice.
   */
  seen?: Set<string>;
}

const DID_PATTERN = /^did:[a-z0-9]+:\S+$/;
const NONCE_PATTERN = /^[0-9a-f]{32,}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

const sharedSeenNonces = new Set<string>();

const refuse = (reason: string): Verdict => ({ ok: false, reason });

/** True only for a string that Date.prototype.toISOString could have written. */
const isIso = (value: unknown): value is string =>
  typeof value === "string" &&
  Number.isFinite(Date.parse(value)) &&
  new Date(Date.parse(value)).toISOString() === value;

/**
 * The exact text the listing owner signs: six lines joined by a line feed,
 * no trailing line feed. Rebuilt on verify, never trusted from input.
 */
export function challengeMessage(
  challenge: Pick<Challenge, "did" | "listingId" | "nonce" | "issuedAt" | "expiresAt">,
): string {
  return [
    "LAX identity challenge",
    `did: ${challenge.did}`,
    `listing: ${challenge.listingId}`,
    `nonce: ${challenge.nonce}`,
    `issued: ${challenge.issuedAt}`,
    `expires: ${challenge.expiresAt}`,
  ].join("\n");
}

export function createChallenge(input: CreateChallengeInput): Challenge {
  const { did, listingId, now, ttlMs = CHALLENGE_TTL_MS, nonce = randomBytes(16).toString("hex") } = input;
  if (typeof did !== "string" || !DID_PATTERN.test(did)) {
    throw new TypeError("did must be a DID such as did:pkh:eip155:8453:0x...");
  }
  if (typeof listingId !== "string" || listingId.trim() === "" || /\s/.test(listingId)) {
    throw new TypeError("listingId must be a non empty id without spaces");
  }
  if (typeof now !== "number" || !Number.isFinite(now)) {
    throw new TypeError("now must be milliseconds since the epoch");
  }
  if (!Number.isFinite(ttlMs) || ttlMs < MIN_TTL_MS || ttlMs > MAX_TTL_MS) {
    throw new RangeError("ttlMs must be between 1 and 15 minutes");
  }
  if (!NONCE_PATTERN.test(nonce)) {
    throw new TypeError("nonce must be at least 16 random bytes in lowercase hex");
  }
  const fields = {
    did,
    listingId,
    nonce,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString(),
  };
  return { ...fields, message: challengeMessage(fields) };
}

/**
 * Checks, in order: the challenge is well formed, its message equals the text
 * rebuilt from its fields, its lifetime is 1 to 15 minutes, it has not expired,
 * its nonce was not used before, and the listing owner signed the message.
 * Never throws: every failure is an `ok: false` verdict with a reason. A nonce
 * is consumed only after the whole check passed, so a failed attempt never
 * burns a fresh challenge.
 */
export async function verifyChallenge(input: VerifyChallengeInput): Promise<Verdict> {
  try {
    const { challenge: c, signature, ownerAddress, now, seen = sharedSeenNonces } = input ?? ({} as VerifyChallengeInput);
    if (!c || typeof c !== "object") return refuse("no challenge");
    if (
      typeof c.did !== "string" ||
      typeof c.listingId !== "string" ||
      !NONCE_PATTERN.test(String(c.nonce)) ||
      !isIso(c.issuedAt) ||
      !isIso(c.expiresAt)
    ) {
      return refuse("the challenge is malformed");
    }
    if (c.message !== challengeMessage(c)) {
      return refuse("the challenge text does not match its fields (tampered)");
    }
    const lifetime = Date.parse(c.expiresAt) - Date.parse(c.issuedAt);
    if (lifetime < MIN_TTL_MS || lifetime > MAX_TTL_MS) {
      return refuse("the challenge lifetime is not between 1 and 15 minutes");
    }
    if (typeof now !== "number" || !Number.isFinite(now)) {
      return refuse("now must be milliseconds since the epoch");
    }
    if (now >= Date.parse(c.expiresAt)) return refuse("the challenge expired");
    if (seen.has(c.nonce)) return refuse("the challenge was already used (replay)");
    if (typeof signature !== "string" || !SIGNATURE_PATTERN.test(signature)) {
      return refuse("the signature is malformed");
    }
    if (typeof ownerAddress !== "string" || !ADDRESS_PATTERN.test(ownerAddress)) {
      return refuse("the owner address is malformed");
    }
    let signer: Address;
    try {
      signer = await recoverMessageAddress({ message: c.message, signature: signature as Hex });
    } catch {
      return refuse("the challenge is not signed by the listing owner");
    }
    if (signer.toLowerCase() !== ownerAddress.toLowerCase()) {
      return refuse("the challenge is not signed by the listing owner");
    }
    seen.add(c.nonce);
    return { ok: true, reason: "signed by the listing owner" };
  } catch {
    return refuse("the input is malformed");
  }
}
