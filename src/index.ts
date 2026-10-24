import { randomBytes } from "node:crypto";
import { recoverMessageAddress, type Address, type Hex } from "viem";

/**
 * Cerberus chamber 1: identity of a listed LAX agent.
 *
 * A pure TypeScript module (no network) that issues a short lived challenge
 * binding an agent DID and a LAX listing id, and verifies that the listing
 * owner address signed that challenge with an EIP-191 personal signature.
 */

export interface Challenge {
  did: string;
  listingId: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  message: string;
}

export type VerifyReason =
  | "ok"
  | "malformed challenge"
  | "not yet valid"
  | "expired"
  | "replayed nonce"
  | "invalid signature"
  | "wrong signer";

export interface VerifyResult {
  ok: boolean;
  reason: VerifyReason;
  signer?: Address;
}

export interface CreateChallengeInput {
  did: string;
  listingId: string;
  now?: number;
  ttlMs?: number;
  nonce?: string;
}

export interface VerifyChallengeInput {
  challenge: Challenge;
  signature: Hex;
  ownerAddress: Address;
  now?: number;
  /**
   * Nonce store used for replay protection. A shared module level store is
   * used when none is passed, so a nonce verified once in this process can
   * never verify twice.
   */
  seen?: Set<string>;
}

export const DEFAULT_TTL_MS = 300_000;

const sharedSeenNonces = new Set<string>();

/** Canonical message the listing owner signs. Rebuilt on verify, never trusted from input. */
export function challengeMessage(challenge: Omit<Challenge, "message">): string {
  return [
    "LAX Cerberus Chamber 1 Challenge",
    `DID: ${challenge.did}`,
    `Listing: ${challenge.listingId}`,
    `Nonce: ${challenge.nonce}`,
    `Issued: ${challenge.issuedAt}`,
    `Expires: ${challenge.expiresAt}`,
  ].join("\n");
}

export function createChallenge(input: CreateChallengeInput): Challenge {
  if (!input.did) {
    throw new TypeError("did is required");
  }
  if (!input.listingId) {
    throw new TypeError("listingId is required");
  }
  const issuedAt = input.now ?? Date.now();
  const base: Omit<Challenge, "message"> = {
    did: input.did,
    listingId: input.listingId,
    nonce: input.nonce ?? randomBytes(16).toString("hex"),
    issuedAt,
    expiresAt: issuedAt + (input.ttlMs ?? DEFAULT_TTL_MS),
  };
  return { ...base, message: challengeMessage(base) };
}

export async function verifyChallenge(input: VerifyChallengeInput): Promise<VerifyResult> {
  const { challenge, signature, ownerAddress } = input;
  const now = input.now ?? Date.now();
  const seen = input.seen ?? sharedSeenNonces;

  if (
    !challenge?.did ||
    !challenge?.listingId ||
    !challenge?.nonce ||
    !Number.isFinite(challenge?.issuedAt) ||
    !Number.isFinite(challenge?.expiresAt)
  ) {
    return { ok: false, reason: "malformed challenge" };
  }
  if (now < challenge.issuedAt) {
    return { ok: false, reason: "not yet valid" };
  }
  if (now >= challenge.expiresAt) {
    return { ok: false, reason: "expired" };
  }
  if (seen.has(challenge.nonce)) {
    return { ok: false, reason: "replayed nonce" };
  }

  let signer: Address;
  try {
    signer = await recoverMessageAddress({
      message: challengeMessage(challenge),
      signature,
    });
  } catch {
    return { ok: false, reason: "invalid signature" };
  }

  if (signer.toLowerCase() !== String(ownerAddress).toLowerCase()) {
    return { ok: false, reason: "wrong signer" };
  }

  seen.add(challenge.nonce);
  return { ok: true, reason: "ok", signer };
}
