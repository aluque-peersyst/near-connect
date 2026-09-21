import type { FinalExecutionOutcome } from "@near-js/types";

import { ED25519_MPC_ALGORITHM, getConfig } from "./config";
import type { Network } from "../utils/types";

/**
 * The `sign` call that makes the MPC network produce the signature is an ordinary NEAR transaction,
 * so somebody has to pay its gas and deposit. The NEAR Auth relayer does, after re-checking the JWT;
 * it can only ever relay a signature for a payload the user already approved in the Auth0 modal.
 */

export interface SignatureRequest {
  guardId: string;
  /** The Auth0 access token, verified again by the on-chain guard. */
  verifyPayload: string;
  /** Borsh bytes of the approved transaction, taken from the token's `fatxn` claim. */
  signPayload: number[];
}

interface RelayerResponse {
  hash: string;
  result: FinalExecutionOutcome;
}

const post = async (url: string, body: unknown): Promise<RelayerResponse> => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).catch(() => null);

  if (!response) throw new Error("NEAR Auth relayer is unreachable");

  const payload = await response.json().catch(() => ({}) as any);
  if (!response.ok) throw new Error(payload?.message || `NEAR Auth relayer rejected the request (${response.status})`);
  return payload as RelayerResponse;
};

/** Relays the approved payload to the fast-auth contract and returns the MPC signature. */
export const relaySignature = async (network: Network, request: SignatureRequest): Promise<Uint8Array> => {
  const { relayerBaseUrl } = getConfig(network);

  const { result } = await post(`${relayerBaseUrl}/relayer/fast-auth/sign-tx`, {
    guard_id: request.guardId,
    verify_payload: request.verifyPayload,
    sign_payload: request.signPayload,
    algorithm: ED25519_MPC_ALGORITHM,
  });

  return readEd25519Signature(result);
};

/**
 * Unwraps the MPC response. Ported from `FastAuthSignature` in the NEAR Auth browser SDK: the
 * contract returns the raw 64 bytes, older deployments return the ECDSA-shaped `big_r`/`s` pair.
 */
const readEd25519Signature = (outcome: FinalExecutionOutcome): Uint8Array => {
  const successValue = (outcome?.status as any)?.SuccessValue;
  if (!successValue) throw new Error("NEAR Auth MPC did not return a signature");

  const payload = JSON.parse(Buffer.from(successValue, "base64").toString());

  if (Array.isArray(payload?.signature)) {
    const signature = Uint8Array.from(payload.signature);
    if (signature.length !== 64) throw new Error("NEAR Auth MPC returned a malformed ed25519 signature");
    return signature;
  }

  const affinePoint = payload?.big_r?.affine_point;
  const scalar = payload?.s?.scalar;
  if (!affinePoint || !scalar) throw new Error("NEAR Auth MPC returned an unknown signature payload");

  return Uint8Array.from(Buffer.concat([normalize(affinePoint), normalize(scalar)]));
};

/** Left-pads (or trims the leading parity byte off) a hex component to exactly 32 bytes. */
const normalize = (hex: string): Buffer => {
  let bytes = Buffer.from(hex, "hex");
  if (bytes.length === 33) bytes = bytes.subarray(1);
  if (bytes.length > 32) bytes = bytes.subarray(bytes.length - 32);
  if (bytes.length < 32) bytes = Buffer.concat([Buffer.alloc(32 - bytes.length, 0), bytes]);
  return bytes;
};
