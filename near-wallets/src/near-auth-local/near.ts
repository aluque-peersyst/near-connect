import type { AccessKeyViewRaw, FinalExecutionOutcome } from "@near-js/types";
import * as nearAPI from "near-api-js";

import { NearRpc } from "../utils/rpc";
import { ED25519_DOMAIN_ID, getConfig } from "./config";
import type { Network } from "../utils/types";

const { transactions: nearApiTransactions, utils: nearApiUtils } = nearAPI;

/** near-api-js bundles its own @near-js/transactions copy, so take the type from there. */
export type NearTransaction = nearAPI.transactions.Transaction;

const rpcs: Partial<Record<Network, NearRpc>> = {};

/** Prefers the RPCs the dapp passed to NearConnector, falling back to the NEAR Auth defaults. */
export const getRpc = (network: Network): NearRpc => {
  if (!rpcs[network]) {
    const dappProviders = window.selector?.providers?.[network] ?? [];
    rpcs[network] = new NearRpc(dappProviders.length ? dappProviders : getConfig(network).rpcUrls);
  }
  return rpcs[network]!;
};

/**
 * Asks the MPC contract for the key it derives for this user. The private half never exists: the
 * MPC network only ever produces signatures for a JWT that the on-chain guard has verified.
 */
export const derivePublicKey = async (network: Network, path: string): Promise<string> => {
  const config = getConfig(network);
  return await getRpc(network).viewMethod({
    contractId: config.mpcContractId,
    methodName: "derived_public_key",
    args: { path, predecessor: config.fastAuthContractId, domain_id: ED25519_DOMAIN_ID },
  });
};

/** Accounts the derived key can already sign for, newest style (named) accounts included. */
export const findAccountIds = async (network: Network, publicKey: string): Promise<string[]> => {
  const { fastNearApiBaseUrl } = getConfig(network);
  const url = `${fastNearApiBaseUrl}/public_key/${encodeURIComponent(publicKey)}/all`;

  const response = await fetch(url).catch(() => null);
  if (!response || !response.ok) return [];

  const body = await response.json().catch(() => null);
  return Array.isArray(body?.account_ids) ? body.account_ids : [];
};

/**
 * Implicit account id of an ed25519 key: the hex of its raw bytes. Used when the derived key does
 * not control a named account yet, so the user still gets a usable, deterministic NEAR address.
 */
export const implicitAccountId = (publicKey: string): string => {
  return Buffer.from(nearApiUtils.PublicKey.from(publicKey).data).toString("hex");
};

/** Builds the transaction the user is asked to approve. */
export const buildTransaction = async (
  network: Network,
  params: { signerId: string; publicKey: string; receiverId: string; actions: any[] }
): Promise<NearTransaction> => {
  const rpc = getRpc(network);

  const [block, accessKey] = await Promise.all([
    rpc.block({ finality: "final" }),
    rpc.query<AccessKeyViewRaw>({
      request_type: "view_access_key",
      finality: "final",
      account_id: params.signerId,
      public_key: params.publicKey,
    }),
  ]);

  return nearApiTransactions.createTransaction(
    params.signerId,
    nearApiUtils.PublicKey.from(params.publicKey),
    params.receiverId,
    accessKey.nonce + 1,
    params.actions,
    nearApiUtils.serialize.base_decode(block.header.hash)
  );
};

/** Auth0 carries the transaction as the decimal byte list its consent screen decodes. */
export const encodeTransactionParam = (transaction: NearTransaction): string => {
  return Array.from(transaction.encode()).join(",");
};

export const broadcast = async (network: Network, signedTransaction: nearAPI.transactions.SignedTransaction): Promise<FinalExecutionOutcome> => {
  return await getRpc(network).sendTransaction(signedTransaction as any);
};

export { nearApiTransactions, nearApiUtils };
