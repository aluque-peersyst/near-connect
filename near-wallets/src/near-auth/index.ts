import { connectorActionsToNearApiJsActions, type ConnectorAction } from "../utils/action";
import type { Network, SignInParams } from "../utils/types";

import { Auth0Client, decodeJwt } from "./auth0";
import { getConfig, getDerivationPath, getGuardId } from "./config";
import * as near from "./near";
import type { NearTransaction } from "./near";
import { relaySignature } from "./relayer";
import { hide, pickAccount } from "./ui";

/**
 * NEAR Auth — social login for NEAR, backed by fast-auth.
 *
 * There is no key material anywhere in this executor. Signing in proves an identity to Auth0; the
 * key that signs is derived by the MPC network from that identity, and it only ever signs a payload
 * the user approved on Auth0's own consent screen.
 */

interface Session {
  /** Auth0 subject claim: the stable identity the MPC key is derived from. */
  sub: string;
  accountId: string;
  publicKey: string;
}

const SIGN_IN_SCOPE = "openid profile email";
const SIGNING_SCOPE = "openid transaction:sign";

const sessionKey = (network: Network) => `session:${network}`;

const loadSession = async (network: Network): Promise<Session | null> => {
  const raw = await window.selector.storage.get(sessionKey(network));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
};

const saveSession = async (network: Network, session: Session) => {
  await window.selector.storage.set(sessionKey(network), JSON.stringify(session));
};

const requireSession = async (network: Network, signerId?: string): Promise<Session> => {
  const session = await loadSession(network);
  if (!session) throw new Error("Not signed in to NEAR Auth");
  if (signerId && signerId !== session.accountId) throw new Error(`NEAR Auth is not signed in as ${signerId}`);
  return session;
};

const createAuth0Client = (network: Network) => {
  const { auth0Domain, auth0ClientId } = getConfig(network);
  return new Auth0Client(auth0Domain, auth0ClientId);
};

/**
 * Picks the account the derived key signs for. Falls back to the key's implicit account, which is a
 * valid NEAR address for that key as soon as it is funded, so sign in never dead-ends.
 */
const resolveAccountId = async (network: Network, publicKey: string): Promise<string> => {
  const accountIds = await near.findAccountIds(network, publicKey);
  if (accountIds.length === 1) return accountIds[0];
  if (accountIds.length > 1) return await pickAccount(accountIds);
  return near.implicitAccountId(publicKey);
};

/** Auth0 renders the transaction, the user approves it, and the token comes back carrying its bytes. */
const approveTransaction = async (network: Network, transaction: NearTransaction) => {
  const config = getConfig(network);

  const tokens = await createAuth0Client(network).authorize({
    redirectUri: Auth0Client.redirectUri(),
    audience: config.signingAudience,
    scope: SIGNING_SCOPE,
    extraParams: { transaction: near.encodeTransactionParam(transaction) },
    fallbackPrompt: { title: "Approve this transaction", button: "Review in NEAR Auth" },
  });

  const { fatxn } = decodeJwt<{ fatxn?: number[] }>(tokens.accessToken);
  if (!Array.isArray(fatxn)) throw new Error("NEAR Auth returned no approved transaction");

  return { accessToken: tokens.accessToken, approvedBytes: fatxn, guardId: getGuardId(config.auth0Domain) };
};

const signAndSend = async (network: Network, transaction: NearTransaction) => {
  const { accessToken, approvedBytes, guardId } = await approveTransaction(network, transaction);

  const signature = await relaySignature(network, {
    guardId,
    verifyPayload: accessToken,
    signPayload: approvedBytes,
  });

  // Broadcast exactly the bytes the user approved rather than the locally built copy.
  const signedTransaction = new near.nearApiTransactions.SignedTransaction({
    transaction: near.nearApiTransactions.Transaction.decode(Buffer.from(approvedBytes)),
    signature: new near.nearApiTransactions.Signature({
      keyType: near.nearApiUtils.key_pair.KeyType.ED25519,
      data: signature,
    }),
  });

  return await near.broadcast(network, signedTransaction);
};

const NearAuthWallet = {
  async signIn({ network, addFunctionCallKey }: SignInParams) {
    if (addFunctionCallKey) throw new Error("NEAR Auth cannot add a function call access key during sign in");

    const existing = await loadSession(network);
    if (existing) return [{ accountId: existing.accountId, publicKey: existing.publicKey }];

    const config = getConfig(network);

    try {
      const tokens = await createAuth0Client(network).authorize({
        redirectUri: Auth0Client.redirectUri(),
        scope: SIGN_IN_SCOPE,
        fallbackPrompt: { title: "Sign in with NEAR Auth", button: "Continue" },
      });

      const { sub } = decodeJwt<{ sub?: string }>(tokens.idToken ?? tokens.accessToken);
      if (!sub) throw new Error("NEAR Auth returned no identity");

      const publicKey = await near.derivePublicKey(network, getDerivationPath(config.auth0Domain, sub));
      const accountId = await resolveAccountId(network, publicKey);

      await saveSession(network, { sub, accountId, publicKey });
      return [{ accountId, publicKey }];
    } finally {
      hide();
    }
  },

  async signInAndSignMessage(): Promise<never> {
    throw new Error("NEAR Auth does not support signing messages yet");
  },

  async signMessage(): Promise<never> {
    throw new Error("NEAR Auth does not support signing messages yet");
  },

  async signOut({ network }: { network: Network }) {
    // Only the connection is dropped. The Auth0 session stays in the browser, so reconnecting is one
    // click, the same as `logout()` without a redirect in the NEAR Auth browser SDK.
    await window.selector.storage.remove(sessionKey(network));
  },

  async getAccounts({ network }: { network: Network }) {
    const session = await loadSession(network);
    if (!session) return [];
    return [{ accountId: session.accountId, publicKey: session.publicKey }];
  },

  async signAndSendTransaction(payload: { network: Network; signerId?: string; receiverId: string; actions: ConnectorAction[] }) {
    const session = await requireSession(payload.network, payload.signerId);

    const transaction = await near.buildTransaction(payload.network, {
      signerId: session.accountId,
      publicKey: session.publicKey,
      receiverId: payload.receiverId,
      actions: connectorActionsToNearApiJsActions(payload.actions),
    });

    return await signAndSend(payload.network, transaction);
  },

  async signAndSendTransactions(payload: {
    network: Network;
    signerId?: string;
    transactions: { receiverId: string; actions: ConnectorAction[] }[];
  }) {
    const session = await requireSession(payload.network, payload.signerId);
    const outcomes = [];

    // Each transaction gets its own approval, so they are built and sent one at a time to keep the
    // nonce in step with what actually landed.
    for (const transaction of payload.transactions) {
      const built = await near.buildTransaction(payload.network, {
        signerId: session.accountId,
        publicKey: session.publicKey,
        receiverId: transaction.receiverId,
        actions: connectorActionsToNearApiJsActions(transaction.actions),
      });

      outcomes.push(await signAndSend(payload.network, built));
    }

    return outcomes;
  },
};

window.selector.ready(NearAuthWallet);
