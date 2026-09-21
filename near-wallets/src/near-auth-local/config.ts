import type { Network } from "../utils/types";

export interface NearAuthNetworkConfig {
  /** Auth0 tenant that issues the JWTs the on-chain guard trusts. */
  auth0Domain: string;
  /** Auth0 application (SPA, PKCE) registered for NEAR Auth. */
  auth0ClientId: string;
  /** Audience that makes Auth0 mint a token carrying the `fatxn` signing claim. */
  signingAudience: string;
  /** MPC contract deriving the user key from the JWT path. */
  mpcContractId: string;
  /** Contract calling the MPC on behalf of the user, also the derivation predecessor. */
  fastAuthContractId: string;
  /** Indexer used to map a derived public key back to its account ids. */
  fastNearApiBaseUrl: string;
  /** NEAR Auth relayer paying gas for the `sign` call (no key ever leaves the MPC). */
  relayerBaseUrl: string;
  /** Fallback RPCs, used when the dapp does not pass its own to NearConnector. */
  rpcUrls: string[];
}

export const NEAR_AUTH_CONFIG: Record<Network, NearAuthNetworkConfig> = {
  mainnet: {
    auth0Domain: "login.auth.near.org",
    auth0ClientId: "dsurLc47fOcWme5PkYeClBvuW0tYrmgW",
    signingAudience: "auth0.jwt.fast-auth.near",
    mpcContractId: "v1.signer",
    fastAuthContractId: "fast-auth.near",
    fastNearApiBaseUrl: "https://api.fastnear.com/v0",
    relayerBaseUrl: "https://fast-auth-production.aws.peersyst.tech/api",
    rpcUrls: ["https://rpc.mainnet.near.org", "https://free.rpc.fastnear.com"],
  },

  testnet: {
    auth0Domain: "login.testnet.fast-auth.com",
    auth0ClientId: "np8paqIpMWmNbzT4xAvOOapZBjsOpptl",
    signingAudience: "auth0.jwt.fast-auth.testnet",
    mpcContractId: "v1.signer-prod.testnet",
    fastAuthContractId: "fast-auth.testnet",
    fastNearApiBaseUrl: "https://test.api.fastnear.com/v0",
    relayerBaseUrl: "http://localhost:3001/api", // LOCAL TEST BUILD
    rpcUrls: ["https://rpc.testnet.near.org", "https://test.rpc.fastnear.com"],
  },
};

export const getConfig = (network: Network): NearAuthNetworkConfig => {
  const config = NEAR_AUTH_CONFIG[network];
  if (!config) throw new Error(`NEAR Auth does not support network "${network}"`);
  return config;
};

/** ed25519 domain in the MPC contract. NEAR accounts use ed25519 keys. */
export const ED25519_DOMAIN_ID = 1;

/** Name the MPC contract gives the ed25519 curve in its `sign` arguments. */
export const ED25519_MPC_ALGORITHM = "eddsa";

/** Guard the fast-auth contract uses to verify JWTs of this Auth0 tenant. */
export const getGuardId = (auth0Domain: string) => `jwt#https://${auth0Domain}/`;

/** Derivation path: the guard plus the subject claim, so each user gets its own key. */
export const getDerivationPath = (auth0Domain: string, sub: string) => `${getGuardId(auth0Domain)}#${sub}`;
