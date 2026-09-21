# NEAR Auth

Social login for NEAR, backed by [fast-auth](https://auth.near.org). The user signs in with Google,
email or a passkey; the key that signs their transactions is derived by the NEAR MPC network from
that identity, so there is no seed phrase and no key material in this executor.

## Flow

| Step | What happens |
| --- | --- |
| `signIn` | OAuth2 Authorization Code + PKCE against the NEAR Auth Auth0 tenant, in a popup. The `sub` claim becomes the derivation path `jwt#https://<domain>/#<sub>`, the MPC contract returns the user's ed25519 key, and the FastNEAR indexer maps that key to the account(s) it controls. |
| `signAndSendTransaction` | The transaction is built locally, borsh-encoded into the `transaction` authorize param, and rendered on Auth0's own consent screen. Approving mints a token carrying the approved bytes in its `fatxn` claim. The NEAR Auth relayer pays for the `sign` call on the fast-auth contract, and the MPC signature is broadcast with the exact bytes the user approved. |
| `signOut` | Drops the connection. The Auth0 session stays in the browser, so reconnecting is one click. |

`signMessage`, `signInAndSignMessage`, `signInWithFunctionCallKey` and `signDelegateActions` are not
supported: the Auth0 signing action only accepts a `transaction` or a `delegateAction` payload, so
there is nothing to sign an arbitrary NEP-413 message with. The manifest declares them `false`.

## Why not `@auth0/auth0-spa-js`

The SDK cannot run in a near-connect sandbox. It drives a real popup handle (`popup.location.href = …`),
which the sandbox replaces with an async proxy, and it derives `redirect_uri` from
`window.location.origin`, which is `null` for a srcdoc iframe. [`auth0.ts`](./auth0.ts) speaks the same
protocol through the `window.selector` primitives instead.

## What a dapp needs

- **Its origin registered with NEAR Auth.** Auth0 validates `redirect_uri` and posts the
  authorization response back to that origin, so the dapp's origin must be an allowed callback URL on
  the NEAR Auth Auth0 application. This is the same requirement as integrating the NEAR Auth browser
  SDK directly.
- **Nothing else.** RPC endpoints passed to `NearConnector` are reused; otherwise the defaults in
  [`config.ts`](./config.ts) apply.

## Configuration

Per-network endpoints live in [`config.ts`](./config.ts): the Auth0 tenant, the MPC and fast-auth
contracts, the FastNEAR indexer and the relayer base url.
