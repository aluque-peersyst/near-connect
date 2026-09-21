import { sha256 } from "@noble/hashes/sha256";

/**
 * Minimal OAuth2 Authorization Code + PKCE client for Auth0.
 *
 * `@auth0/auth0-spa-js` cannot run inside a near-connect sandbox: it drives a real popup handle
 * (`popup.location.href = ...`), which the sandbox replaces with an async proxy, and it derives the
 * redirect uri from `window.location.origin`, which is `null` for a srcdoc iframe. The flow below is
 * the same protocol the SDK speaks, expressed through the `window.selector` primitives instead.
 */

const PKCE_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

const POPUP_WIDTH = 480;
const POPUP_HEIGHT = 720;

export interface Auth0Tokens {
  accessToken: string;
  idToken?: string;
  expiresIn: number;
}

export interface AuthorizeParams {
  /** Origin the dapp is served from. Must be an allowed callback url of the Auth0 application. */
  redirectUri: string;
  scope: string;
  /** Omitted for plain sign in, set to the signing audience to mint a `fatxn` token. */
  audience?: string;
  /** Extra authorize params, e.g. the borsh transaction the consent screen renders. */
  extraParams?: Record<string, string>;
  /** Copy shown in the sandbox when the browser blocks the popup. */
  fallbackPrompt?: { title: string; button: string };
}

const randomString = (length: number): string => {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => PKCE_CHARSET[byte % PKCE_CHARSET.length]).join("");
};

const base64UrlEncode = (bytes: Uint8Array): string => {
  let binary = "";
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const base64UrlDecode = (value: string): string => {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));
};

/** Reads a JWT body. The token is verified on chain by the guard, not here. */
export const decodeJwt = <T = Record<string, any>>(token: string): T => {
  const payload = token.split(".")[1];
  if (!payload) throw new Error("Malformed JWT returned by NEAR Auth");
  return JSON.parse(decodeURIComponent(escape(base64UrlDecode(payload))));
};

const popupFeatures = () => {
  const left = window.selector.screenX + (window.selector.outerWidth - POPUP_WIDTH) / 2;
  const top = window.selector.screenY + (window.selector.outerHeight - POPUP_HEIGHT) / 2;
  return `width=${POPUP_WIDTH},height=${POPUP_HEIGHT},top=${top},left=${left},resizable,scrollbars=yes,status=1`;
};

export class Auth0Client {
  constructor(readonly domain: string, readonly clientId: string) {}

  /** Origin of the embedding dapp, which Auth0 validates and posts the response back to. */
  static redirectUri(): string {
    const location = window.selector.location;
    if (!location) throw new Error("NEAR Auth requires the `location` manifest permission");
    return new URL(location).origin;
  }

  private authorizeUrl(params: AuthorizeParams, state: string, nonce: string, codeChallenge: string): string {
    const url = new URL(`https://${this.domain}/authorize`);
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", params.redirectUri);
    url.searchParams.set("response_type", "code");
    // Auth0 answers by posting the code to the window that opened the popup, so the sandbox never
    // has to read the popup's url (which it cannot do through the proxy handle).
    url.searchParams.set("response_mode", "web_message");
    url.searchParams.set("scope", params.scope);
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (params.audience) url.searchParams.set("audience", params.audience);

    Object.entries(params.extraParams ?? {}).forEach(([key, value]) => url.searchParams.set(key, value));
    return url.toString();
  }

  /**
   * Waits for the code Auth0 posts back to the window that opened the popup, which the connector
   * forwards into this sandbox. Armed before the popup opens, because with a live Auth0 session the
   * response can land almost immediately.
   */
  private awaitCode(state: string, isClosed: () => boolean) {
    let cancel = () => {};

    const promise = new Promise<string>((resolve, reject) => {
      const settle = (run: () => void) => {
        cancel();
        run();
      };

      const onMessage = (event: MessageEvent) => {
        const data = event.data;
        if (!data || data.type !== "authorization_response") return;

        const payload = data.response ?? {};
        if (payload.error) {
          const message = payload.error_description || payload.error;
          settle(() => reject(new Error(message === "Unauthorized" ? "NEAR Auth sign in was rejected" : message)));
          return;
        }

        // Guards against a response replayed from another authorize call.
        if (payload.state !== state) {
          settle(() => reject(new Error("NEAR Auth returned a response for another request")));
          return;
        }

        settle(() => resolve(payload.code));
      };

      const closeWatcher = setInterval(() => {
        if (isClosed()) settle(() => reject(new Error("User closed the NEAR Auth window")));
      }, 300);

      cancel = () => {
        window.removeEventListener("message", onMessage);
        clearInterval(closeWatcher);
      };

      window.addEventListener("message", onMessage);
    });

    // Nothing awaits this promise once it is cancelled, so keep it from becoming an unhandled rejection.
    promise.catch(() => {});
    return { promise, cancel: () => cancel() };
  }

  /** Opens the Auth0 modal and resolves with the authorization code it posts back. */
  private async requestCode(url: string, state: string, fallbackPrompt?: { title: string; button: string }): Promise<string> {
    let popup: ReturnType<typeof window.selector.open> | null = null;
    const { promise, cancel } = this.awaitCode(state, () => !!popup?.closed);

    popup = window.selector.open(url, "_blank", popupFeatures());
    const windowId = await popup.windowIdPromise;

    // The browser blocked the popup: ask for a click inside the sandbox and retry within its gesture.
    if (!windowId) {
      cancel();
      await window.selector.ui.whenApprove(fallbackPrompt ?? { title: "Continue with NEAR Auth", button: "Open NEAR Auth" });
      return await this.requestCode(url, state, fallbackPrompt);
    }

    try {
      return await promise;
    } finally {
      cancel();
      popup.close();
    }
  }

  private async exchangeCode(code: string, codeVerifier: string, redirectUri: string): Promise<Auth0Tokens> {
    const response = await fetch(`https://${this.domain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: this.clientId,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        code,
      }),
    });

    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error_description || body.error || "NEAR Auth token exchange failed");

    return { accessToken: body.access_token, idToken: body.id_token, expiresIn: body.expires_in };
  }

  /** DEMO BUILD ONLY: stands in for the interactive Auth0 step with a fixed identity. */
  async authorize(_params: AuthorizeParams): Promise<Auth0Tokens> {
    await new Promise((resolve) => setTimeout(resolve, 900));
    return { accessToken: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiZ29vZ2xlLW9hdXRoMnwxMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCAiaXNzIjogImh0dHBzOi8vbG9naW4udGVzdG5ldC5mYXN0LWF1dGguY29tLyJ9.stub", idToken: "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiZ29vZ2xlLW9hdXRoMnwxMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCAiaXNzIjogImh0dHBzOi8vbG9naW4udGVzdG5ldC5mYXN0LWF1dGguY29tLyJ9.stub", expiresIn: 60 };
  }

  async realAuthorize(params: AuthorizeParams): Promise<Auth0Tokens> {
    const codeVerifier = randomString(64);
    const codeChallenge = base64UrlEncode(sha256(new TextEncoder().encode(codeVerifier)));
    const state = randomString(32);
    const nonce = randomString(32);

    const url = this.authorizeUrl(params, state, nonce, codeChallenge);
    const code = await this.requestCode(url, state, params.fallbackPrompt);
    return await this.exchangeCode(code, codeVerifier, params.redirectUri);
  }

  /** Ends the Auth0 session so the next sign in asks for credentials again. */
  logoutUrl(returnTo: string): string {
    const url = new URL(`https://${this.domain}/v2/logout`);
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("returnTo", returnTo);
    return url.toString();
  }
}
