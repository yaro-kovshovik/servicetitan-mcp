/**
 * Minimal OAuth 2.1 authorization server, bolted onto the Streamable HTTP transport
 * so native remote-connector clients (Claude web/Desktop/mobile) can authorize without
 * the mcp-remote local-proxy workaround, which only works for stdio-capable clients.
 *
 * Single confidential client (ID + secret registered once in the connector UI), single
 * shared password gates the interactive /authorize step, authorization code + PKCE (S256)
 * per the MCP authorization spec. All state is in-memory — consistent with this server's
 * existing single-instance-only session model.
 *
 * Entirely additive: if ST_OAUTH_CLIENT_ID / ST_OAUTH_CLIENT_SECRET / ST_OAUTH_PASSWORD /
 * ST_OAUTH_ISSUER_URL aren't all set, oauthConfigFromEnv() returns null and none of this
 * activates — the existing static ST_MCP_API_KEY path is untouched.
 */
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  password: string;
  issuerUrl: string;
}

interface AuthCodeRecord {
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
}

interface TokenRecord {
  expiresAt: number;
}

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 65_536;

const authCodes = new Map<string, AuthCodeRecord>();
const accessTokens = new Map<string, TokenRecord>();
const refreshTokens = new Map<string, TokenRecord>();

export function oauthConfigFromEnv(): OAuthConfig | null {
  const clientId = process.env.ST_OAUTH_CLIENT_ID ?? "";
  const clientSecret = process.env.ST_OAUTH_CLIENT_SECRET ?? "";
  const password = process.env.ST_OAUTH_PASSWORD ?? "";
  const issuerUrl = (process.env.ST_OAUTH_ISSUER_URL ?? "").replace(/\/+$/, "");
  if (!clientId || !clientSecret || !password || !issuerUrl) return null;
  return { clientId, clientSecret, password, issuerUrl };
}

function safeCompare(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string
  ));
}

async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("Request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function loginPage(hiddenFields: Record<string, string>, error?: string): string {
  const hidden = Object.entries(hiddenFields)
    .filter(([, value]) => value.length > 0)
    .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
    .join("\n");
  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ServiceTitan MCP — Sign in</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #131619; color: #eceef0;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  form { background: #1b1f23; padding: 2rem 2.25rem; border-radius: 12px; border: 1px solid #2b3136;
         width: min(320px, 90vw); }
  h1 { font-size: 1.05rem; margin: 0 0 1.25rem; font-weight: 600; }
  input[type=password] { width: 100%; padding: 0.6rem 0.7rem; border-radius: 8px; border: 1px solid #2b3136;
         background: #14171a; color: #eceef0; font-size: 0.95rem; box-sizing: border-box; }
  button { margin-top: 1rem; width: 100%; padding: 0.65rem; border-radius: 8px; border: none;
         background: #5fb8ae; color: #0c1a18; font-weight: 600; font-size: 0.95rem; cursor: pointer; }
  .err { color: #d99a3d; font-size: 0.85rem; margin-bottom: 0.75rem; }
</style></head>
<body>
<form method="post" action="/authorize">
  <h1>Sign in to ServiceTitan MCP</h1>
  ${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
  ${hidden}
  <input type="password" name="password" placeholder="Access password" autofocus required>
  <button type="submit">Continue</button>
</form>
</body></html>`;
}

export function wwwAuthenticateHeader(issuerUrl: string): string {
  return `Bearer resource_metadata="${issuerUrl}/.well-known/oauth-protected-resource"`;
}

export function oauthBearerAuthenticated(req: IncomingMessage): boolean {
  const authorization = req.headers.authorization;
  if (typeof authorization !== "string" || !/^Bearer /i.test(authorization)) return false;
  const token = authorization.slice(7);
  const record = accessTokens.get(token);
  if (!record) return false;
  if (Date.now() > record.expiresAt) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

/** Returns true if this route was handled (response already sent), false otherwise. */
export async function handleOAuthRoute(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  cfg: OAuthConfig,
): Promise<boolean> {
  if (url.pathname === "/.well-known/oauth-authorization-server" && req.method === "GET") {
    sendJson(res, 200, {
      issuer: cfg.issuerUrl,
      authorization_endpoint: `${cfg.issuerUrl}/authorize`,
      token_endpoint: `${cfg.issuerUrl}/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post"],
    });
    return true;
  }

  if (url.pathname === "/.well-known/oauth-protected-resource" && req.method === "GET") {
    sendJson(res, 200, {
      resource: `${cfg.issuerUrl}/mcp`,
      authorization_servers: [cfg.issuerUrl],
    });
    return true;
  }

  if (url.pathname === "/authorize" && req.method === "GET") {
    const p = url.searchParams;
    const fields = {
      response_type: p.get("response_type") ?? "",
      client_id: p.get("client_id") ?? "",
      redirect_uri: p.get("redirect_uri") ?? "",
      state: p.get("state") ?? "",
      code_challenge: p.get("code_challenge") ?? "",
      code_challenge_method: p.get("code_challenge_method") ?? "",
    };
    const valid = fields.response_type === "code"
      && fields.code_challenge_method === "S256"
      && fields.code_challenge.length > 0
      && fields.redirect_uri.length > 0
      && safeCompare(fields.client_id, cfg.clientId);
    if (!valid) {
      sendJson(res, 400, { error: "invalid_request" });
      return true;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(loginPage(fields));
    return true;
  }

  if (url.pathname === "/authorize" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const fields = {
      response_type: form.get("response_type") ?? "",
      client_id: form.get("client_id") ?? "",
      redirect_uri: form.get("redirect_uri") ?? "",
      state: form.get("state") ?? "",
      code_challenge: form.get("code_challenge") ?? "",
      code_challenge_method: form.get("code_challenge_method") ?? "",
    };
    const password = form.get("password") ?? "";

    if (!safeCompare(fields.client_id, cfg.clientId) || fields.code_challenge_method !== "S256" || !fields.redirect_uri) {
      sendJson(res, 400, { error: "invalid_request" });
      return true;
    }

    if (!safeCompare(password, cfg.password)) {
      res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
      res.end(loginPage(fields, "Wrong password — try again."));
      return true;
    }

    const code = randomToken();
    authCodes.set(code, {
      redirectUri: fields.redirect_uri,
      codeChallenge: fields.code_challenge,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });

    let redirect: URL;
    try {
      redirect = new URL(fields.redirect_uri);
    } catch {
      sendJson(res, 400, { error: "invalid_request", error_description: "Malformed redirect_uri" });
      return true;
    }
    redirect.searchParams.set("code", code);
    if (fields.state) redirect.searchParams.set("state", fields.state);
    res.writeHead(302, { Location: redirect.toString() });
    res.end();
    return true;
  }

  if (url.pathname === "/token" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const grantType = form.get("grant_type") ?? "";
    const clientId = form.get("client_id") ?? "";
    const clientSecret = form.get("client_secret") ?? "";

    if (!safeCompare(clientId, cfg.clientId) || !safeCompare(clientSecret, cfg.clientSecret)) {
      sendJson(res, 401, { error: "invalid_client" });
      return true;
    }

    if (grantType === "authorization_code") {
      const code = form.get("code") ?? "";
      const redirectUri = form.get("redirect_uri") ?? "";
      const verifier = form.get("code_verifier") ?? "";
      const record = authCodes.get(code);

      if (!record || Date.now() > record.expiresAt || record.redirectUri !== redirectUri) {
        sendJson(res, 400, { error: "invalid_grant" });
        return true;
      }
      if (!verifier || pkceChallenge(verifier) !== record.codeChallenge) {
        sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
        return true;
      }

      authCodes.delete(code);
      const accessToken = randomToken();
      const refreshToken = randomToken();
      accessTokens.set(accessToken, { expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS });
      refreshTokens.set(refreshToken, { expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS });
      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
        refresh_token: refreshToken,
      });
      return true;
    }

    if (grantType === "refresh_token") {
      const refreshToken = form.get("refresh_token") ?? "";
      const record = refreshTokens.get(refreshToken);
      if (!record || Date.now() > record.expiresAt) {
        sendJson(res, 400, { error: "invalid_grant" });
        return true;
      }
      const accessToken = randomToken();
      accessTokens.set(accessToken, { expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS });
      sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
      });
      return true;
    }

    sendJson(res, 400, { error: "unsupported_grant_type" });
    return true;
  }

  return false;
}
