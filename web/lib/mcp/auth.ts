/**
 * Bearer-token authentication + rate limiting for the hosted MCP endpoint.
 *
 * Called by web/app/api/mcp/[transport]/route.ts on every request. Uses the
 * atomic `increment_mcp_call` RPC to look up the token, enforce the per-tier
 * daily quota, and bump the usage counter in a single round-trip.
 */

import { getServiceClient } from './db';
import { extractBearer, hashToken } from './tokens';

export interface AuthContext {
  tokenId: string;
  userId: string;
  tier: 'free' | 'pro' | 'admin' | 'blocked';
  limit: number;
  remaining: number;
}

type AuthRpcResult =
  | { ok: true; token_id: string; user_id: string; tier: AuthContext['tier']; limit: number; remaining: number }
  | { ok: false; reason: 'invalid_token' | 'revoked' | 'blocked' | 'quota_exceeded'; [k: string]: unknown };

/**
 * Authenticate a Request for the MCP endpoint.
 * Returns either { context } on success or { response } with a fully-formed
 * JSON-RPC error Response to return directly to the client.
 */
export async function authenticateMcpRequest(
  request: Request,
): Promise<{ context: AuthContext; response?: undefined } | { context?: undefined; response: Response }> {
  const authHeader =
    request.headers.get('authorization') ??
    request.headers.get('Authorization') ??
    request.headers.get('x-mcp-token');

  const token = extractBearer(authHeader);
  if (!token) {
    return { response: errorResponse(401, -32001, 'Missing or invalid bearer token. Generate one at https://detect.michaelhaag.org/account/tokens') };
  }

  const tokenHash = hashToken(token);
  const supabase = getServiceClient();

  const { data, error } = await supabase.rpc('increment_mcp_call', { p_token_hash: tokenHash });

  if (error) {
    console.error('[mcp-auth] RPC error:', error.message);
    return { response: errorResponse(500, -32603, 'Auth backend error') };
  }

  const result = data as AuthRpcResult | null;
  if (!result) {
    return { response: errorResponse(500, -32603, 'Auth backend returned no data') };
  }

  if (!result.ok) {
    switch (result.reason) {
      case 'invalid_token':
        return { response: errorResponse(401, -32001, 'Invalid token. Check your Authorization header.') };
      case 'revoked':
        return { response: errorResponse(401, -32001, 'Token has been revoked. Generate a new one at /account/tokens') };
      case 'blocked':
        return { response: errorResponse(403, -32002, 'Account blocked. Contact support.') };
      case 'quota_exceeded':
        return {
          response: errorResponse(
            429,
            -32003,
            `Daily quota exceeded (${result.limit} calls/day). Resets at 00:00 UTC. Upgrade to Pro for higher limits.`,
          ),
        };
      default:
        return { response: errorResponse(401, -32001, 'Authentication failed') };
    }
  }

  return {
    context: {
      tokenId: result.token_id,
      userId: result.user_id,
      tier: result.tier,
      limit: result.limit,
      remaining: result.remaining,
    },
  };
}

function errorResponse(httpStatus: number, jsonRpcCode: number, message: string): Response {
  const body = {
    jsonrpc: '2.0',
    error: { code: jsonRpcCode, message },
    id: null,
  };
  return new Response(JSON.stringify(body), {
    status: httpStatus,
    headers: {
      'Content-Type': 'application/json',
      'WWW-Authenticate': 'Bearer realm="mcp"',
    },
  });
}
