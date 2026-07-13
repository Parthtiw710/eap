import * as crypto from 'crypto';

export interface EapConfig {
  jwtSecret: string;
  allowedEmails: string[];
  rateLimitPerSec?: number;
  rateBurst?: number;
  s2sRateLimitPerSec?: number;
  s2sRateBurst?: number;
  googleClientId?: string;
  googleClientSecret?: string;
  googleRedirectUrl?: string;
  targetUrl?: string;
  tunnelToken?: string;
}

export interface PendingRequest {
  id: string;
  method: string;
  path: string;
  query: string;
  headers: Record<string, string[]>;
  body: string; // Base64 encoded body
}

export interface TunnelResponse {
  status: number;
  headers: Record<string, string[]>;
  body: string; // Base64 encoded body
}

interface ClientLimit {
  tokens: number;
  lastSeen: number;
}

export class EapEngine {
  private config: EapConfig;
  private clientLimits = new Map<string, ClientLimit>();
  private requestCounter = 0n;
  private activeRequests = new Map<string, (resp: TunnelResponse) => void>();
  private pendingRequests: PendingRequest[] = [];
  private pendingResolvers: (() => void)[] = [];

  public static fromEnv(): EapEngine {
    const allowedStr = process.env.ALLOWED_EMAILS || process.env.ADMIN_EMAIL || '';
    const allowedEmails = allowedStr.split(',').map((s) => s.trim()).filter(Boolean);

    const rateLimit = process.env.RATE_LIMIT_PER_SEC ? parseFloat(process.env.RATE_LIMIT_PER_SEC) : 3.0;
    const rateBurst = process.env.RATE_BURST ? parseFloat(process.env.RATE_BURST) : 5.0;
    const s2sLimit = process.env.S2S_RATE_LIMIT_PER_SEC ? parseFloat(process.env.S2S_RATE_LIMIT_PER_SEC) : 30.0;
    const s2sBurst = process.env.S2S_RATE_BURST ? parseFloat(process.env.S2S_RATE_BURST) : 100.0;

    return new EapEngine({
      jwtSecret: process.env.JWT_SECRET || '',
      allowedEmails,
      rateLimitPerSec: rateLimit,
      rateBurst: rateBurst,
      s2sRateLimitPerSec: s2sLimit,
      s2sRateBurst: s2sBurst,
      googleClientId: process.env.GOOGLE_CLIENT_ID,
      googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
      googleRedirectUrl: process.env.GOOGLE_REDIRECT_URL,
      targetUrl: process.env.TARGET_URL,
      tunnelToken: process.env.TUNNEL_TOKEN,
    });
  }

  constructor(config: EapConfig) {
    this.config = {
      rateLimitPerSec: 3,
      rateBurst: 5,
      s2sRateLimitPerSec: 30,
      s2sRateBurst: 100,
      ...config,
    };
  }

  // Middleware function for Express
  public middleware() {
    return async (req: any, res: any, next: any) => {
      const path = req.path || req.url.split('?')[0];

      // Bypass EAP endpoints
      if (['/login', '/auth/callback', '/logout', '/tunnel/poll', '/tunnel/respond'].includes(path)) {
        return this.handleEapRoute(req, res);
      }

      let email: string | null = null;
      let isS2S = false;

      // Extract bearer token or cookie session
      const authHeader = req.headers['authorization'];
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        try {
          email = this.verifySession(token);
          isS2S = true;
        } catch {
          return res.status(401).send('Unauthorized S2S token');
        }
      } else {
        const cookies = this.parseCookies(req.headers['cookie'] || '');
        const session = cookies['eap_session'];
        if (session) {
          try {
            email = this.verifySession(session);
          } catch {
            // Invalid session
          }
        }
      }

      // Check rate limiting
      if (this.isRateLimited(req, email, isS2S)) {
        if (isS2S) {
          res.setHeader('Retry-After', '1');
          return res.status(429).send('Too Many Requests');
        }
        return res.redirect(`/error/429?redirect_to=${encodeURIComponent(req.originalUrl || req.url)}`);
      }

      if (!email) {
        if (isS2S) return res.status(401).send('Unauthorized');
        res.setHeader('Set-Cookie', `redirect_to=${req.originalUrl || req.url}; Path=/; HttpOnly`);
        return res.redirect('/login');
      }

      if (!this.isEmailAllowed(email)) {
        return res.redirect('/error/403');
      }

      req.headers['x-user-email'] = email;

      if (this.config.targetUrl === 'tunnel') {
        return this.proxyThroughTunnel(req, res, email);
      }

      // Direct Proxy logic (using standard HTTP request in Node)
      next();
    };
  }

  private async handleEapRoute(req: any, res: any) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;

    if (path === '/login') {
      if (!this.config.googleClientId) {
        return res.status(500).send('OAuth not configured');
      }
      const redirectTo = url.searchParams.get('redirect_to') || '/';
      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${
        this.config.googleClientId
      }&redirect_uri=${encodeURIComponent(
        this.config.googleRedirectUrl || ''
      )}&response_type=code&scope=email%20profile&state=${encodeURIComponent(redirectTo)}`;
      return res.redirect(authUrl);
    }

    if (path === '/auth/callback') {
      const code = url.searchParams.get('code');
      if (!code) return res.redirect('/error/400');

      try {
        // Exchange code for token
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: this.config.googleClientId || '',
            client_secret: this.config.googleClientSecret || '',
            redirect_uri: this.config.googleRedirectUrl || '',
            grant_type: 'authorization_code',
          }),
        });

        const tokenData = await tokenRes.json();
        const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });

        const userData = await userRes.json();
        const email = userData.email;

        if (!email || !this.isEmailAllowed(email)) {
          return res.redirect('/error/403');
        }

        // Sign HS256 Token
        const sessionToken = this.signSession(email);
        const state = url.searchParams.get('state') || '/';

        res.setHeader('Set-Cookie', [
          `eap_session=${sessionToken}; Path=/; HttpOnly; Max-Age=86400`,
          `redirect_to=; Path=/; Max-Age=0`,
        ]);
        return res.redirect(state);
      } catch (err) {
        return res.redirect('/error/500');
      }
    }

    if (path === '/logout') {
      res.setHeader('Set-Cookie', 'eap_session=; Path=/; Max-Age=0');
      return res.redirect('/login');
    }

    if (path === '/tunnel/poll') {
      const token = url.searchParams.get('token');
      if (!this.config.tunnelToken || token !== this.config.tunnelToken) {
        return res.status(401).send('Unauthorized');
      }

      const getRequest = (): Promise<PendingRequest | null> => {
        return new Promise((resolve) => {
          if (this.pendingRequests.length > 0) {
            return resolve(this.pendingRequests.shift()!);
          }
          const timeout = setTimeout(() => {
            const idx = this.pendingResolvers.indexOf(resolver);
            if (idx > -1) this.pendingResolvers.splice(idx, 1);
            resolve(null);
          }, 15000);

          const resolver = () => {
            clearTimeout(timeout);
            resolve(this.pendingRequests.shift()!);
          };
          this.pendingResolvers.push(resolver);
        });
      };

      const pendingReq = await getRequest();
      if (!pendingReq) {
        return res.status(204).end();
      }
      return res.json(pendingReq);
    }

    if (path === '/tunnel/respond') {
      const token = url.searchParams.get('token');
      const id = url.searchParams.get('id');
      if (!this.config.tunnelToken || token !== this.config.tunnelToken) {
        return res.status(401).send('Unauthorized');
      }

      let body = '';
      req.on('data', (chunk: any) => {
        body += chunk;
      });
      req.on('end', () => {
        try {
          const respData: TunnelResponse = JSON.parse(body);
          const resolver = this.activeRequests.get(id || '');
          if (resolver) {
            resolver(respData);
            this.activeRequests.delete(id || '');
          }
          res.status(200).send('OK');
        } catch {
          res.status(400).send('Bad Request');
        }
      });
    }
  }

  private isEmailAllowed(email: string): boolean {
    const cleanEmail = email.toLowerCase().trim();
    return this.config.allowedEmails.some((pattern) => {
      const cleanPattern = pattern.toLowerCase().trim();
      if (cleanPattern.startsWith('@')) {
        return cleanEmail.endsWith(cleanPattern);
      }
      return cleanEmail === cleanPattern;
    });
  }

  private signSession(email: string): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { email, exp: Math.floor(Date.now() / 1000) + 86400 };

    const base64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
    const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');

    const signature = crypto
      .createHmac('sha256', this.config.jwtSecret)
      .update(`${base64Header}.${base64Payload}`)
      .digest('base64url');

    return `${base64Header}.${base64Payload}.${signature}`;
  }

  private verifySession(token: string): string {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token');
    const [headerB64, payloadB64, signature] = parts;

    const computedSignature = crypto
      .createHmac('sha256', this.config.jwtSecret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    if (signature !== computedSignature) throw new Error('Signature verification failed');

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() / 1000 > payload.exp) throw new Error('Token expired');

    return payload.email;
  }

  private isRateLimited(req: any, email: string | null, isS2S: boolean): boolean {
    const key = email || req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();

    const limitPerSec = isS2S ? this.config.s2sRateLimitPerSec! : this.config.rateLimitPerSec!;
    const burst = isS2S ? this.config.s2sRateBurst! : this.config.rateBurst!;

    let limit = this.clientLimits.get(key);
    if (!limit) {
      this.clientLimits.set(key, { tokens: burst - 1, lastSeen: now });
      return false;
    }

    const elapsed = (now - limit.lastSeen) / 1000;
    limit.tokens = Math.min(burst, limit.tokens + elapsed * limitPerSec);
    limit.lastSeen = now;

    if (limit.tokens >= 1) {
      limit.tokens -= 1;
      return false;
    }
    return true;
  }

  private async proxyThroughTunnel(req: any, res: any, email: string) {
    const id = (++this.requestCounter).toString();
    const headers: Record<string, string[]> = {};
    for (const key of Object.keys(req.headers)) {
      headers[key] = Array.isArray(req.headers[key]) ? req.headers[key] : [req.headers[key]];
    }
    headers['X-User-Email'] = [email];

    // Read body
    const bodyBuffer = await this.readRequestBody(req);
    const bodyBase64 = bodyBuffer.toString('base64');

    const pendingReq: PendingRequest = {
      id,
      method: req.method,
      path: req.path || req.url.split('?')[0],
      query: req.url.split('?')[1] || '',
      headers,
      body: bodyBase64,
    };

    const responsePromise = new Promise<TunnelResponse>((resolve) => {
      this.activeRequests.set(id, resolve);
    });

    this.pendingRequests.push(pendingReq);
    if (this.pendingResolvers.length > 0) {
      const resolver = this.pendingResolvers.shift();
      if (resolver) resolver();
    }

    try {
      const tunnelResp = await Promise.race([
        responsePromise,
        new Promise<null>((_, reject) => setTimeout(() => reject(new Error('Gateway Timeout')), 30000)),
      ]);

      if (!tunnelResp) {
        return res.status(504).send('Gateway Timeout');
      }

      res.status(tunnelResp.status);
      for (const [key, values] of Object.entries(tunnelResp.headers)) {
        res.setHeader(key, values);
      }
      res.send(Buffer.from(tunnelResp.body, 'base64'));
    } catch {
      res.status(504).send('Gateway Timeout');
    }
  }

  private readRequestBody(req: any): Promise<Buffer> {
    return new Promise((resolve) => {
      const chunks: any[] = [];
      req.on('data', (c: any) => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  private parseCookies(cookieStr: string): Record<string, string> {
    const list: Record<string, string> = {};
    cookieStr.split(';').forEach((cookie) => {
      const parts = cookie.split('=');
      list[parts.shift()!.trim()] = decodeURI(parts.join('='));
    });
    return list;
  }
}

// Tunnel Client Routine
export async function startTunnelClient(serverUrl: string, token: string, localPort: number) {
  const localAddr = `http://localhost:${localPort}`;
  const pollUrl = `${serverUrl}/tunnel/poll?token=${encodeURIComponent(token)}`;

  while (true) {
    try {
      const resp = await fetch(pollUrl);
      if (resp.status === 204) continue;
      if (resp.status !== 200) {
        await new Promise((r) => setTimeout(r, 3000));
        continue;
      }

      const reqData: PendingRequest = await resp.json();

      // Process async
      (async () => {
        let tunnelResp: TunnelResponse;
        try {
          const localUrl = `${localAddr}${reqData.path}${reqData.query ? '?' + reqData.query : ''}`;
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(reqData.headers)) {
            headers[k] = v[0];
          }

          const localRes = await fetch(localUrl, {
            method: reqData.method,
            headers,
            body: ['GET', 'HEAD'].includes(reqData.method.toUpperCase()) ? undefined : Buffer.from(reqData.body, 'base64'),
          });

          const localBody = await localRes.arrayBuffer();
          const responseHeaders: Record<string, string[]> = {};
          localRes.headers.forEach((value, name) => {
            responseHeaders[name] = [value];
          });

          tunnelResp = {
            status: localRes.status,
            headers: responseHeaders,
            body: Buffer.from(localBody).toString('base64'),
          };
        } catch (err: any) {
          tunnelResp = {
            status: 502,
            headers: {},
            body: Buffer.from(err.message).toString('base64'),
          };
        }

        // Post response back
        try {
          await fetch(`${serverUrl}/tunnel/respond?token=${encodeURIComponent(token)}&id=${encodeURIComponent(reqData.id)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(tunnelResp),
          });
        } catch {
          // ignore error
        }
      })();
    } catch {
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}
