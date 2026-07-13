# Universal EAP Tunnel Gateway Setup

This guide provides the setups to deploy your secure EAP Tunnel Gateway. You can run it as a persistent, stateful application (recommended for Render, Railway, or local testing) or as a serverless Cloudflare Worker using a free Upstash Redis database to coordinate state.

---

## 1. Stateful Node.js Gateway (Memory & Redis Hybrid)

If you are deploying to **Render**, **Railway**, **Fly.io**, or running **locally**, use this script. It uses local memory by default (no database needed) but automatically upgrades to Redis if the `REDIS_URL` environment variables are present.

Save this code as `gateway.js`:

```javascript
const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const TUNNEL_TOKEN = process.env.TUNNEL_TOKEN;

const REDIS_URL = process.env.REDIS_URL;
const REDIS_TOKEN = process.env.REDIS_TOKEN;

const pendingRequests = [];
const pendingResolvers = [];
const activeRequests = new Map();

async function redisCmd(commandArray) {
  try {
    const response = await fetch(REDIS_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${REDIS_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(commandArray),
    });
    const data = await response.json();
    return data.result;
  } catch (err) {
    console.error('[Redis Error]', err.message);
    return null;
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  const token = url.searchParams.get('token');
  const useRedis = !!(REDIS_URL && REDIS_TOKEN);

  if (path === '/tunnel/poll') {
    if (token !== TUNNEL_TOKEN) {
      res.writeHead(401);
      return res.end('Unauthorized');
    }
    if (useRedis) {
      const rawReq = await redisCmd(['LPOP', 'eap:pending_requests']);
      if (!rawReq) {
        res.writeHead(204);
        return res.end();
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(rawReq);
    } else {
      const getRequest = () => new Promise((resolve) => {
        if (pendingRequests.length > 0) return resolve(pendingRequests.shift());
        const timeout = setTimeout(() => {
          const idx = pendingResolvers.indexOf(resolver);
          if (idx > -1) pendingResolvers.splice(idx, 1);
          resolve(null);
        }, 15000);
        const resolver = () => {
          clearTimeout(timeout);
          resolve(pendingRequests.shift());
        };
        pendingResolvers.push(resolver);
      });
      const pending = await getRequest();
      if (!pending) {
        res.writeHead(204);
        return res.end();
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(pending));
    }
  }

  if (path === '/tunnel/respond') {
    if (token !== TUNNEL_TOKEN) {
      res.writeHead(401);
      return res.end('Unauthorized');
    }
    const id = url.searchParams.get('id');
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', async () => {
      try {
        if (useRedis) {
          await redisCmd(['SET', `eap:response:${id}`, body, 'EX', '60']);
        } else {
          const resolver = activeRequests.get(id);
          if (resolver) {
            resolver(JSON.parse(body));
            activeRequests.delete(id);
          }
        }
        res.writeHead(200);
        res.end('OK');
      } catch (err) {
        res.writeHead(400);
        res.end('Bad Request');
      }
    });
    return;
  }

  // Forward request down the tunnel
  const id = crypto.randomUUID();
  const headers = {};
  for (const [key, val] of Object.entries(req.headers)) {
    headers[key] = Array.isArray(val) ? val : [val];
  }

  const bodyChunks = [];
  req.on('data', (chunk) => { bodyChunks.push(chunk); });
  req.on('end', async () => {
    const reqBody = Buffer.concat(bodyChunks);
    const pendingReq = {
      id,
      method: req.method,
      path: path + url.search,
      headers,
      body: reqBody.toString('base64'),
    };

    if (useRedis) {
      await redisCmd(['RPUSH', 'eap:pending_requests', JSON.stringify(pendingReq)]);
      let tunnelResp = null;
      const start = Date.now();
      while (Date.now() - start < 30000) {
        const val = await redisCmd(['GET', `eap:response:${id}`]);
        if (val) {
          tunnelResp = JSON.parse(val);
          await redisCmd(['DEL', `eap:response:${id}`]);
          break;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      if (!tunnelResp) {
        res.writeHead(504);
        return res.end('Gateway Timeout');
      }
      const respHeaders = {};
      for (const [key, values] of Object.entries(tunnelResp.headers)) {
        respHeaders[key] = values;
      }
      res.writeHead(tunnelResp.status, respHeaders);
      res.end(Buffer.from(tunnelResp.body, 'base64'));
    } else {
      pendingRequests.push(pendingReq);
      if (pendingResolvers.length > 0) pendingResolvers.shift()();
      const responsePromise = new Promise((resolve) => {
        activeRequests.set(id, resolve);
        setTimeout(() => { if (activeRequests.delete(id)) resolve(null); }, 30000);
      });
      const tunnelResp = await responsePromise;
      if (!tunnelResp) {
        res.writeHead(504);
        return res.end('Gateway Timeout');
      }
      const respHeaders = {};
      for (const [key, values] of Object.entries(tunnelResp.headers)) {
        respHeaders[key] = values;
      }
      res.writeHead(tunnelResp.status, respHeaders);
      res.end(Buffer.from(tunnelResp.body, 'base64'));
    }
  });
});

server.listen(PORT, () => {
  console.log(`Localtunnel Gateway Server listening on port ${PORT} (Redis Mode: ${useRedis})`);
});
```

---

## 2. Cloudflare Workers Gateway (Serverless Redis Mode)

Because Cloudflare Workers are stateless and scale across multiple edge isolates, they cannot share memory queues. You **must** configure a free Upstash Redis database to coordinate state between incoming requests.

Copy and paste this code directly into your **Cloudflare Workers** dashboard:

```javascript
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const token = url.searchParams.get('token');
    const expectedToken = env.TUNNEL_TOKEN;
    const redisUrl = env.REDIS_URL;
    const redisToken = env.REDIS_TOKEN;

    if (!redisUrl || !redisToken) {
      return new Response("Configuration Error: REDIS_URL and REDIS_TOKEN must be set.", { status: 500 });
    }

    async function redisCmd(cmd) {
      try {
        const resp = await fetch(redisUrl, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${redisToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(cmd)
        });
        const data = await resp.json();
        return data.result;
      } catch (err) {
        return null;
      }
    }

    if (path === '/tunnel/poll') {
      if (token !== expectedToken) return new Response('Unauthorized', { status: 401 });
      const rawReq = await redisCmd(['LPOP', 'eap:pending_requests']);
      if (!rawReq) return new Response(null, { status: 204 });
      return new Response(rawReq, { headers: { 'Content-Type': 'application/json' } });
    }

    if (path === '/tunnel/respond') {
      if (token !== expectedToken) return new Response('Unauthorized', { status: 401 });
      const id = url.searchParams.get('id');
      const body = await request.text();
      await redisCmd(['SET', `eap:response:${id}`, body, 'EX', '60']);
      return new Response('OK');
    }

    // Public request routing
    const id = crypto.randomUUID();
    const headers = {};
    for (const [key, val] of request.headers.entries()) {
      headers[key] = [val];
    }

    const reqBody = await request.arrayBuffer();
    const binary = String.fromCharCode(...new Uint8Array(reqBody));
    const base64Body = btoa(binary);

    const pendingReq = {
      id,
      method: request.method,
      path: path + url.search,
      headers,
      body: base64Body
    };

    await redisCmd(['RPUSH', 'eap:pending_requests', JSON.stringify(pendingReq)]);

    let tunnelResp = null;
    const start = Date.now();
    while (Date.now() - start < 30000) {
      const val = await redisCmd(['GET', `eap:response:${id}`]);
      if (val) {
        tunnelResp = JSON.parse(val);
        await redisCmd(['DEL', `eap:response:${id}`]);
        break;
      }
      await new Promise(r => setTimeout(r, 200));
    }

    if (!tunnelResp) {
      return new Response('Gateway Timeout', { status: 504 });
    }

    const respHeaders = new Headers();
    for (const [key, values] of Object.entries(tunnelResp.headers)) {
      for (const val of values) {
        respHeaders.append(key, val);
      }
    }

    const binaryString = atob(tunnelResp.body);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return new Response(bytes, {
      status: tunnelResp.status,
      headers: respHeaders
    });
  }
};
```

---

## 3. Environment Variables Configuration

Configure the local application `.env` file where the EAP library/middleware is imported:

```env
# EAP Auth configurations
JWT_SECRET=your_local_jwt_secret
ALLOWED_EMAILS=your_email@gmail.com
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URL=https://your-deployed-subdomain.com/auth/callback

# Tunnel Connection (Gateway) configurations
EAP_SERVER_URL=https://your-deployed-subdomain.com   # The public URL of the gateway
TUNNEL_TOKEN=7619f6a0-fcdc-446b-894a-faf19d347263eabe632c7e584d61b7ce35c14b735a28
```

