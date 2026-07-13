const http = require('http');
const { EapEngine, startTunnelClient } = require('@arcops/eap');

const port = process.env.PORT || 3000;

// Initialize the EAP Engine using environment variables
const engine = EapEngine.fromEnv();
const middleware = engine.middleware();

const server = http.createServer((req, res) => {
  // Simple shims for Express response helpers used by the EAP middleware
  res.status = (code) => {
    res.statusCode = code;
    return {
      send: (msg) => {
        res.setHeader('Content-Type', 'text/plain');
        res.end(msg);
      }
    };
  };

  res.redirect = (url) => {
    res.writeHead(302, { Location: url });
    res.end();
  };

  // Run EAP Middleware
  middleware(req, res, () => {
    // If authentication succeeds, handle the request
    if (req.url === '/' || req.url.startsWith('/?')) {
      const email = req.headers['x-user-email'] || 'anonymous';
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<h1>Hello, user email is: ${email}</h1>`);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });
});

// Start Server
server.listen(port, () => {
  console.log(`Demo app listening at http://localhost:${port}`);

  // Automatically start the Localtunnel client if EAP_SERVER_URL is provided
  const eapServerUrl = process.env.EAP_SERVER_URL;
  const tunnelToken = process.env.TUNNEL_TOKEN;

  if (eapServerUrl && tunnelToken) {
    console.log(`[Tunnel] Starting client. Connecting to gateway: ${eapServerUrl}`);
    startTunnelClient(eapServerUrl, tunnelToken, port)
      .then(() => console.log('[Tunnel] Client connected and polling.'))
      .catch((err) => console.error('[Tunnel] Client error:', err));
  } else {
    console.log('[Tunnel] Client skipped (EAP_SERVER_URL or TUNNEL_TOKEN not set in environment).');
  }
});
