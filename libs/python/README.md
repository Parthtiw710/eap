# EAP Python Middleware

External Authentication Proxy (EAP) Middleware and Client SDK for Python.

## Installation
```bash
pip install eap-middleware
```

## Usage

```python
from eap import EapEngine

# Automatically loads configuration from environment variables
engine = EapEngine.from_env()

# In a FastAPI/Starlette app:
app.add_middleware(engine.asgi_middleware())
```

## Configuration (Environment Variables)

When initializing the engine with `EapEngine.from_env()`, EAP reads configuration directly from environment variables. Configure these variables in your host environment or `.env` file:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | Cryptographic secret used to sign session cookies (`HS256`). | *Required* |
| `ALLOWED_EMAILS` | Comma-separated whitelist of allowed user emails or domains (e.g. `admin@gmail.com, @iiitkota.ac.in`). | *Required* |
| `GOOGLE_CLIENT_ID` | Client ID from your Google Cloud Console Credentials. | *Required for Web OAuth* |
| `GOOGLE_CLIENT_SECRET` | Client Secret from your Google Cloud Console Credentials. | *Required for Web OAuth* |
| `GOOGLE_REDIRECT_URL` | Redirect URI registered in your Google Console (e.g., `http://localhost:8080/auth/callback`). | *Required for Web OAuth* |
| `TARGET_URL` | Set to `"tunnel"` to use localtunnel gateway, or backend service URL. | `None` |
| `TUNNEL_TOKEN` | Secure token required to authenticate tunnel clients (if `TARGET_URL=tunnel`). | `None` |
| `RATE_LIMIT_PER_SEC` | Requests per second limit for web users. | `3.0` |
| `RATE_BURST` | Max burst capacity for web users. | `5.0` |
| `S2S_RATE_LIMIT_PER_SEC` | Requests per second limit for Server-to-Server API clients. | `30.0` |
| `S2S_RATE_BURST` | Max burst capacity for Server-to-Server API clients. | `100.0` |
