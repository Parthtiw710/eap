import time
import hmac
import hashlib
import base64
import json
import urllib.request
import urllib.parse
import threading
from typing import Dict, List, Optional, Callable, Any

class EapConfig:
    def __init__(self,
                 jwt_secret: str,
                 allowed_emails: List[str],
                 rate_limit_per_sec: float = 3.0,
                 rate_burst: float = 5.0,
                 s2s_rate_limit_per_sec: float = 30.0,
                 s2s_rate_burst: float = 100.0,
                 google_client_id: Optional[str] = None,
                 google_client_secret: Optional[str] = None,
                 google_redirect_url: Optional[str] = None,
                 target_url: Optional[str] = None,
                 tunnel_token: Optional[str] = None):
        self.jwt_secret = jwt_secret
        self.allowed_emails = allowed_emails
        self.rate_limit_per_sec = rate_limit_per_sec
        self.rate_burst = rate_burst
        self.s2s_rate_limit_per_sec = s2s_rate_limit_per_sec
        self.s2s_rate_burst = s2s_rate_burst
        self.google_client_id = google_client_id
        self.google_client_secret = google_client_secret
        self.google_redirect_url = google_redirect_url
        self.target_url = target_url
        self.tunnel_token = tunnel_token

class EapEngine:
    @classmethod
    def from_env(cls) -> "EapEngine":
        import os
        allowed_str = os.getenv("ALLOWED_EMAILS", os.getenv("ADMIN_EMAIL", ""))
        allowed_emails = [x.strip() for x in allowed_str.split(",") if x.strip()]
        
        def safe_float(val, default):
            try:
                return float(val) if val else default
            except ValueError:
                return default

        config = EapConfig(
            jwt_secret=os.getenv("JWT_SECRET", ""),
            allowed_emails=allowed_emails,
            rate_limit_per_sec=safe_float(os.getenv("RATE_LIMIT_PER_SEC"), 3.0),
            rate_burst=safe_float(os.getenv("RATE_BURST"), 5.0),
            s2s_rate_limit_per_sec=safe_float(os.getenv("S2S_RATE_LIMIT_PER_SEC"), 30.0),
            s2s_rate_burst=safe_float(os.getenv("S2S_RATE_BURST"), 100.0),
            google_client_id=os.getenv("GOOGLE_CLIENT_ID"),
            google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
            google_redirect_url=os.getenv("GOOGLE_REDIRECT_URL"),
            target_url=os.getenv("TARGET_URL"),
            tunnel_token=os.getenv("TUNNEL_TOKEN")
        )
        return cls(config)

    def __init__(self, config: EapConfig):
        self.config = config
        self.client_limits: Dict[str, Dict[str, Any]] = {}
        self.limits_lock = threading.Lock()
        self.request_counter = 0
        self.counter_lock = threading.Lock()
        
        # Tunnel state mapping
        self.active_requests: Dict[str, threading.Event] = {}
        self.responses: Dict[str, Dict[str, Any]] = {}
        self.active_requests_lock = threading.Lock()
        self.pending_requests: List[Dict[str, Any]] = []
        self.pending_lock = threading.Lock()
        self.pending_event = threading.Event()

    # ASGI Middleware implementation (FastAPI / Starlette)
    def asgi_middleware(self) -> Callable:
        async def middleware(scope: Any, receive: Callable, send: Callable) -> None:
            if scope["type"] != "http":
                await send({"type": "http.response.start", "status": 200, "headers": []})
                return

            path = scope["path"]

            # Intercept EAP routes
            if path in ["/login", "/auth/callback", "/logout", "/tunnel/poll", "/tunnel/respond"]:
                await self.handle_eap_route_asgi(scope, receive, send)
                return

            # Extract auth
            headers = dict(scope.get("headers", []))
            email: Optional[str] = None
            is_s2s = False

            auth_header = headers.get(b"authorization", b"").decode("utf-8")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    email = self.verify_session(token)
                    is_s2s = True
                except ValueError:
                    await self.respond_asgi(send, 401, b"Unauthorized S2S token")
                    return
            else:
                cookies = self.parse_cookies(headers.get(b"cookie", b"").decode("utf-8"))
                session = cookies.get("eap_session")
                if session:
                    try:
                        email = self.verify_session(session)
                    except ValueError:
                        pass

            # Check rate limiting
            client_ip = scope.get("client", [""])[0]
            if self.is_rate_limited(client_ip, email, is_s2s):
                if is_s2s:
                    await self.respond_asgi(send, 429, b"Too Many Requests", {b"retry-after": b"1"})
                    return
                # Redirect to error page
                redirect_uri = urllib.parse.quote(scope.get("query_string", b"").decode("utf-8"))
                await self.redirect_asgi(send, f"/error/429?redirect_to={redirect_uri}")
                return

            if not email:
                if is_s2s:
                    await self.respond_asgi(send, 401, b"Unauthorized")
                    return
                # Set redirect_to cookie and send to login
                original_uri = scope["path"]
                if scope.get("query_string"):
                    original_uri += "?" + scope["query_string"].decode("utf-8")
                headers = {b"set-cookie": f"redirect_to={original_uri}; Path=/; HttpOnly".encode("utf-8")}
                await self.redirect_asgi(send, "/login", headers)
                return

            if not self.is_email_allowed(email):
                await self.redirect_asgi(send, "/error/403")
                return

            # Inject User email header
            scope_headers = list(scope.get("headers", []))
            scope_headers.append((b"x-user-email", email.encode("utf-8")))
            scope["headers"] = scope_headers

            if self.config.target_url == "tunnel":
                await self.proxy_through_tunnel_asgi(scope, receive, send, email)
                return

            # Continue execution (we're acting as a middleware library)
            # In a real environment, the underlying ASGI application takes over
            return

        return middleware

    async def handle_eap_route_asgi(self, scope: Any, receive: Callable, send: Callable) -> None:
        path = scope["path"]
        query_params = urllib.parse.parse_qs(scope.get("query_string", b"").decode("utf-8"))

        if path == "/login":
            if not self.config.google_client_id:
                await self.respond_asgi(send, 500, b"OAuth not configured")
                return
            redirect_to = query_params.get("redirect_to", ["/"])[0]
            auth_url = (f"https://accounts.google.com/o/oauth2/v2/auth?client_id={self.config.google_client_id}"
                        f"&redirect_uri={urllib.parse.quote(self.config.google_redirect_url or '')}"
                        f"&response_type=code&scope=email%20profile&state={urllib.parse.quote(redirect_to)}")
            await self.redirect_asgi(send, auth_url)
            return

        if path == "/auth/callback":
            code = query_params.get("code", [""])[0]
            if not code:
                await self.redirect_asgi(send, "/error/400")
                return

            try:
                # Exchange code using urllib
                data = urllib.parse.urlencode({
                    "code": code,
                    "client_id": self.config.google_client_id or "",
                    "client_secret": self.config.google_client_secret or "",
                    "redirect_uri": self.config.google_redirect_url or "",
                    "grant_type": "authorization_code"
                }).encode("utf-8")

                req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data)
                with urllib.request.urlopen(req) as res:
                    token_data = json.loads(res.read().decode("utf-8"))

                user_req = urllib.request.Request(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {token_data['access_token']}"}
                )
                with urllib.request.urlopen(user_req) as res:
                    user_data = json.loads(res.read().decode("utf-8"))

                email = user_data.get("email")
                if not email or not self.is_email_allowed(email):
                    await self.redirect_asgi(send, "/error/403")
                    return

                session_token = self.sign_session(email)
                state = query_params.get("state", ["/"])[0]

                headers = {
                    b"set-cookie": f"eap_session={session_token}; Path=/; HttpOnly; Max-Age=86400".encode("utf-8")
                }
                await self.redirect_asgi(send, state, headers)
            except Exception:
                await self.redirect_asgi(send, "/error/500")
            return

        if path == "/logout":
            headers = {b"set-cookie": b"eap_session=; Path=/; Max-Age=0"}
            await self.redirect_asgi(send, "/login", headers)
            return

        if path == "/tunnel/poll":
            token = query_params.get("token", [""])[0]
            if not self.config.tunnel_token or token != self.config.tunnel_token:
                await self.respond_asgi(send, 401, b"Unauthorized")
                return

            # Long poll wait
            has_request = self.pending_event.wait(15.0)
            if not has_request:
                await send({"type": "http.response.start", "status": 204, "headers": []})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return

            with self.pending_lock:
                if self.pending_requests:
                    req_data = self.pending_requests.pop(0)
                    if not self.pending_requests:
                        self.pending_event.clear()
                    await self.respond_asgi(send, 200, json.dumps(req_data).encode("utf-8"), {b"content-type": b"application/json"})
                    return
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return

        if path == "/tunnel/respond":
            token = query_params.get("token", [""])[0]
            req_id = query_params.get("id", [""])[0]
            if not self.config.tunnel_token or token != self.config.tunnel_token:
                await self.respond_asgi(send, 401, b"Unauthorized")
                return

            # Read body
            body_bytes = b""
            more_body = True
            while more_body:
                msg = await receive()
                body_bytes += msg.get("body", b"")
                more_body = msg.get("more_body", False)

            try:
                resp_data = json.loads(body_bytes.decode("utf-8"))
                with self.active_requests_lock:
                    self.responses[req_id] = resp_data
                    event = self.active_requests.get(req_id)
                    if event:
                        event.set()
                await self.respond_asgi(send, 200, b"OK")
            except Exception:
                await self.respond_asgi(send, 400, b"Bad Request")
            return

    async def proxy_through_tunnel_asgi(self, scope: Any, receive: Callable, send: Callable, email: str) -> None:
        with self.counter_lock:
            self.request_counter += 1
            req_id = str(self.request_counter)

        # Read body
        body_bytes = b""
        more_body = True
        while more_body:
            msg = await receive()
            body_bytes += msg.get("body", b"")
            more_body = msg.get("more_body", False)

        body_b64 = base64.b64encode(body_bytes).decode("utf-8")

        headers_dict = {}
        for k, v in scope.get("headers", []):
            headers_dict[k.decode("utf-8")] = [v.decode("utf-8")]
        headers_dict["X-User-Email"] = [email]

        pending_req = {
            "id": req_id,
            "method": scope["method"],
            "path": scope["path"],
            "query": scope.get("query_string", b"").decode("utf-8"),
            "headers": headers_dict,
            "body": body_b64
        }

        event = threading.Event()
        with self.active_requests_lock:
            self.active_requests[req_id] = event

        with self.pending_lock:
            self.pending_requests.append(pending_req)
            self.pending_event.set()

        # Wait for response
        success = event.wait(30.0)
        
        with self.active_requests_lock:
            if req_id in self.active_requests:
                del self.active_requests[req_id]
            resp_data = self.responses.pop(req_id, None)

        if not success or not resp_data:
            await self.respond_asgi(send, 504, b"Gateway Timeout")
            return

        headers = []
        for k, values in resp_data.get("headers", {}).items():
            for v in values:
                headers.append((k.lower().encode("utf-8"), v.encode("utf-8")))

        body = base64.b64decode(resp_data.get("body", ""))
        await send({"type": "http.response.start", "status": resp_data.get("status", 200), "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def respond_asgi(self, send: Callable, status: int, body: bytes, headers: Optional[Dict[bytes, bytes]] = None) -> None:
        headers_list = []
        if headers:
            for k, v in headers.items():
                headers_list.append((k, v))
        await send({"type": "http.response.start", "status": status, "headers": headers_list})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def redirect_asgi(self, send: Callable, location: str, extra_headers: Optional[Dict[bytes, bytes]] = None) -> None:
        headers = {b"location": location.encode("utf-8")}
        if extra_headers:
            headers.update(extra_headers)
        await self.respond_asgi(send, 302, b"", headers)

    # JWT Session logic (Pure Python standard library implementation)
    def sign_session(self, email: str) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"email": email, "exp": int(time.time()) + 86400}
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        
        signature = hmac.new(self.config.jwt_secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def verify_session(self, token: str) -> str:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        header_b64, payload_b64, signature_b64 = parts
        
        signature = hmac.new(self.config.jwt_secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        expected_signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        if not hmac.compare_digest(signature_b64, expected_signature_b64):
            raise ValueError("Signature mismatch")
            
        padding = len(payload_b64) % 4
        if padding:
            payload_b64 += "=" * (4 - padding)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        
        if "exp" in payload and time.time() > payload["exp"]:
            raise ValueError("Token expired")
        return payload["email"]

    def is_email_allowed(self, email: str) -> bool:
        email_clean = email.lower().strip()
        for p in self.config.allowed_emails:
            pattern = p.lower().strip()
            if pattern.startswith("@") and email_clean.endswith(pattern):
                return True
            if pattern == email_clean:
                return True
        return False

    def is_rate_limited(self, ip: str, email: Optional[str], is_s2s: bool) -> bool:
        key = email if email else ip
        now = time.time()
        
        limit_per_sec = self.config.s2s_rate_limit_per_sec if is_s2s else self.config.rate_limit_per_sec
        burst = self.config.s2s_rate_burst if is_s2s else self.config.rate_burst
        
        with self.limits_lock:
            limit = self.client_limits.get(key)
            if not limit:
                self.client_limits[key] = {"tokens": burst - 1.0, "last_seen": now}
                return False
                
            elapsed = now - limit["last_seen"]
            limit["tokens"] = min(burst, limit["tokens"] + elapsed * limit_per_sec)
            limit["last_seen"] = now
            
            if limit["tokens"] >= 1.0:
                limit["tokens"] -= 1.0
                return False
            return True

    def parse_cookies(self, cookie_str: str) -> Dict[str, str]:
        cookies = {}
        for cookie in cookie_str.split(";"):
            parts = cookie.strip().split("=")
            if len(parts) >= 2:
                cookies[parts[0]] = parts[1]
        return cookies

# Tunnel Client execution routine (Pure Python standard library)
def start_tunnel_client(server_url: str, token: str, local_port: int) -> None:
    local_addr = f"http://localhost:{local_port}"
    poll_url = f"{server_url}/tunnel/poll?token={urllib.parse.quote(token)}"
    
    while True:
        try:
            req = urllib.request.Request(poll_url)
            with urllib.request.urlopen(req) as res:
                if res.getcode() == 204:
                    continue
                req_data = json.loads(res.read().decode("utf-8"))
            
            def process_and_respond(r_data):
                try:
                    local_url = f"{local_addr}{r_data['path']}"
                    if r_data.get("query"):
                        local_url += "?" + r_data["query"]
                        
                    headers = {k: v[0] for k, v in r_data.get("headers", {}).items()}
                    body_bytes = base64.b64decode(r_data.get("body", "")) if r_data.get("body") else None
                    
                    local_req = urllib.request.Request(local_url, data=body_bytes, headers=headers, method=r_data["method"])
                    try:
                        with urllib.request.urlopen(local_req) as local_res:
                            status = local_res.getcode()
                            resp_headers = {k: [v] for k, v in local_res.info().items()}
                            resp_body = base64.b64encode(local_res.read()).decode("utf-8")
                    except urllib.error.HTTPError as he:
                        status = he.code
                        resp_headers = {k: [v] for k, v in he.info().items()}
                        resp_body = base64.b64encode(he.read()).decode("utf-8")
                    
                    tunnel_resp = {
                        "status": status,
                        "headers": resp_headers,
                        "body": resp_body
                    }
                except Exception as e:
                    tunnel_resp = {
                        "status": 502,
                        "headers": {},
                        "body": base64.b64encode(str(e).encode()).decode("utf-8")
                    }
                
                # Send back response
                try:
                    respond_url = f"{server_url}/tunnel/respond?token={urllib.parse.quote(token)}&id={urllib.parse.quote(r_data['id'])}"
                    post_req = urllib.request.Request(
                        respond_url,
                        data=json.dumps(tunnel_resp).encode("utf-8"),
                        headers={"Content-Type": "application/json"}
                    )
                    with urllib.request.urlopen(post_req) as pr:
                        pr.read()
                except Exception:
                    pass

            threading.Thread(target=process_and_respond, args=(req_data,), daemon=True).start()
        except Exception:
            time.sleep(3)
