import re
import requests
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urljoin
from .flag_engine import FlagEngine

class BuiltinScanners:
    """Fast heuristics for beginner/intermediate CTF patterns (picoCTF style)."""

    def __init__(
        self,
        target_url: str,
        flag_regex: re.Pattern,
        timeout: int = 5,
        credentials: Optional[Dict[str, str]] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.flag_regex = flag_regex
        self.timeout = timeout
        self.credentials = credentials or {}
        self.flag_engine = FlagEngine()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTF-Web-Solver/1.0"
        })

    def _flags(self, text: str):
        """Extract complete, non-placeholder flag matches from a response."""
        return [
            match.group(0)
            for match in self.flag_regex.finditer(text or "")
            if self.flag_engine.is_likely_real_flag(match.group(0))
        ]

    def authenticate(self) -> bool:
        """Try common JSON login routes using credentials supplied by the challenge."""
        if not self.credentials:
            return False

        raw = {str(k): str(v) for k, v in self.credentials.items() if v not in (None, "")}
        payloads = [raw]
        if "workspace" in raw and "org" not in raw:
            payloads.append({**raw, "org": raw["workspace"]})
        if {"email", "pin"}.issubset(raw):
            payloads.append({"email": raw["email"], "pin": raw["pin"]})
        if {"username", "password"}.issubset(raw):
            payloads.append({"username": raw["username"], "password": raw["password"]})

        endpoints = ["/api/auth/login", "/auth/login", "/api/login", "/login"]
        for endpoint in endpoints:
            url = urljoin(self.target_url + "/", endpoint.lstrip("/"))
            for payload in payloads:
                try:
                    response = self.session.post(url, json=payload, timeout=self.timeout)
                    if response.status_code not in (200, 201, 204, 302):
                        continue
                    if self.session.cookies or response.cookies:
                        return True
                    try:
                        data = response.json()
                        if isinstance(data, dict) and any(k in data for k in ("user", "org", "token", "session")):
                            return True
                    except ValueError:
                        if "login" not in response.text.lower() and "sign in" not in response.text.lower():
                            return True
                except requests.RequestException:
                    continue
        return False

    def run_all(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Runs built-in fast checks.
        Returns (flag, method_name) if found, else (None, None).
        """
        self.authenticate()
        methods = [
            ("HTML Comments & Source Check", self.check_html_comments),
            ("Common Files (robots.txt, .git, /flag)", self.check_common_files),
            ("API Secrets & Hidden Options", self.check_api_secrets),
            ("HTTP Methods & Headers (HEAD, OPTIONS, POST)", self.check_http_methods),
            ("Cookie Tampering", self.check_cookie_tampering)
        ]
        
        for name, method in methods:
            try:
                flag = method()
                if flag:
                    return flag, name
            except Exception:
                continue
        return None, None

    def check_html_comments(self) -> Optional[str]:
        try:
            r = self.session.get(self.target_url, timeout=self.timeout)
            matches = self._flags(r.text)
            if matches:
                return matches[0]
        except Exception:
            pass
        return None

    def check_common_files(self) -> Optional[str]:
        endpoints = [
            "/robots.txt", "/flag", "/flag.txt", "/.env", "/secret",
            "/.git/HEAD", "/sitemap.xml", "/source", "/debug"
        ]
        for ep in endpoints:
            try:
                url = self.target_url + ep
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200:
                    matches = self._flags(r.text)
                    if matches:
                        return matches[0]
            except Exception:
                continue
        return None

    def check_http_methods(self) -> Optional[str]:
        # picoCTF "GET aHEAD" style
        try:
            # Check HEAD request headers
            r_head = self.session.head(self.target_url, timeout=self.timeout)
            for k, v in r_head.headers.items():
                matches = self._flags(f"{k}: {v}")
                if matches:
                    return matches[0]

            # Check OPTIONS
            r_opt = self.session.options(self.target_url, timeout=self.timeout)
            for k, v in r_opt.headers.items():
                matches = self._flags(f"{k}: {v}")
                if matches:
                    return matches[0]
        except Exception:
            pass
        return None

    def check_cookie_tampering(self) -> Optional[str]:
        # picoCTF "Cookies" style: test cookie 'name' from 0 to 25, or 'admin=1'
        try:
            r_init = self.session.get(self.target_url, timeout=self.timeout)
            cookies = r_init.cookies.get_dict()
            
            # If there's an 'admin' or 'auth' cookie
            candidate_keys = set(cookies) | {"admin", "auth", "is_admin", "role"}
            for auth_key in candidate_keys:
                for val in ["1", "true", "True", "admin"]:
                    r = self.session.get(self.target_url, cookies={auth_key: val}, timeout=self.timeout)
                    matches = self._flags(r.text)
                    if matches:
                        return matches[0]

            # If cookie contains an integer (like name=0, name=-1)
            for ck, cv in cookies.items():
                if cv.isdigit() or cv == "-1":
                    for i in range(0, 25):
                        r = self.session.get(self.target_url, cookies={ck: str(i)}, timeout=self.timeout)
                        matches = self._flags(r.text)
                        if matches:
                            return matches[0]
        except Exception:
            pass
        return None

    def check_api_secrets(self) -> Optional[str]:
        """Checks for client-side API endpoints (/api/options, /api/config) disclosing secret commands."""
        try:
            r = self.session.get(self.target_url, timeout=self.timeout)
            html = r.text
            scripts = re.findall(r'<script\b[^>]*src=[\'"]([^\'"]+)[\'"]', html, re.I)
            
            api_endpoints = set(["/api/options", "/api/config", "/api/commands", "/api/data", "/options", "/config"])
            for s_src in scripts:
                if any(lib in s_src.lower() for lib in ["jquery", "bootstrap", "react", "vue"]):
                    continue
                s_url = urljoin(self.target_url, s_src)
                try:
                    r_js = self.session.get(s_url, timeout=3)
                    if r_js.status_code == 200:
                        eps = re.findall(r'[\'"](/(?:api|v[0-9]|cmd)[^\'"]*)[\'"]', r_js.text)
                        for ep in eps:
                            api_endpoints.add(ep)
                except Exception:
                    pass

            secrets_found = []
            post_endpoints = [ep for ep in api_endpoints if any(k in ep.lower() for k in ["monitor", "cmd", "execute", "action", "check"])]
            
            for ep in api_endpoints:
                try:
                    ep_url = urljoin(self.target_url, ep)
                    r_api = self.session.get(ep_url, timeout=3)
                    if r_api.status_code == 200:
                        try:
                            data = r_api.json()
                            def extract(obj):
                                s_list = []
                                if isinstance(obj, dict):
                                    for k, v in obj.items():
                                        if any(sk in k.lower() for sk in ["secret", "flag", "hidden", "command"]):
                                            if isinstance(v, list):
                                                s_list.extend(v)
                                            elif isinstance(v, str):
                                                s_list.append(v)
                                        s_list.extend(extract(v))
                                elif isinstance(obj, list):
                                    for item in obj:
                                        s_list.extend(extract(item))
                                return s_list
                            
                            secrets_found.extend(extract(data))
                        except Exception:
                            pass
                except Exception:
                    pass

            if secrets_found:
                targets = post_endpoints or ["/api/monitor", "/api/cmd", "/api/execute"]
                for p_ep in targets:
                    target_post_url = urljoin(self.target_url, p_ep)
                    for sec in secrets_found:
                        for key in ["command", "cmd", "secret", "payload", "input", "action"]:
                            try:
                                r_post = self.session.post(target_post_url, headers={"Content-Type": "application/json"}, json={key: sec}, timeout=3)
                                matches = self._flags(r_post.text)
                                if matches:
                                    return matches[0]
                            except Exception:
                                pass
        except Exception:
            pass
        return None

