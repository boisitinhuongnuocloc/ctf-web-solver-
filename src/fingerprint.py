import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

class ChallengeFingerprinter:
    def __init__(self, challenge_dir: Path):
        self.challenge_dir = challenge_dir
        self.report: Dict[str, Any] = {
            "name": challenge_dir.name,
            "tech_stack": [],
            "category": "Web",
            "is_client_side": False,
            "has_bot": False,
            "flag_location_hints": [],
            "exposed_ports": [],
            "dangerous_sinks": [],
            "routes": [],
            "live_recon": [],
            "auth": {"attempted": False, "authenticated": False, "endpoint": None},
            "files_analyzed": [],
            "summary_for_ai": ""
        }

    def analyze(self) -> Dict[str, Any]:
        """Runs complete static analysis on the challenge folder."""
        if not self.challenge_dir.exists():
            return self.report

        self._check_docker()
        self._scan_source_files()
        self._synthesize_summary()
        return self.report

    def _check_docker(self):
        """Extracts info from Dockerfile and docker-compose files."""
        docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]
        for fname in docker_files:
            fpath = self.challenge_dir / fname
            if fpath.is_file():
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    self.report["files_analyzed"].append(fname)
                    
                    # Detect Base Images / Tech Stack
                    if re.search(r"FROM\s+python", content, re.I):
                        self._add_stack("Python")
                    if re.search(r"FROM\s+php", content, re.I):
                        self._add_stack("PHP")
                    if re.search(r"FROM\s+node", content, re.I):
                        self._add_stack("Node.js")
                    if re.search(r"FROM\s+golang", content, re.I):
                        self._add_stack("Go")
                    if re.search(r"FROM\s+.*(openjdk|java)", content, re.I):
                        self._add_stack("Java")

                    # Detect Ports
                    ports = re.findall(r"(?:EXPOSE|\bports:[\s\S]*?-)\s*[\"']?(\d{2,5})", content)
                    for p in ports:
                        if p not in self.report["exposed_ports"]:
                            self.report["exposed_ports"].append(p)

                    # Detect Flag locations
                    flag_matches = re.findall(r"(?:COPY|RUN|ENV|ADD).*?(?:flag[\w\.\-]*|FLAG[\w\.\-]*)", content, re.I)
                    for fm in flag_matches:
                        self.report["flag_location_hints"].append(fm.strip())

                    # Check for headless browser / bot in Docker
                    if re.search(r"(puppeteer|playwright|selenium|chromium|firefox-esr|google-chrome)", content, re.I):
                        self.report["has_bot"] = True
                        self.report["is_client_side"] = True
                except Exception:
                    pass

    def _scan_source_files(self):
        """Scans code files for routes, sinks, and vulnerabilities."""
        patterns = {
            "SSTI (Jinja2/Flask)": [
                r"render_template_string\s*\(",
                r"from\s+jinja2\s+import\s+Template",
                r"Template\s*\(.*?\)\.render\s*\("
            ],
            "Insecure Deserialization": [
                r"pickle\.loads\s*\(",
                r"yaml\.load\s*\([^,)]+Loader=yaml\.(?:UnsafeLoader|Loader)",
                r"unserialize\s*\(",
                r"serialize\s*\("
            ],
            "SQL Injection (Raw Query)": [
                r"(?:execute|query|cursor\.execute)\s*\(\s*f[\"']SELECT",
                r"(?:execute|query)\s*\(\s*[\"'].*?%\s*\(",
                r"(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM).*?\+\s*[\w\.\['\"]+"
            ],
            "Command Injection / RCE": [
                r"os\.system\s*\(",
                r"subprocess\.(?:Popen|run|check_output|call)\s*\(",
                r"child_process\.(?:exec|execSync|spawn)\s*\(",
                r"(?:shell_exec|system|exec|passthru)\s*\(",
                r"eval\s*\("
            ],
            "Path Traversal / LFI": [
                r"open\s*\(\s*(?:os\.path\.join|f[\"'])",
                r"include\s*[\(\s]\s*\$_GET",
                r"require\s*[\(\s]\s*\$_GET",
                r"file_get_contents\s*\(\s*\$_GET"
            ],
            "Prototype Pollution (Node.js)": [
                r"lodash\.merge\s*\(",
                r"deepMerge|cloneDeep",
                r"__proto__|constructor\s*\[|prototype\s*\["
            ],
            "Client-Side / Bot Trigger": [
                r"(?:puppeteer|playwright)\.launch",
                r"/(?:visit|report(?:/|\b)|submit-url)"
            ]
        }

        # Extensions to scan
        valid_exts = {".py", ".php", ".js", ".ts", ".go", ".html", ".sql", ".json", ".yaml", ".yml"}
        
        for root, dirs, files in os.walk(self.challenge_dir):
            # Exclude unwanted directories
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", "__pycache__", "dist", "build"}]
            
            for file in files:
                p = Path(root) / file
                if p.suffix.lower() in valid_exts and p.stat().st_size < 1_000_000:
                    rel_path = p.relative_to(self.challenge_dir)
                    self.report["files_analyzed"].append(str(rel_path))
                    
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    # Language detection
                    if p.suffix == ".py":
                        self._add_stack("Python")
                    elif p.suffix == ".php":
                        self._add_stack("PHP")
                    elif p.suffix in [".js", ".ts"]:
                        self._add_stack("Node.js")
                    elif p.suffix == ".go":
                        self._add_stack("Go")

                    # Scan for routes
                    route_matches = re.findall(
                        r"(?:@(?:app|router)\.(?:route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']|(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"'])",
                        content,
                        re.I,
                    )
                    if p.suffix.lower() in {".js", ".ts"}:
                        route_matches.extend((route, "") for route in self._extract_api_endpoints(content))
                    for rm in route_matches:
                        route = rm[0] or rm[1]
                        if route and route not in self.report["routes"]:
                            self.report["routes"].append(route)

                    # Scan for sinks
                    for vul_type, regex_list in patterns.items():
                        for rgx in regex_list:
                            matches = re.finditer(rgx, content, re.MULTILINE)
                            for m in matches:
                                line_no = content[:m.start()].count("\n") + 1
                                snippet = content[max(0, m.start() - 40):min(len(content), m.end() + 60)].strip().replace("\n", " ")
                                
                                extra_hint = ""
                                if "Command" in vul_type:
                                    if "'" in snippet or "date '" in content or re.search(r"[']\s*\.\s*\$", content):
                                        extra_hint = " [CRITICAL: Target parameter is inside single quotes '...'. Exploit MUST break out using single-quote prefix like: '; cat /flag # or ' || cat /flag || ']"
                                    elif '"' in snippet or re.search(r'["]\s*\.\s*\$', content):
                                        extra_hint = " [CRITICAL: Target parameter is inside double quotes. Exploit MUST break out using: \"; cat /flag # or \"$(cat /flag)\"]"

                                self.report["dangerous_sinks"].append({
                                    "file": str(rel_path),
                                    "line": line_no,
                                    "vuln_class": vul_type,
                                    "snippet": snippet + extra_hint
                                })
                                if "Bot Trigger" in vul_type:
                                    self.report["has_bot"] = True
                                    self.report["is_client_side"] = True

    def _add_stack(self, stack: str):
        if stack not in self.report["tech_stack"]:
            self.report["tech_stack"].append(stack)

    @staticmethod
    def _extract_api_endpoints(js_code: str) -> List[str]:
        """Resolve the common `api(method, path)` frontend wrapper into real routes."""
        endpoints = []

        # The app's wrapper prepends /api to paths such as /auth/login or /tickets.
        wrapper_paths = re.findall(
            r"\bapi\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]\s*,\s*[`'\"](/[^`'\"]*)[`'\"]",
            js_code,
            re.I,
        )
        for path in wrapper_paths:
            normalized = path if path.startswith("/api/") else "/api" + path
            if normalized != "/api" and normalized not in endpoints:
                endpoints.append(normalized)

        # Also retain explicitly written API-like paths from fetch(), links, and SDKs.
        direct_paths = re.findall(
            r'''[`'"](/(?:api/|v\d+/|update(?:/|$)|admin/|exec(?:/|$)|query(?:/|$)|upload(?:/|$)|options(?:/|$)|monitor(?:/|$)|cmd(?:/|$)|command(?:/|$))[^`'"]*)[`'"]''',
            js_code,
            re.I,
        )
        for path in direct_paths:
            if path != "/api" and path not in endpoints:
                endpoints.append(path)
        return endpoints

    @staticmethod
    def _credential_payloads(credentials: Dict[str, str]) -> List[Dict[str, str]]:
        raw = {str(k): str(v) for k, v in credentials.items() if v not in (None, "")}
        payloads = [raw]
        if "workspace" in raw and "org" not in raw:
            payloads.append({**raw, "org": raw["workspace"]})
        if {"email", "pin"}.issubset(raw):
            payloads.append({"email": raw["email"], "pin": raw["pin"]})
        if {"username", "password"}.issubset(raw):
            payloads.append({"username": raw["username"], "password": raw["password"]})
        return payloads

    def _try_login(self, session, target_url: str, credentials: Dict[str, str]) -> Optional[str]:
        """Try common login routes without exposing credentials in recon output."""
        if not credentials:
            return None
        endpoints = ["/api/auth/login", "/auth/login", "/api/login", "/login"]
        try:
            landing = session.get(target_url, timeout=4)
            form_matches = re.findall(
                r"<form\b[^>]*action=[\"']?([^\"' >]*)[\"']?[^>]*method=[\"']?([^\"' >]*)[\"']?[^>]*>",
                landing.text,
                re.I,
            )
            for action, method in form_matches:
                if method.upper() == "POST":
                    endpoints.insert(0, action or "/")
        except Exception:
            pass

        for endpoint in endpoints:
            url = urljoin(target_url.rstrip("/") + "/", endpoint.lstrip("/"))
            for payload in self._credential_payloads(credentials):
                try:
                    response = session.post(url, json=payload, timeout=4)
                    if response.status_code not in (200, 201, 204, 302):
                        continue
                    if session.cookies or response.cookies:
                        return endpoint
                    try:
                        data = response.json()
                        if isinstance(data, dict) and any(k in data for k in ("user", "org", "token", "session")):
                            return endpoint
                    except ValueError:
                        if "login" not in response.text.lower() and "sign in" not in response.text.lower():
                            return endpoint
                except Exception:
                    continue
        return None

    def _synthesize_summary(self):
        """Builds a concise technical summary to inject into the AI prompt."""
        lines = []
        lines.append(f"Target: {self.report['name']}")
        lines.append(f"Tech Stack: {', '.join(self.report['tech_stack']) or 'Unknown'}")
        lines.append(f"Category: {'Client-Side (XSS/Bot)' if self.report['is_client_side'] else 'Server-Side Web'}")
        
        if self.report["flag_location_hints"]:
            lines.append("Flag Location Clues: " + "; ".join(self.report["flag_location_hints"]))
            
        if self.report["routes"]:
            lines.append("Detected Routes: " + ", ".join(self.report["routes"][:15]))

        auth = self.report.get("auth", {})
        if auth.get("attempted"):
            state = "authenticated" if auth.get("authenticated") else "not authenticated"
            endpoint = f" via {auth['endpoint']}" if auth.get("endpoint") else ""
            lines.append(f"Live session auth: {state}{endpoint}")
            
        if self.report["dangerous_sinks"]:
            lines.append("High-Priority Dangerous Sinks Identified:")
            for s in self.report["dangerous_sinks"][:8]:
                lines.append(f" - [{s['vuln_class']}] at {s['file']}:L{s['line']} -> `{s['snippet']}`")
        if self.report.get("live_recon"):
            lines.append("Live Target Reconnaissance Results:")
            for rn in self.report["live_recon"][:12]:
                lines.append(f" - {rn}")

        self.report["summary_for_ai"] = "\n".join(lines)

    def recon_live_target(self, target_url: str, credentials: Optional[Dict[str, str]] = None):
        """
        Crawls and fingerprints the live web application if online.
        Extracts routes, forms, parameters, textareas, and linked scripts.
        """
        import requests
        from urllib.parse import urljoin, urlparse

        target_url = target_url.rstrip("/")
        visited_urls = set()
        to_visit = [target_url]
        recon_notes = []

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTF-Web-Solver/1.0"
        })

        parsed_base = urlparse(target_url)
        base_netloc = parsed_base.netloc

        if credentials:
            self.report["auth"]["attempted"] = True
            login_endpoint = self._try_login(session, target_url, credentials)
            if login_endpoint:
                self.report["auth"].update({"authenticated": True, "endpoint": login_endpoint})
                recon_notes.append(f"Authenticated session established via {login_endpoint}")
            else:
                recon_notes.append("Credentials detected, but common login endpoints rejected them")

        while to_visit and len(visited_urls) < 10:
            curr_url = to_visit.pop(0)
            if curr_url in visited_urls:
                continue
            visited_urls.add(curr_url)

            try:
                r = session.get(curr_url, timeout=4)
            except Exception:
                continue

            # Detect server/framework headers
            srv = r.headers.get("Server") or r.headers.get("X-Powered-By")
            if srv and srv not in self.report["tech_stack"]:
                self._add_stack(srv)

            html_text = r.text
            rel_path = urlparse(curr_url).path or "/"
            if rel_path not in self.report["routes"]:
                self.report["routes"].append(rel_path)

            # Check forms
            forms = re.findall(r"<form\b[^>]*action=[\"']?([^\"' >]*)[\"']?[^>]*method=[\"']?([^\"' >]*)[\"']?[^>]*>", html_text, re.I)
            for action, method in forms:
                action_url = action or rel_path
                m = method.upper() if method else "GET"
                recon_notes.append(f"Found Form: {m} {action_url}")
                if action_url.startswith("/") and action_url not in self.report["routes"]:
                    self.report["routes"].append(action_url)

            # Check inputs
            inputs = re.findall(r"<input\b[^>]*name=[\"']([^\"']+)[\"'][^>]*>", html_text, re.I)
            if inputs:
                recon_notes.append(f"Page {rel_path} has inputs: {', '.join(inputs)}")

            # Check textareas
            textareas = re.findall(r"<textarea\b[^>]*id=[\"']([^\"']+)[\"'][^>]*>", html_text, re.I)
            if textareas:
                recon_notes.append(f"Page {rel_path} has textarea: {', '.join(textareas)}")

            # Check for XML / XXE keywords in HTML
            if re.search(r"\b(xml|firmware|soap|svg|rss)\b", html_text, re.I):
                self.report["dangerous_sinks"].append({
                    "file": rel_path,
                    "line": 1,
                    "vuln_class": "XXE / XML External Entity Injection",
                    "snippet": f"Found XML keyword on {rel_path}"
                })

            # Check scripts
            script_srcs = re.findall(r"<script\b[^>]*src=[\"']([^\"']+)[\"'][^>]*>", html_text, re.I)
            for s_src in script_srcs:
                if any(lib in s_src.lower() for lib in ["jquery", "bootstrap", "react", "vue", "angular"]):
                    continue
                full_js_url = urljoin(curr_url, s_src)
                try:
                    r_js = session.get(full_js_url, timeout=3)
                    if r_js.status_code == 200:
                        js_code = r_js.text
                        api_endpoints = self._extract_api_endpoints(js_code)
                        for api_ep in api_endpoints:
                            if api_ep not in self.report["routes"]:
                                self.report["routes"].append(api_ep)
                                recon_notes.append(f"Discovered API endpoint in {s_src}: {api_ep}")
                            
                            # Probe read-only API endpoint for hidden options/secrets
                            if any(k in api_ep.lower() for k in ["options", "config", "debug", "info", "data", "status", "cmd", "command", "secret", "all"]):
                                try:
                                    r_api = session.get(urljoin(target_url + "/", api_ep.lstrip("/")), timeout=3)
                                    if r_api.status_code == 200 and ("json" in r_api.headers.get("Content-Type", "") or r_api.text.strip().startswith("{")):
                                        try:
                                            api_json = r_api.json()
                                            def find_secrets(obj):
                                                res = []
                                                if isinstance(obj, dict):
                                                    for k, v in obj.items():
                                                        if any(sk in k.lower() for sk in ["secret", "flag", "hidden", "admin", "token", "key", "password"]):
                                                            res.append((k, v))
                                                        res.extend(find_secrets(v))
                                                elif isinstance(obj, list):
                                                    for item in obj:
                                                        res.extend(find_secrets(item))
                                                return res

                                            found_secrets = find_secrets(api_json)
                                            if found_secrets:
                                                for sk, sv in found_secrets:
                                                    secret_val = sv[0] if isinstance(sv, list) and sv else sv
                                                    recon_notes.append(f"Disclosed {sk} in {api_ep}: {secret_val}")
                                                    self.report["dangerous_sinks"].append({
                                                        "file": api_ep,
                                                        "line": 1,
                                                        "vuln_class": "API Secret Disclosure & Hidden Command",
                                                        "snippet": f"Endpoint {api_ep} revealed secret '{sk}': \"{secret_val}\". MUST test sending this exact secret value in POST request to monitor/command endpoints."
                                                    })
                                            else:
                                                recon_notes.append(f"API {api_ep} returned JSON: {r_api.text[:200].strip()}")
                                        except Exception:
                                            recon_notes.append(f"API {api_ep} returned JSON: {r_api.text[:200].strip()}")
                                except Exception:
                                    pass

                        # Only flag JSON command sinks when both a JSON body and a
                        # command-like field/route are actually visible.
                        has_json_body = bool(re.search(r"JSON\.stringify\s*\(", js_code, re.I))
                        has_command_field = bool(re.search(
                            r"\b(?:command|cmd|exec|execute|query|action|secret|payload|input)\b",
                            js_code,
                            re.I,
                        ))
                        command_endpoints = [
                            ep for ep in api_endpoints
                            if any(k in ep.lower() for k in ["monitor", "cmd", "exec", "command", "action", "check", "submit"])
                        ]
                        if has_json_body and has_command_field and command_endpoints:
                            json_body_match = re.search(r"JSON\.stringify\s*\(\s*\{([^}]+)\}", js_code)
                            json_schema = json_body_match.group(1).strip() if json_body_match else "JSON body inferred from frontend code"
                            target_post = command_endpoints[0]
                            recon_notes.append(f"Target API Endpoint: POST {target_post} with headers={{'Content-Type': 'application/json'}}, body: {{{json_schema}}}")
                            self.report["dangerous_sinks"].append({
                                "file": s_src,
                                "line": 1,
                                "vuln_class": "JSON API Command / Secret Parameter",
                                "snippet": f"POST {target_post} with headers={{'Content-Type': 'application/json'}}, json={{{json_schema}}}. Send secret command/payload extracted from API or parameters."
                            })

                        if "application/xml" in js_code and api_endpoints:
                            target_ep = api_endpoints[0]
                            sample_xml = ""
                            xml_matches = re.findall(r"(<[A-Za-z0-9]+>[\s\S]*?</[A-Za-z0-9]+>)", js_code)
                            if xml_matches:
                                sample_xml = xml_matches[0][:220].replace("\n", " ")
                            recon_notes.append(f"Target API Endpoint: POST {target_ep} with Content-Type: application/xml")
                            self.report["dangerous_sinks"].append({
                                "file": s_src,
                                "line": 1,
                                "vuln_class": "XXE / XML External Entity Injection",
                                "snippet": f"Endpoint: POST {target_ep} (Headers: {{'Content-Type': 'application/xml'}}, send raw string: data=payload). Template: {sample_xml}. (Inject <!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///flag.txt'> ]> into XML tag, omit <?xml ... ?> declaration)"
                            })
                except Exception:
                    pass

            # Find next links to crawl
            links = re.findall(r"<a\b[^>]*href=[\"']([^\"'#]+)[\"'][^>]*>", html_text, re.I)
            for link in links:
                if link.startswith("javascript:") or link.startswith("mailto:"):
                    continue
                if re.search(r"\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf)$", link, re.I):
                    continue
                abs_link = urljoin(curr_url, link)
                parsed_link = urlparse(abs_link)
                if parsed_link.netloc == base_netloc and abs_link not in visited_urls and abs_link not in to_visit:
                    to_visit.append(abs_link)

        self.report["live_recon"] = recon_notes
        self._synthesize_summary()

