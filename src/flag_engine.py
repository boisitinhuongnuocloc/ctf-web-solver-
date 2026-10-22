import re
from pathlib import Path
from typing import Optional, Set, List
from .config import UNIVERSAL_FLAG_PATTERN

DUMMY_FLAG_KEYWORDS = ["fake", "dummy", "placeholder", "xxx", "here", "sample", "mock"]

class FlagEngine:
    def __init__(self, custom_prefix: Optional[str] = None, custom_regex: Optional[str] = None):
        self.custom_prefix = custom_prefix
        self.custom_regex = custom_regex
        self._compiled_regex = None

    def get_regex(self, challenge_dir: Optional[Path] = None) -> re.Pattern:
        """Determines the most accurate flag regex pattern for the target challenge."""
        if self.custom_regex:
            return re.compile(self.custom_regex)
        
        if self.custom_prefix:
            prefix = re.escape(self.custom_prefix.strip("{}"))
            return re.compile(rf"{prefix}\{{[^}}\n]+\}}", re.IGNORECASE)

        # Auto-detect from source files / Dockerfile if directory provided
        if challenge_dir and challenge_dir.is_dir():
            detected_prefix = self._scan_dummy_flags(challenge_dir)
            if detected_prefix:
                return re.compile(rf"{re.escape(detected_prefix)}\{{[^}}\n]+\}}")

        # Fallback to universal pattern
        return re.compile(UNIVERSAL_FLAG_PATTERN)

    def _scan_dummy_flags(self, challenge_dir: Path) -> Optional[str]:
        """Scans Dockerfile, compose, and code files to detect the organizer's flag format prefix."""
        files_to_check = [
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            ".env", "flag.txt", "flag", "entrypoint.sh", "run.sh"
        ]
        
        # Check high priority config files first
        for fname in files_to_check:
            fpath = challenge_dir / fname
            if fpath.is_file():
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    prefix = self._find_prefix_in_text(content)
                    if prefix:
                        return prefix
                except Exception:
                    pass

        # Check source files (.py, .php, .js, .go, .c, .html)
        for ext in ["*.py", "*.php", "*.js", "*.go", "*.html", "*.json"]:
            for fpath in challenge_dir.rglob(ext):
                # avoid node_modules, .git, venv
                if any(ignored in fpath.parts for ignored in [".git", "node_modules", "venv", "__pycache__"]):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    prefix = self._find_prefix_in_text(content)
                    if prefix:
                        return prefix
                except Exception:
                    pass
        return None

    def _find_prefix_in_text(self, text: str) -> Optional[str]:
        """Finds any flag prefix like picoCTF, cscv2026, SVATTT, etc. in a text string."""
        matches = re.findall(r"([a-zA-Z0-9_\-\.\+]{2,20})\{[^\}\n]+\}", text)
        for m in matches:
            prefix = m.strip()
            # If it's a known generic word or organizer prefix
            if prefix and not prefix.lower().startswith("regex"):
                return prefix
        return None

    def extract_flags(self, text: str, regex: re.Pattern) -> List[str]:
        """Extracts unique valid flags from raw text or tool output."""
        if not text:
            return []
        
        cleaned = []
        # finditer preserves the complete match even when a custom regex has groups.
        for match in regex.finditer(text):
            val = match.group(0).strip()
            if val and val not in cleaned:
                cleaned.append(val)
        return cleaned

    def is_likely_real_flag(self, flag: str) -> bool:
        """Filters out obvious placeholder flags like flag{fake_flag}."""
        lower = flag.lower()
        body = lower[lower.find("{") + 1:lower.rfind("}")] if "{" in lower else lower
        if any(kw in body for kw in DUMMY_FLAG_KEYWORDS):
            return False
        if re.search(r"(?:^|[_-])test(?:[_-]?flag)?(?:$|[_-])", body):
            return False
        return True

    def find_fragmented_flag(self, challenge_dir: Path) -> Optional[str]:
        """
        Detects multi-part/fragmented flags commonly split across HTML comments,
        CSS comments, JS comments, and HTML element attributes (Inspector style).
        """
        fragments = []
        open_pattern = re.compile(r"([a-zA-Z0-9_\-\.\+]{2,20})\{([a-zA-Z0-9_\-\.\!\?@#$%^&*+=~/]+)")
        close_pattern = re.compile(r"([a-zA-Z0-9_\-\.\!\?@#$%^&*+=~/]+)\}")

        start_frag = None
        end_frag = None
        middle_parts = []

        for ext in ["*.html", "*.htm", "*.css", "*.js"]:
            for fpath in challenge_dir.rglob(ext):
                try:
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # HTML comments: <!-- ... -->
                for c in re.findall(r"<!--\s*([\s\S]*?)\s*-->", text):
                    c_clean = c.strip()
                    if c_clean:
                        fragments.append(c_clean)

                # CSS/JS multi-line comments: /* ... */
                for c in re.findall(r"/\*\s*([\s\S]*?)\s*\*/", text):
                    c_clean = c.strip()
                    if c_clean:
                        fragments.append(c_clean)

                # HTML attributes (id, data-...)
                for a in re.findall(r'\b(?:id|data-[\w\-]+)\s*=\s*["\']([^"\']+)["\']', text):
                    a_clean = a.strip()
                    if "}" in a_clean or "{" in a_clean or a_clean.startswith("_"):
                        fragments.append(a_clean)

        for frag in fragments:
            if "{" in frag and "}" not in frag:
                m = open_pattern.search(frag)
                if m:
                    start_frag = m.group(0)
            elif "}" in frag and "{" not in frag:
                m = close_pattern.search(frag)
                if m:
                    end_frag = m.group(0)
            elif (frag.startswith("_") or frag.endswith("_")) and not frag.startswith("__"):
                if frag not in middle_parts:
                    middle_parts.append(frag)

        if start_frag and end_frag:
            # Clean middle parts to make sure they connect cleanly
            assembled = start_frag
            for mp in middle_parts:
                if mp not in assembled:
                    assembled += mp
            if not assembled.endswith(end_frag):
                assembled += end_frag
            return assembled

        return None

