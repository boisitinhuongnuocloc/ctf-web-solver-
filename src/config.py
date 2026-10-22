import os
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent.parent
CHALLENGES_DIR = ROOT_DIR / "challenges"
SOLVE_DIR = ROOT_DIR / "solve"
WRITEUPS_DIR = ROOT_DIR / "writeups"

# AI Provider Settings ("opencode" or "ollama")
DEFAULT_AI_PROVIDER = os.getenv("CTF_AI_PROVIDER", "opencode")

# OpenCode & Lingling Settings
DEFAULT_OPENCODE_HOST = os.getenv("OPENCODE_SERVICE_HOST", "http://127.0.0.1:45278")
DEFAULT_OPENCODE_MODEL = os.getenv("OPENCODE_MODEL", "deepseek-v4.1-flash-free")
DEFAULT_OPENCODE_USER = os.getenv("OPENCODE_USER", "opencode")
OPENCODE_CONFIG_DIR = Path(os.getenv("OPENCODE_CONFIG_DIR", Path.home() / ".config" / "opencode"))

# Ollama Settings
DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("CTF_AI_MODEL", "qwen2.5:7b")

# Execution settings
# A failed exploit is regenerated/re-run up to three times total.
MAX_SELF_HEAL_ATTEMPTS = 3
# None disables the parent-process timeout; the exploit controls its own lifetime.
EXPLOIT_TIMEOUT_SECONDS = None
AI_GENERATION_TIMEOUT = 120

# Universal Flag Regex matching formats like flag{...}, picoCTF{...}, cscv2026{...}, CTF{...}
UNIVERSAL_FLAG_PATTERN = r"[a-zA-Z0-9_\-\.\+]{2,30}\{[a-zA-Z0-9_\-\.\!\?@#$%^&*+=~/ ]+\}"
