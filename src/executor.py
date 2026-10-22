import sys
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional
import re

from .config import EXPLOIT_TIMEOUT_SECONDS
from .flag_engine import FlagEngine

class ExploitExecutor:
    def __init__(self, timeout: Optional[int] = EXPLOIT_TIMEOUT_SECONDS):
        self.timeout = timeout

    def run_script(
        self,
        script_path: Path,
        flag_regex: re.Pattern,
        target_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a Python exploit script and parses the output for the flag.
        """
        result = {
            "success": False,
            "flag": None,
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error_summary": ""
        }

        if not script_path.is_file():
            result["error_summary"] = f"Script file not found: {script_path}"
            return result

        cmd = [sys.executable, str(script_path)]
        # Always pass the current CLI target so generated scripts cannot fall back
        # to a stale URL embedded in their source.
        if target_url:
            cmd.append(target_url)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=script_path.parent
            )
            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr
            result["returncode"] = proc.returncode

            combined_output = f"{proc.stdout}\n{proc.stderr}"
            flag_engine = FlagEngine()
            flags = flag_engine.extract_flags(combined_output, flag_regex)

            # Filter for real flags
            valid_flags = [f for f in flags if flag_engine.is_likely_real_flag(f)]
            if valid_flags:
                result["success"] = True
                result["flag"] = valid_flags[0]
            elif flags:
                # Do not report a solve when every match looks like a placeholder.
                result["flag"] = flags[0]
                result["error_summary"] = "Only placeholder-looking flag values were printed; solve rejected."

            if not result["success"]:
                combined_err = f"{proc.stdout}\n{proc.stderr}"
                if result["error_summary"]:
                    pass
                elif "ConnectionRefusedError" in combined_err or "10061" in combined_err or "Failed to establish a new connection" in combined_err:
                    result["error_summary"] = "Target server is offline or connection refused. Verify that the target instance/URL is reachable."
                elif proc.returncode != 0:
                    result["error_summary"] = f"Process exited with code {proc.returncode}.\nStderr: {proc.stderr[:500]}"
                else:
                    result["error_summary"] = f"Script completed with code 0 but no flag matching pattern was printed.\nOutput: {proc.stdout[:500]}"

        except subprocess.TimeoutExpired:
            result["error_summary"] = f"Exploit execution timed out after {self.timeout} seconds."
        except Exception as e:
            result["error_summary"] = f"Execution error: {str(e)}"

        return result
