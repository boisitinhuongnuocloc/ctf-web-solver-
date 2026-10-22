import re
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from src.executor import ExploitExecutor
from src.fingerprint import ChallengeFingerprinter
from src.flag_engine import FlagEngine
from src.orchestrator import ChallengeOrchestrator


ROOT = Path(__file__).resolve().parents[1]


class SolverCoreTests(unittest.TestCase):
    def test_recon_login_uses_challenge_credentials(self):
        class Response:
            status_code = 200
            text = '{"user": {"id": 1}}'
            cookies = {"session": "ok"}

            def json(self):
                return {"user": {"id": 1}}

        class Session:
            cookies = {}

            def get(self, *args, **kwargs):
                return Response()

            def post(self, *args, **kwargs):
                return Response()

        endpoint = ChallengeFingerprinter(ROOT / "challenges" / "web")._try_login(
            Session(),
            "http://target",
            {"org": "workspace", "email": "user@example.test", "pin": "1234"},
        )
        self.assertEqual(endpoint, "/api/auth/login")

    def test_frontend_wrapper_routes_are_resolved(self):
        app_js = (ROOT / "solve" / "web" / "app.js").read_text(encoding="utf-8")
        routes = ChallengeFingerprinter._extract_api_endpoints(app_js)
        self.assertIn("/api/auth/login", routes)
        self.assertIn("/api/tickets", routes)
        self.assertNotIn("/api", routes)

    def test_challenge_credentials_are_read_from_description(self):
        metadata = ChallengeOrchestrator(provider="opencode").read_target_metadata(
            ROOT / "challenges" / "web"
        )
        self.assertEqual(metadata["credentials"]["org"], "nro-helpdesk")
        self.assertEqual(metadata["credentials"]["email"], "h.saidi@records.gov.example")
        self.assertEqual(metadata["credentials"]["pin"], "NRO2009")

    def test_custom_regex_groups_keep_the_complete_flag(self):
        engine = FlagEngine()
        regex = re.compile(r"(Securinets)\{([^}]+)\}")
        self.assertEqual(engine.extract_flags("Securinets{abc123}", regex), ["Securinets{abc123}"])

    def test_executor_passes_current_url_without_timeout(self):
        script = ROOT / "solve" / "web" / "exploit.py"
        flag_regex = re.compile(r"picoCTF\{[^}]+\}")
        completed = CompletedProcess([], 0, stdout="picoCTF{real_value}\n", stderr="")

        with patch("src.executor.subprocess.run", return_value=completed) as run:
            result = ExploitExecutor().run_script(script, flag_regex, "http://current-target")

        self.assertTrue(result["success"])
        self.assertEqual(run.call_args.args[0][-1], "http://current-target")
        self.assertIsNone(run.call_args.kwargs["timeout"])


if __name__ == "__main__":
    unittest.main()
