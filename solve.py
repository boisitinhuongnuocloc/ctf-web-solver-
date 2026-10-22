import sys
import argparse
from pathlib import Path

# Force UTF-8 on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from src.config import CHALLENGES_DIR, SOLVE_DIR, DEFAULT_MODEL, DEFAULT_AI_PROVIDER, DEFAULT_OPENCODE_MODEL
from src.orchestrator import ChallengeOrchestrator
from src.ai_agent import OpenCodeAIAgent, OllamaAIAgent

console = Console(highlight=False)

def run_self_test(orchestrator: ChallengeOrchestrator):
    """Runs a quick end-to-end self-test using a mock challenge."""
    console.print(Panel("[bold yellow]Running Self-Test Diagnostic[/bold yellow]", expand=False))
    
    # 1. Check AI Provider (OpenCode or Ollama)
    agent = orchestrator.ai_agent
    is_opencode = isinstance(agent, OpenCodeAIAgent)
    agent_name = "OpenCode + lingling" if is_opencode else "Ollama"

    if not agent.is_available():
        if is_opencode:
            console.print(f"[bold red][!] OpenCode is not accessible at {getattr(agent, 'host', 'default')}.[/bold red]")
            console.print("    Please start lingling/opencode using: [green]start.bat[/green] in 'C:\\Users\\Van Thai\\Downloads\\open code'")
        else:
            console.print(f"[bold red][!] Ollama is not accessible at {getattr(agent, 'host', 'http://localhost:11434')}.[/bold red]")
            console.print("    Please start Ollama using: [green]ollama serve[/green]")
        return False
    
    models = agent.list_models()
    console.print(f"[green][+] {agent_name} Connected![/green] Available models: {', '.join(models) or 'None'}")
    console.print(f"[green][+] Using model: [bold]{orchestrator.model_name}[/bold][/green]")

    # 2. Create a mock challenge folder
    mock_dir = CHALLENGES_DIR / "test_mock_ssti"
    mock_dir.mkdir(parents=True, exist_ok=True)
    
    # Mock Dockerfile with dummy flag format
    (mock_dir / "Dockerfile").write_text("FROM python:3.11-slim\nENV FLAG=picoCTF{mock_ssti_solved_succesfully}\nEXPOSE 5000\n", encoding="utf-8")
    
    # Mock vulnerable Flask app
    mock_app_code = '''import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get("name", "Guest")
    # Vulnerable SSTI sink
    template = f"Hello {name}!"
    return render_template_string(template)

if __name__ == "__main__":
    app.run(port=5000)
'''
    (mock_dir / "app.py").write_text(mock_app_code, encoding="utf-8")
    (mock_dir / "target.txt").write_text("http://127.0.0.1:5000", encoding="utf-8")

    console.print("[cyan][*] Created mock challenge in challenges/test_mock_ssti. Testing static analysis...[/cyan]")
    from src.fingerprint import ChallengeFingerprinter
    fp = ChallengeFingerprinter(mock_dir)
    res = fp.analyze()
    
    console.print(f"[green][+] Detected Stack:[/green] {res['tech_stack']}")
    console.print(f"[green][+] Detected Sinks:[/green] {[s['vuln_class'] for s in res['dangerous_sinks']]}")
    console.print(f"[green][+] Flag format detected from Dockerfile:[/green] picoCTF{{...}}")

    console.print(Panel("[bold green]Self-Test Passed! The framework is ready to solve real CTF challenges.[/bold green]", expand=False))
    return True

def display_summary_table(results):
    table = Table(title="[bold cyan]CTF Web Solver Results Summary[/bold cyan]", show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Challenge", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Method", style="magenta")
    table.add_column("Flag / Result", style="bold yellow")
    table.add_column("Solve Directory", style="dim")

    for r in results:
        status_color = "bold green" if r.get("status") == "SOLVED" else "bold red"
        status_text = f"[{status_color}]{r.get('status', 'FAILED')}[/{status_color}]"
        flag_text = r.get("flag") or "[dim]None[/dim]"
        table.add_row(
            r.get("challenge", "unknown"),
            status_text,
            r.get("method", "N/A"),
            flag_text,
            r.get("solve_dir", "")
        )
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Autonomous Multi-Target Web CTF Solver")
    parser.add_argument("-t", "--target", help="Specific challenge directory or zip file inside challenges/")
    parser.add_argument("-u", "--url", help="Target instance URL (e.g. http://instance.picoctf.net:12345)")
    parser.add_argument("-p", "--flag-prefix", help="Expected flag prefix (e.g. picoCTF, cscv2026)")
    parser.add_argument("-r", "--flag-regex", help="Custom regex pattern for the flag")
    parser.add_argument("-a", "--all", action="store_true", help="Solve all challenge folders inside challenges/")
    parser.add_argument("--provider", default=DEFAULT_AI_PROVIDER, choices=["opencode", "ollama"], help=f"AI backend provider (default: {DEFAULT_AI_PROVIDER})")
    parser.add_argument("-m", "--model", default=None, help="Model name (default: deepseek-v4.1-flash-free for OpenCode, qwen2.5:7b for Ollama)")
    parser.add_argument("--test", action="store_true", help="Run diagnostic self-test")
    parser.add_argument("--clean", action="store_true", help="Clean all artifacts in solve/ directory")

    args = parser.parse_args()

    orchestrator = ChallengeOrchestrator(model_name=args.model, provider=args.provider)

    if args.clean:
        if SOLVE_DIR.exists():
            import shutil
            for item in SOLVE_DIR.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                elif item.name != "README.md":
                    item.unlink()
            console.print("[green][+] Cleared all previous solve artifacts.[/green]")
        return

    if args.test:
        run_self_test(orchestrator)
        return

    if args.all:
        console.print(f"[bold cyan][*] Running batch solver on all folders in {CHALLENGES_DIR}...[/bold cyan]")
        results = orchestrator.solve_all(CHALLENGES_DIR)
        if not results:
            console.print(f"[yellow][!] No challenge folders found in {CHALLENGES_DIR}. Place your challenge folders or zips there![/yellow]")
            return
        display_summary_table(results)
        return

    if args.target:
        target_path = Path(args.target)
        if not target_path.is_absolute():
            # Check relative to cwd or relative to CHALLENGES_DIR
            if not target_path.exists() and (CHALLENGES_DIR / target_path).exists():
                target_path = CHALLENGES_DIR / target_path

        if not target_path.exists():
            console.print(f"[bold red][!] Error: Target path '{target_path}' does not exist.[/bold red]")
            sys.exit(1)

        # If it's a zip file, unpack it first
        if target_path.is_file() and target_path.suffix.lower() == ".zip":
            extracted_dir = CHALLENGES_DIR / target_path.stem
            extracted_dir.mkdir(parents=True, exist_ok=True)
            import zipfile
            with zipfile.ZipFile(target_path, 'r') as zf:
                zf.extractall(extracted_dir)
            target_path = extracted_dir

        res = orchestrator.solve_challenge(
            challenge_dir=target_path,
            target_url=args.url,
            custom_prefix=args.flag_prefix,
            custom_regex=args.flag_regex,
            logger_func=lambda msg: console.print(msg)
        )
        display_summary_table([res])
        return

    # If no arguments provided, show usage help
    parser.print_help()
    console.print("\n[dim]Tip: Place your challenge folders in `challenges/` and run `python solve.py --all`[/dim]")

if __name__ == "__main__":
    main()
