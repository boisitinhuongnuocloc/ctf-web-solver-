import os
import re
import zipfile
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

from .config import (
    CHALLENGES_DIR, SOLVE_DIR, WRITEUPS_DIR, MAX_SELF_HEAL_ATTEMPTS,
    DEFAULT_MODEL, DEFAULT_OPENCODE_MODEL, DEFAULT_AI_PROVIDER
)
from .flag_engine import FlagEngine
from .fingerprint import ChallengeFingerprinter
from .builtins import BuiltinScanners
from .ai_agent import create_ai_agent, OpenCodeAIAgent, OllamaAIAgent
from .executor import ExploitExecutor
from .memory import ExperienceMemory

class ChallengeOrchestrator:
    def __init__(self, model_name: Optional[str] = None, provider: Optional[str] = None):
        self.provider = provider or DEFAULT_AI_PROVIDER
        self.ai_agent = create_ai_agent(provider=self.provider, model_name=model_name)
        self.model_name = getattr(self.ai_agent, "model_name", model_name or "default")
        self.executor = ExploitExecutor()
        self.memory = ExperienceMemory()

    def auto_unpack_zips(self, base_dir: Path = CHALLENGES_DIR):
        """Unpacks any .zip files placed in the challenges directory into their own subfolders."""
        if not base_dir.exists():
            return
        for zip_file in base_dir.glob("*.zip"):
            target_dir = base_dir / zip_file.stem
            if not target_dir.exists():
                try:
                    with zipfile.ZipFile(zip_file, 'r') as zf:
                        zf.extractall(target_dir)
                except Exception:
                    pass

    def read_target_metadata(self, challenge_dir: Path) -> Dict[str, Any]:
        """Reads target URL, flag format hints, and scenario brief from text/markdown files inside challenge directory."""
        meta = {
            "url": None,
            "flag_prefix": None,
            "credentials": {},
            "scenario": {
                "name": None,
                "description": None,
                "flag_location": None
            }
        }
        
        # Scan candidate metadata files
        candidate_files = []
        for pat in ["*.txt", "*.md", "*.info", "*.json", "*.yaml", "*.yml"]:
            candidate_files.extend(challenge_dir.glob(pat))
            
        for fpath in candidate_files:
            if not fpath.is_file():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                
                # 1. Search for full URL (http://... or https://...)
                if not meta["url"]:
                    url_match = re.search(r'(https?://[^\s\'"<>]+)', content)
                    if url_match:
                        meta["url"] = url_match.group(1).rstrip("/.")
                
                # 2. Search for IP:PORT (e.g. 154.57.164.81:42720 or 127.0.0.1:8080)
                if not meta["url"]:
                    ip_port_match = re.search(r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5})\b', content)
                    if ip_port_match:
                        meta["url"] = f"http://{ip_port_match.group(1)}"

                # 3. Login clues commonly pasted into challenge descriptions.
                credential_patterns = {
                    "org": r"(?:workspace|organization|org)\s*[:=]\s*([^\s,;]+)",
                    "email": r"email\s*[:=]\s*([^\s,;]+)",
                    "username": r"(?:username|user)\s*[:=]\s*([^\s,;]+)",
                    "pin": r"(?:pin|passcode)\s*[:=]\s*([^\s,;]+)",
                    "password": r"password\s*[:=]\s*([^\s,;]+)",
                }
                for key, pattern in credential_patterns.items():
                    if key not in meta["credentials"]:
                        credential_match = re.search(pattern, content, re.I)
                        if credential_match:
                            meta["credentials"][key] = credential_match.group(1).strip().rstrip(".")
                
                # 3. Search for flag prefix or format hints (e.g. picoCTF{, HTB{, CSCC{)
                if not meta["flag_prefix"]:
                    flag_fmt_match = re.search(r'\b([a-zA-Z0-9_\-\.\+]{2,20})\{', content)
                    if flag_fmt_match:
                        pfx = flag_fmt_match.group(1)
                        if not pfx.lower().startswith("regex") and not pfx.lower().startswith("flag"):
                            meta["flag_prefix"] = pfx

                # 4. Scenario Name
                if not meta["scenario"]["name"]:
                    sc_match = re.search(r"(?:SCENARIO\s*NAME|CHALLENGE\s*NAME|Title)[:\s]*\n*([^\n\r]+)", content, re.I)
                    if sc_match:
                        meta["scenario"]["name"] = sc_match.group(1).strip()
                    else:
                        lines = [l.strip() for l in content.splitlines() if l.strip()]
                        if lines and len(lines[0]) < 40 and not lines[0].lower().startswith("http"):
                            if len(lines) > 1 and lines[1].lower() in ["web", "pwn", "crypto", "forensics", "rev", "misc", "general", "reverse"]:
                                meta["scenario"]["name"] = lines[0]

                # 5. Flag Location Hint (e.g. The flag is located in /flag.txt)
                if not meta["scenario"]["flag_location"]:
                    flag_loc_match = re.search(r"(?:flag|FLAG).*?(?:located\s+in|in|at|location[:\s]+)\s+([/\.][\w\.\-]+)", content, re.I)
                    if flag_loc_match:
                        meta["scenario"]["flag_location"] = flag_loc_match.group(1).strip()

                # 6. Overall description
                if not meta["scenario"]["description"] and len(content.strip()) > 25:
                    meta["scenario"]["description"] = content.strip()[:1000]

            except Exception:
                pass

        return meta

    def solve_challenge(
        self,
        challenge_dir: Path,
        target_url: Optional[str] = None,
        custom_prefix: Optional[str] = None,
        custom_regex: Optional[str] = None,
        logger_func = None
    ) -> Dict[str, Any]:
        """
        End-to-end autonomous solver for a single challenge directory.
        Outputs everything cleanly to solve/<challenge_name>/.
        """
        def log(msg: str):
            if logger_func:
                logger_func(msg)
            else:
                print(msg)

        chall_name = challenge_dir.name
        log(f"[*] Starting solver for challenge: [bold cyan]{chall_name}[/bold cyan]")

        # Prepare dedicated solve directory
        out_dir = SOLVE_DIR / chall_name
        out_dir.mkdir(parents=True, exist_ok=True)
        run_log_file = out_dir / "run.log"
        log_records = []

        def log_record(msg: str):
            log_records.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")
            log(msg)

        # 1. Metadata & Target URL
        meta = self.read_target_metadata(challenge_dir)
        effective_url = target_url or meta.get("url")
        effective_prefix = custom_prefix or meta.get("flag_prefix")
        credentials = meta.get("credentials") or {}

        # 2. Flag Format Engine
        flag_engine = FlagEngine(custom_prefix=effective_prefix, custom_regex=custom_regex)
        flag_regex = flag_engine.get_regex(challenge_dir)
        from rich.markup import escape
        log_record(f"Target Flag Regex: {escape(flag_regex.pattern)}")

        result_summary = {
            "challenge": chall_name,
            "status": "FAILED",
            "flag": None,
            "method": None,
            "attempts": 0,
            "solve_dir": str(out_dir)
        }

        # 3. Check for exposed flags in source files (YAML, Dockerfile, PHP, source code, unstripped files)
        scan_extensions = ["*.txt", "*.html", "*.js", "*.env", "*.yaml", "*.yml", "*.php", "*.py", "*.json", "*.md"]
        all_candidate_files = []
        for ext in scan_extensions:
            all_candidate_files.extend(challenge_dir.rglob(ext))
        for df in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
            df_path = challenge_dir / df
            if df_path.is_file() and df_path not in all_candidate_files:
                all_candidate_files.append(df_path)

        for fpath in all_candidate_files:
            if any(ignored in fpath.parts for ignored in [".git", "node_modules", "venv", "__pycache__"]):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                extracted = flag_engine.extract_flags(content, flag_regex)
                real_extracted = [fl for fl in extracted if flag_engine.is_likely_real_flag(fl)]
                if real_extracted:
                    captured = real_extracted[0]
                    log_record(f"[bold green][SUCCESS][/bold green] Flag found directly in challenge files ({fpath.name}): [bold yellow]{captured}[/bold yellow]")
                    (out_dir / "flag.txt").write_text(captured, encoding="utf-8")
                    result_summary["status"] = "SOLVED"
                    result_summary["flag"] = captured
                    result_summary["method"] = f"Static Source ({fpath.name})"
                    try:
                        self._generate_writeup(
                            chall_name=chall_name,
                            target_url=effective_url,
                            analysis_data={"tech_stack": ["Static Files"], "dangerous_sinks": []},
                            exploit_code=f"# Flag captured directly from static source file: {fpath.name}\nprint('{captured}')",
                            flag=captured,
                            scenario_info=meta.get("scenario")
                        )
                    except Exception:
                        pass
                    run_log_file.write_text("\n".join(log_records), encoding="utf-8")
                    return result_summary
            except Exception:
                pass

        # Check for multi-part fragmented flags across HTML/CSS/JS (Inspector style)
        frag_flag = flag_engine.find_fragmented_flag(challenge_dir)
        if frag_flag and flag_engine.is_likely_real_flag(frag_flag):
            log_record(f"[bold green][SUCCESS][/bold green] Multi-part flag reconstructed from source files: [bold yellow]{frag_flag}[/bold yellow]")
            (out_dir / "flag.txt").write_text(frag_flag, encoding="utf-8")
            result_summary["status"] = "SOLVED"
            result_summary["flag"] = frag_flag
            result_summary["method"] = "Source Fragment Assembly"
            try:
                self._generate_writeup(
                    chall_name=chall_name,
                    target_url=effective_url,
                    analysis_data={"tech_stack": ["Client-Side (HTML/CSS/JS)"], "dangerous_sinks": []},
                    exploit_code=f"# Multi-part flag reconstructed from comments/scripts\nprint('{frag_flag}')",
                    flag=frag_flag,
                    scenario_info=meta.get("scenario")
                )
            except Exception:
                pass
            run_log_file.write_text("\n".join(log_records), encoding="utf-8")
            return result_summary

        # 4. Fast Heuristic Built-in Checks (picoCTF quick wins)
        url_is_online = False
        if effective_url:
            try:
                import requests
                r_ping = requests.get(effective_url, timeout=3)
                url_is_online = True
            except Exception:
                url_is_online = False
                log_record(f"[!] Target URL ({effective_url}) is offline or unreachable. Will still generate exploit script.")
        else:
            log_record("[*] No live target URL provided. Analyzing source code offline.")

        if url_is_online:
            log_record(f"Running fast built-in checks against {effective_url}...")
            builtins = BuiltinScanners(effective_url, flag_regex, credentials=credentials)
            fast_flag, method_name = builtins.run_all()
            if fast_flag:
                log_record(f"[SUCCESS] Flag captured via {method_name}: {fast_flag}")
                (out_dir / "flag.txt").write_text(fast_flag, encoding="utf-8")
                result_summary["status"] = "SOLVED"
                result_summary["flag"] = fast_flag
                sc_name = (meta.get("scenario") or {}).get("name")
                exploit_snippet = (
                    f"import requests\n\n"
                    f"# Flag captured via built-in scanner: {method_name}\n"
                    f"# Target: {effective_url}\n"
                    f"print('Flag found: {fast_flag}')\n"
                )
                (out_dir / "exploit.py").write_text(exploit_snippet, encoding="utf-8")
                self.memory.record_solve(
                    challenge_name=chall_name,
                    analysis_data={"tech_stack": ["Web"], "dangerous_sinks": []},
                    exploit_code=exploit_snippet,
                    flag=fast_flag,
                    scenario_name=sc_name
                )
                log_record("[green][+] Learned! This exploit technique has been saved into Knowledge Base.[/green]")
                try:
                    self._generate_writeup(
                        chall_name=chall_name,
                        target_url=effective_url,
                        analysis_data={"tech_stack": ["Web"], "dangerous_sinks": []},
                        exploit_code=exploit_snippet,
                        flag=fast_flag,
                        scenario_info=meta.get("scenario")
                    )
                except Exception:
                    pass
                run_log_file.write_text("\n".join(log_records), encoding="utf-8")
                return result_summary

        # 5. Static Fingerprinting & Code Analysis
        log_record("Analyzing source code, Docker configs, and vulnerability sinks...")
        fingerprinter = ChallengeFingerprinter(challenge_dir)
        analysis_data = fingerprinter.analyze()
        
        # If live target is online, run live crawling reconnaissance
        if url_is_online:
            log_record(f"Crawling and fingerprinting live target application at {effective_url}...")
            try:
                fingerprinter.recon_live_target(effective_url, credentials=credentials)
            except Exception as e:
                pass
        
        # Save analysis artifact
        (out_dir / "analysis.json").write_text(json.dumps(analysis_data, indent=2), encoding="utf-8")
        log_record(f"Tech Stack detected: {', '.join(analysis_data['tech_stack']) or 'Generic Web'}")
        if analysis_data["dangerous_sinks"]:
            log_record(f"Found {len(analysis_data['dangerous_sinks'])} dangerous sinks.")

        # 6. Extract Code Context for AI
        code_context = self._gather_source_context(challenge_dir)

        # 7. Check Ollama availability
        if not self.ai_agent.is_available():
            log_record("[WARNING] Local Ollama service is not responding at " + self.ai_agent.host)
            result_summary["error"] = "Ollama service unavailable"
            run_log_file.write_text("\n".join(log_records), encoding="utf-8")
            return result_summary

        # 7. Query Persistent Experience Memory for Relevant Solved Patterns
        memory_context = self.memory.get_relevant_context(analysis_data)

        # Offline Target Handling: If no online target, generate 1 exploit template and exit cleanly
        if not url_is_online:
            log_record("[bold yellow][!] Mục tiêu hiện đang OFFLINE hoặc chưa có URL hoạt động.[/bold yellow]")
            ports_msg = ""
            if analysis_data.get("exposed_ports"):
                ports_msg = f" (gợi ý port từ Docker: {', '.join(analysis_data['exposed_ports'])})"
            
            log_record("[*] Đang sinh file exploit mẫu (template) dựa trên phân tích mã nguồn...")
            ai_resp = self.ai_agent.generate_exploit(
                challenge_name=chall_name,
                target_url=effective_url or "http://127.0.0.1:PORT",
                fingerprint_data=analysis_data,
                source_code_context=code_context,
                flag_pattern_str=flag_regex.pattern,
                previous_error=None,
                experience_context=memory_context,
                scenario_info=meta.get("scenario"),
                credentials=credentials
            )
            exploit_code = ai_resp.get("exploit_code", "")
            if exploit_code:
                script_path = out_dir / "exploit.py"
                script_path.write_text(exploit_code, encoding="utf-8")
                log_record(f"[green][+] Đã lưu script exploit mẫu tại: {script_path.name}[/green]")
            
            suggested_port = analysis_data["exposed_ports"][0] if analysis_data.get("exposed_ports") else "5000"
            log_record(f"[yellow][!] Hướng dẫn: Khởi động container / bật instance{ports_msg}, sau đó chạy lại lệnh:[/yellow]")
            log_record(f"    python solve.py -t challenges/{chall_name} -u http://127.0.0.1:{suggested_port}")
            
            result_summary["status"] = "OFFLINE_TEMPLATE_GENERATED"
            last_error = f"Target server is offline or unreachable ({effective_url or 'No URL provided'}). Please start the instance and specify -u <url>."
            self._generate_debrief(chall_name, analysis_data, last_error, result_summary, out_dir, log_func=log)
            run_log_file.write_text("\n".join(log_records), encoding="utf-8")
            return result_summary

        # 8. AI Agent Autonomous Solving Loop with Self-Healing (for Online Target)
        last_error = None
        for attempt in range(1, MAX_SELF_HEAL_ATTEMPTS + 1):
            result_summary["attempts"] = attempt
            log_record(f"[AI Agent] Generating exploit plan & code (Attempt {attempt}/{MAX_SELF_HEAL_ATTEMPTS})...")
            
            ai_resp = self.ai_agent.generate_exploit(
                challenge_name=chall_name,
                target_url=effective_url,
                fingerprint_data=analysis_data,
                source_code_context=code_context,
                flag_pattern_str=flag_regex.pattern,
                previous_error=last_error,
                experience_context=memory_context,
                scenario_info=meta.get("scenario"),
                credentials=credentials
            )

            exploit_code = ai_resp.get("exploit_code", "")
            if not exploit_code:
                log_record(f"[AI Agent] Failed to generate valid python exploit block on attempt {attempt}.")
                last_error = "LLM did not produce a valid python script block."
                continue

            # Display AI's strategic hypothesis
            reasoning_text = re.sub(r"```[\s\S]*?```", "", ai_resp.get("reasoning", "")).strip()
            if reasoning_text:
                log_record(f"[bold cyan][AI Attack Hypothesis & Strategy][/bold cyan]\n{reasoning_text[:350]}...")

            # Save exploit script to solve directory
            script_path = out_dir / "exploit.py"
            script_path.write_text(exploit_code, encoding="utf-8")
            log_record(f"Saved generated multi-vector exploit to {script_path.name}")

            # Execute exploit
            log_record("Executing exploit against target...")
            exec_res = self.executor.run_script(script_path, flag_regex, effective_url)
            
            if exec_res["success"] and exec_res["flag"]:
                captured_flag = exec_res["flag"]
                log_record(f"[bold green][SUCCESS][/bold green] Flag captured: [bold yellow]{captured_flag}[/bold yellow]")
                (out_dir / "flag.txt").write_text(captured_flag, encoding="utf-8")
                result_summary["status"] = "SOLVED"
                result_summary["flag"] = captured_flag
                result_summary["method"] = f"AI Agent ({self.model_name})"
                
                # Record successful solve into memory bank so AI gets smarter
                sc_name = (meta.get("scenario") or {}).get("name")
                self.memory.record_solve(
                    challenge_name=chall_name,
                    analysis_data=analysis_data,
                    exploit_code=exploit_code,
                    flag=captured_flag,
                    scenario_name=sc_name
                )
                log_record("[green][+] Learned! This exploit technique has been saved into Knowledge Base.[/green]")

                # Generate professional CTF writeup report
                try:
                    writeup_file = self._generate_writeup(
                        chall_name=chall_name,
                        target_url=effective_url,
                        analysis_data=analysis_data,
                        exploit_code=exploit_code,
                        flag=captured_flag,
                        scenario_info=meta.get("scenario")
                    )
                    log_record(f"[bold cyan][+] Write-up generated:[/bold cyan] {writeup_file}")
                except Exception as e:
                    pass

                break
            else:
                last_error = exec_res.get("error_summary", "Unknown error or no flag pattern found.")
                log_record(f"[Attempt {attempt} Failed] {last_error[:160]}...")

        # If challenge was not solved, generate diagnostic debrief
        if result_summary["status"] != "SOLVED":
            self._generate_debrief(chall_name, analysis_data, last_error, result_summary, out_dir, log_func=log)

        run_log_file.write_text("\n".join(log_records), encoding="utf-8")
        return result_summary

    def _generate_debrief(
        self,
        chall_name: str,
        analysis_data: Dict[str, Any],
        last_error: Optional[str],
        result_summary: Dict[str, Any],
        out_dir: Path,
        log_func = None
    ) -> str:
        lines = []
        lines.append("\n" + "=" * 65)
        lines.append(f"[bold yellow][!] BÁO CÁO CHẨN ĐOÁN & GỠ VƯỚNG (DEBRIEF): {chall_name}[/bold yellow]")
        lines.append("=" * 65)

        # 1. Đã phát hiện được gì
        lines.append("\n[bold cyan][1] ĐÃ PHÁT HIỆN ĐƯỢC GÌ (DISCOVERY):[/bold cyan]")
        lines.append(f"  * Tech Stack: {', '.join(analysis_data.get('tech_stack', [])) or 'Không xác định'}")
        if analysis_data.get("routes"):
            lines.append(f"  * Các endpoint tìm thấy: {', '.join(analysis_data['routes'][:6])}")
        if analysis_data.get("dangerous_sinks"):
            lines.append("  * Các điểm nhạy cảm (Sinks):")
            for s in analysis_data["dangerous_sinks"][:4]:
                lines.append(f"    - [{s['vuln_class']}] tại {s['file']}:L{s['line']}")

        # 2. Đã làm được những gì
        lines.append("\n[bold cyan][2] TIẾN TRÌNH ĐÃ THỬ (ATTEMPTS):[/bold cyan]")
        lines.append(f"  * Đã thử nghiệm: {result_summary.get('attempts', 0)} lượt sinh và chạy exploit tự động.")
        script_file = out_dir / "exploit.py"
        if script_file.is_file():
            lines.append(f"  * Script exploit gần nhất đã lưu tại: {script_file.name}")

        # 3. Điểm nghẽn / Vướng chỗ nào
        lines.append("\n[bold red][3] ĐIỂM NGHẼN / VƯỚNG CHỖ NÀO (BOTTLENECK):[/bold red]")
        if last_error:
            lines.append(f"  * Phản hồi / Lỗi từ mục tiêu: {last_error.strip()[:200]}")
        else:
            lines.append("  * Không nhận được lỗi cụ thể, nhưng output trả về chưa khớp định dạng Flag.")

        # 4. Gợi ý gỡ vướng cho bạn
        lines.append("\n[bold green][4] GỢI Ý BƯỚC TIẾP THEO (NEXT STEPS FOR HUMAN):[/bold green]")
        sinks_types = [s.get("vuln_class", "") for s in analysis_data.get("dangerous_sinks", [])]
        if any("SQL" in st for st in sinks_types):
            lines.append("  * [SQLi] Kiểm tra xem payload có cần comment (-- hoặc /*) để triệt tiêu vế password không.")
            lines.append("  * [SQLi] Thử các payload login bypass: admin' -- hoặc ' OR 1=1 --")
        elif any("Command" in st for st in sinks_types):
            lines.append("  * [RCE] Thử các ký tự nối lệnh khác nhau: & (cho Windows) hoặc ; | (cho Linux).")
            lines.append("  * [RCE] Kiểm tra vị trí file flag: thử đọc 'flag.txt' cục bộ thay vì '/flag.txt' hoặc biến môi trường.")
        elif any("SSTI" in st for st in sinks_types):
            lines.append("  * [SSTI] Thử rò rỉ config app: {{ config }} hoặc {{ config.FLAG }}")
        else:
            lines.append("  * Kiểm tra lại file Dockerfile/source xem Flag có được lưu trong biến môi trường ($FLAG) hay DB không.")

        lines.append("=" * 65 + "\n")
        debrief_text = "\n".join(lines)

        (out_dir / "debrief.md").write_text(debrief_text, encoding="utf-8")
        if log_func:
            log_func(debrief_text)
        return debrief_text

    def _generate_writeup(
        self,
        chall_name: str,
        target_url: Optional[str],
        analysis_data: Dict[str, Any],
        exploit_code: str,
        flag: str,
        scenario_info: Optional[Dict[str, Any]] = None
    ) -> Path:
        """Generates a professional Markdown CTF write-up report and saves it to writeups/<chall_name>.md."""
        WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)
        writeup_path = WRITEUPS_DIR / f"{chall_name}.md"
        
        sc_name = (scenario_info or {}).get("name") or chall_name
        sc_desc = (scenario_info or {}).get("description") or "N/A"
        tech = ", ".join(analysis_data.get("tech_stack", [])) or "Web"
        
        vulns = [s.get("vuln_class", "") for s in analysis_data.get("dangerous_sinks", [])]
        primary_vuln = vulns[0] if vulns else "Web Exploitation"
        
        md_lines = [
            f"# CTF Write-up: {sc_name}",
            "",
            "## 1. Challenge Overview",
            f"- **Challenge / Scenario Name:** {sc_name}",
            f"- **Category:** Web",
            f"- **Target URL:** `{target_url or 'Offline / Local'}`",
            f"- **Tech Stack:** {tech}",
            f"- **Vulnerability Class:** `{primary_vuln}`",
            f"- **Captured Flag:** `{flag}`",
            "",
            "## 2. Scenario & Briefing",
            f"> {sc_desc.replace(chr(10), ' ')}",
            "",
            "## 3. Vulnerability Analysis",
            f"The application was fingerprinted as using **{tech}**. During static analysis and live reconnaissance, the following high-priority sinks/routes were identified:",
            ""
        ]
        
        for s in analysis_data.get("dangerous_sinks", [])[:6]:
            md_lines.append(f"- **[{s.get('vuln_class')}]** at `{s.get('file')}:L{s.get('line')}`: `{s.get('snippet')}`")
            
        md_lines.extend([
            "",
            "## 4. Exploitation PoC (Autonomous Python Exploit)",
            "```python",
            exploit_code.strip(),
            "```",
            "",
            "## 5. Remediation & Hardening",
            "- Validate and parameterize all user-controlled inputs before processing.",
            "- Avoid executing unsanitized commands directly via shell interpreters (`exec`, `system`, `os.popen`).",
            "- For XML parsers, disable external DTDs and entity resolution (`resolve_entities=False` or `libxml_disable_entity_loader(true)`).",
            ""
        ])
        
        writeup_path.write_text("\n".join(md_lines), encoding="utf-8")
        if sc_name and sc_name != chall_name:
            safe_sc = re.sub(r'[^\w\-_]', '_', sc_name)
            (WRITEUPS_DIR / f"{safe_sc}.md").write_text("\n".join(md_lines), encoding="utf-8")
        return writeup_path

    def _gather_source_context(self, challenge_dir: Path, max_chars: int = 12000) -> str:
        """Gathers key source code files (app.py, controllers, dockerfiles) for AI prompt context."""
        collected = []
        total_len = 0
        
        # Priority filenames (descriptions, dockers, entrypoints)
        priority_files = [
            "challenge.txt", "description.txt", "README.md", "readme.md", "prompt.txt", "info.txt",
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            "app.py", "main.py", "index.php", "server.js", "app.js"
        ]
        for pfile in priority_files:
            fpath = challenge_dir / pfile
            if fpath.is_file():
                try:
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                    snippet = f"--- File: {pfile} ---\n{text}\n"
                    collected.append(snippet)
                    total_len += len(snippet)
                except Exception:
                    pass

        # If still space, gather other .py, .php, .js files
        if total_len < max_chars:
            for ext in ["*.py", "*.php", "*.js"]:
                for fpath in challenge_dir.rglob(ext):
                    if any(ignored in fpath.parts for ignored in [".git", "node_modules", "venv", "__pycache__"]):
                        continue
                    if fpath.name in priority_files:
                        continue
                    try:
                        text = fpath.read_text(encoding="utf-8", errors="ignore")
                        rel = fpath.relative_to(challenge_dir)
                        snippet = f"--- File: {rel} ---\n{text}\n"
                        if total_len + len(snippet) > max_chars:
                            snippet = snippet[:max_chars - total_len] + "\n...[TRUNCATED]\n"
                            collected.append(snippet)
                            break
                        collected.append(snippet)
                        total_len += len(snippet)
                    except Exception:
                        pass
        return "\n".join(collected)

    def solve_all(self, base_dir: Path = CHALLENGES_DIR, max_workers: int = 1) -> List[Dict[str, Any]]:
        """Solves all challenges found in challenges directory concurrently or sequentially."""
        self.auto_unpack_zips(base_dir)
        subdirs = [d for d in base_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
        
        if not subdirs:
            return []

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.solve_challenge, d) for d in subdirs]
            for f in futures:
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append({"status": "ERROR", "error": str(e)})
        return results
