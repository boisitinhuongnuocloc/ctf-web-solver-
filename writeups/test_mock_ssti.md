# CTF Write-up: test_mock_ssti

## 1. Challenge Overview
- **Challenge / Scenario Name:** test_mock_ssti
- **Category:** Web
- **Target URL:** `http://127.0.0.1:5000`
- **Tech Stack:** Static Files
- **Vulnerability Class:** `Web Exploitation`
- **Captured Flag:** `picoCTF{mock_ssti_solved_succesfully}`

## 2. Scenario & Briefing
> N/A

## 3. Vulnerability Analysis
The application was fingerprinted as using **Static Files**. During static analysis and live reconnaissance, the following high-priority sinks/routes were identified:


## 4. Exploitation PoC (Autonomous Python Exploit)
```python
# Flag captured directly from static source file: Dockerfile
print('picoCTF{mock_ssti_solved_succesfully}')
```

## 5. Remediation & Hardening
- Validate and parameterize all user-controlled inputs before processing.
- Avoid executing unsanitized commands directly via shell interpreters (`exec`, `system`, `os.popen`).
- For XML parsers, disable external DTDs and entity resolution (`resolve_entities=False` or `libxml_disable_entity_loader(true)`).
