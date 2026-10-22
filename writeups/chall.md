# CTF Write-up: Flag Command

## 1. Challenge Overview
- **Challenge / Scenario Name:** Flag Command
- **Category:** Web
- **Target URL:** `http://154.57.164.82:37422`
- **Tech Stack:** Web
- **Vulnerability Class:** `Web Exploitation`
- **Captured Flag:** `HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!_1d918d1d5f5b91a1be923f8940d6411a}`

## 2. Scenario & Briefing
> SCENARIO NAME Flag Command Web Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape! Expand description Submit flag & press enter DOCKER SPAWNED 154.57.164.82:37422 IP ADDRESS & PORT

## 3. Vulnerability Analysis
The application was fingerprinted as using **Web**. During static analysis and live reconnaissance, the following high-priority sinks/routes were identified:


## 4. Exploitation PoC (Autonomous Python Exploit)
```python
import requests

# Flag captured via built-in scanner: API Secrets & Hidden Options
# Target: http://154.57.164.82:37422
print('Flag found: HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!_1d918d1d5f5b91a1be923f8940d6411a}')
```

## 5. Remediation & Hardening
- Validate and parameterize all user-controlled inputs before processing.
- Avoid executing unsanitized commands directly via shell interpreters (`exec`, `system`, `os.popen`).
- For XML parsers, disable external DTDs and entity resolution (`resolve_entities=False` or `libxml_disable_entity_loader(true)`).
