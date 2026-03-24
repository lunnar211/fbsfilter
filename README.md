# fbsfilter

**FBSFilter** is an advanced GUI credential-filter and proxy-management tool for Windows.  
It ships as a ready-to-run **`FBSFilter.exe`** – no Python installation required.

> ⚠️ **Legal Notice** – This tool is intended solely for security research, penetration testing, and account recovery on systems you own or have explicit written permission to test. Unauthorised credential stuffing or account access is illegal in most jurisdictions. The authors assume no liability for misuse.

---

## ⬇️ Download the Windows EXE

**Pre-built binaries are automatically produced by GitHub Actions.**

| How to get the EXE | Steps |
|---|---|
| **Latest release** | Go to the [Releases](../../releases) page → download `FBSFilter-Windows.zip` → extract → run `FBSFilter.exe` |
| **From a CI build** | Go to [Actions](../../actions) → click the most recent *Build Windows EXE* run → scroll to **Artifacts** → download `FBSFilter-Windows-EXE` |

> No Python, no pip, no dependencies to install – just unzip and double-click `FBSFilter.exe`.

---

## Features

| Feature | Details |
|---|---|
| **GUI application** | Dark-themed desktop app – runs without a terminal |
| **Credential Checker** | Multi-threaded login testing; configurable target URL, threads, timeout |
| **Proxy Filter** | Paste any proxy list (proxydb.net, raw dumps, etc.), auto-detect format, filter by type / anonymity / country, live-test all proxies concurrently |
| **AI Assistant** | Groq-powered credential pattern analysis and proxy analysis (requires free API key) |
| **Settings** | Persist target URL, login field names, threading parameters across sessions |
| **Result categories** | `working.txt`, `invalid.txt`, `locked.txt`, `2fa.txt` |
| **Proxy rotation** | HTTP / HTTPS / SOCKS4 / SOCKS5 with automatic bad-proxy removal |
| **Checkpoint / resume** | Saves progress; resumes if interrupted |

---

## First Launch

1. **Run `FBSFilter.exe`**
2. A dialog will ask for a **Groq API key** (for the AI features)
   - Get a free key at <https://console.groq.com/keys>
   - Click **Skip** to use normal mode – all non-AI features work without a key

---

## GUI Tabs

### 🔑 Credential Checker
- Browse for a credential file (`user:pass` per line) and an optional proxy file
- Configure threads, timeout, delimiter
- Hit **▶ Start Checking** – live progress bar and colour-coded stats update in real time
- Results are written to `working.txt`, `invalid.txt`, `locked.txt`, `2fa.txt`

### 🌐 Proxy Filter
- Paste any proxy list – supports every format:
  - `1.2.3.4:8080`
  - `http://1.2.3.4:8080`
  - Tab-separated table rows from proxydb.net, proxyscrape.com, etc.
- Filter by **protocol** (HTTP / HTTPS / SOCKS4 / SOCKS5)
- Filter by **anonymity level** (Transparent / Anonymous / Elite)
- Filter by **country code**
- **Live proxy testing** – concurrent test with configurable timeout and worker count
- Save the filtered list in URL, `host:port`, or CSV format
- **→ Use as Proxy File** sets the filtered list directly in the Credential Checker tab
- **✨ AI Suggest Filters** uses Groq to auto-suggest the best filter settings (requires API key)

### 🤖 AI Assistant
- Connect a Groq API key at any time
- **Credential Analysis** – identifies patterns in your credential list (weak passwords, disposable emails, test accounts)
- **Proxy Analysis** – summarises your proxy list and suggests optimal filters
- Passwords are **never sent raw** to the AI – only username, password length, and character-class patterns are transmitted

### ⚙️ Settings
- Target URL, username/password form fields, success/failure keywords
- Thread count, timeout, retry count, request delay, credential delimiter
- All settings are saved automatically

---

## Project Structure

```
fbsfilter/
├── fbsfilter_gui.py      # GUI application (main entry point)
├── fbsfilter.py          # Legacy CLI entry point
├── fbsfilter.spec        # PyInstaller build spec
├── build_exe.py          # Local build helper script
├── config.ini            # Default configuration
├── requirements.txt      # Python dependencies
├── .github/
│   └── workflows/
│       └── build_exe.yml # CI: builds FBSFilter.exe on Windows automatically
└── utils/
    ├── __init__.py
    ├── ai_filter.py      # Groq AI integration
    ├── checker.py        # HTTP login attempt + result classification
    ├── file_handler.py   # Streaming file I/O + result writers
    ├── proxy_filter.py   # Advanced proxy parsing, filtering, testing
    └── proxy_manager.py  # Proxy pool with rotation (used by CLI)
```

---

## Building the EXE Locally (Windows)

If you want to build the EXE yourself:

```powershell
# 1. Install Python 3.11+ from python.org
# 2. Install dependencies
pip install -r requirements.txt

# 3. Build using the helper script
python build_exe.py
# or directly:
pyinstaller fbsfilter.spec --noconfirm --clean
```

The output will be in `dist\FBSFilter\FBSFilter.exe`.  
Zip the entire `dist\FBSFilter\` folder for distribution.

---

## CLI Usage (fbsfilter.py)

The original command-line tool still works:

```bash
# No proxy, 20 threads
python fbsfilter.py -i leaks.txt -t 20

# With proxy file, 50 threads
python fbsfilter.py -i leaks.txt -p proxies.txt -t 50
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP requests |
| `requests[socks]` | SOCKS4/5 proxy support |
| `groq` | Groq AI API client |
| `colorama` | Coloured console output on Windows |
| `tqdm` | Progress bars |
| `urllib3` | SSL warning suppression |
| `pyinstaller` | Builds the standalone `.exe` |

