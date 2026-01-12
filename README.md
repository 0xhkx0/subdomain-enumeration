# Subdomain Enumeration Toolkit

This repository provides a single command-line entry point for subdomain scanning and automation helpers. You can run everything through `main.py` (or the installed `subdomain-enum` command) without invoking `automation.py` directly.

## Requirements

- Python 3.8+
- `requests`

## Installation

### Install as a CLI (recommended)

```bash
pip install .
```

This installs the `subdomain-enum` command.

For editable installs during development:

```bash
pip install -e .
```

### Run as scripts (no install)

```bash
pip install requests
```

## CLI Overview

Get help for all commands:

```bash
subdomain-enum -h
```

Or without installing:

```bash
python main.py -h
```

## Subdomain Scanner

### Usage

```bash
subdomain-enum scan <domain> [--wordlist WORDLIST] [--threads N]
```

Or:

```bash
python main.py scan <domain> [--wordlist WORDLIST] [--threads N]
```

### Arguments

- `domain`: target domain to scan (e.g., `example.com`).
- `--wordlist`, `-w`: path to a wordlist file (default: `subdomains.txt`).
- `--threads`, `-t`: number of worker threads (default: `50`).

### Example

```bash
subdomain-enum scan example.com -w subdomains.txt -t 100
```

### Legacy Usage

The original usage still works and runs the scanner:

```bash
python main.py example.com -w subdomains.txt -t 100
```

### Notes

- The scanner performs `http://<subdomain>.<domain>` requests and reports `200 OK` responses.
- If the wordlist file is missing, the scanner falls back to a default list containing `hacked`.
- Results are printed to STDOUT and not written to a file.

## Automation Helpers

All automation helpers are available through `main.py` or `subdomain-enum`.

```bash
subdomain-enum <command> [options]
```

Or:

```bash
python main.py <command> [options]
```

The dedicated script (`automation.py`) still works, but it is no longer required.

### Scribd Search

Search Scribd for documents containing a query string.

```bash
subdomain-enum scribd "company secret" --limit 20
```

### Google Drive Exposure Check

Check Drive URLs for public accessibility.

```bash
subdomain-enum gdrive "https://drive.google.com/file/d/FILE_ID/view"
```

### URL Collection

Collect URLs using different sources.

```bash
subdomain-enum urls example.com --wayback --katana
```

Optional sources/flags:

- `--wayback`: Wayback Machine CDX search
- `--katana`: run `katana` locally (must be installed and in PATH)
- `--virustotal`: VirusTotal subdomain API (requires `VT_API_KEY`)
- `--alienvault`: AlienVault OTX URL list (requires `OTX_API_KEY`)
- `--nuclei`: run `nuclei` on collected URLs
- `--nuclei-templates`: template path for `nuclei`
- `--nuclei-severity`: severity filter for `nuclei`

Environment variables for API access:

```bash
export VT_API_KEY="your_api_key"
export OTX_API_KEY="your_api_key"
```

### Host Scanning

Run `nmap` or `naabu` against targets.

```bash
subdomain-enum scan-hosts nmap 10.0.0.1 --ports 1-1024
```

### Authorization Checks

Probe endpoints with/without auth headers or cookies.

```bash
subdomain-enum authz https://api.example.com \
  --endpoints-file endpoints.txt \
  --auth-header "Authorization: Bearer TOKEN" \
  --auth-cookie "session=abc" \
  --method GET
```

If no endpoints file is provided, defaults are used.

### Public API Path Detection

Check for unauthenticated API responses.

```bash
subdomain-enum api-paths https://api.example.com --openapi
```

### Cache Poisoning Probe

Run a basic cache poisoning check with injected headers.

```bash
subdomain-enum cache-poison https://example.com
```

### npm Audit + JS Scanning

Run `npm audit` and scan JS files for risky patterns.

```bash
subdomain-enum npm-audit --root .
```

### HTML Injection Test

Test a signup endpoint for HTML injection in name fields.

```bash
subdomain-enum email-injection https://example.com/signup \
  --email test@example.com \
  --first-name Test \
  --last-name User
```

### IntelX Search

Search IntelX for credential leaks.

```bash
subdomain-enum intelx example.com --api-key YOUR_KEY
```

Or set:

```bash
export INTELX_API_KEY="your_api_key"
```

### Subdomain Takeover Fingerprints

Check URLs for common takeover signatures.

```bash
subdomain-enum takeover https://sub.example.com https://static.example.com
```

## Safety & Legal

Use these tools only against assets you own or have permission to test. Respect rate limits and terms of service for third-party APIs.
