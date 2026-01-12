import argparse
import json
import os
import random
import re
import string
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote_plus, urlparse

import requests


DEFAULT_HEADERS = {"User-Agent": "SubdomainAutomation/1.1"}
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 1.5
DEFAULT_API_PATHS = [
    "api/internal",
    "api/admin",
    "api/private",
    "internal",
    "admin/api",
    "v1/internal",
    "v1/admin",
]
DEFAULT_AUTHZ_ENDPOINTS = [
    "api/me",
    "api/users",
    "api/admin/users",
    "v1/users",
    "v1/admin/users",
]


@dataclass
class ToolResult:
    name: str
    success: bool
    output: str


def run_external_tool(command: Sequence[str]) -> ToolResult:
    tool_name = command[0]
    if not shutil_which(tool_name):
        return ToolResult(tool_name, False, f"{tool_name} not found in PATH.")
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        return ToolResult(tool_name, False, f"Failed to run {tool_name}: {exc}")
    success = completed.returncode == 0
    return ToolResult(tool_name, success, completed.stdout.strip())


def shutil_which(binary: str) -> Optional[str]:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path) / binary
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def request_json(url: str, headers: Optional[Dict[str, str]] = None) -> Optional[object]:
    response = request_with_backoff("GET", url, headers=headers)
    if not response or response.status_code != 200:
        return None
    try:
        return response.json()
    except json.JSONDecodeError:
        return None


def request_with_backoff(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, str]] = None,
) -> Optional[requests.Response]:
    for attempt in range(DEFAULT_RETRIES + 1):
        try:
            response = requests.request(
                method,
                url,
                headers=headers or DEFAULT_HEADERS,
                data=data,
                timeout=DEFAULT_TIMEOUT,
            )
            return response
        except requests.exceptions.RequestException:
            if attempt >= DEFAULT_RETRIES:
                return None
            time.sleep(DEFAULT_BACKOFF * (attempt + 1))
    return None


def search_scribd(query: str, limit: int = 20) -> List[str]:
    url = f"https://www.scribd.com/search?query={quote_plus(query)}"
    response = request_with_backoff("GET", url, headers=DEFAULT_HEADERS)
    if not response:
        return []
    if response.status_code != 200:
        return []
    matches = re.findall(r'href="(/document/\d+/[^"]+)"', response.text)
    results: List[str] = []
    for match in matches:
        full_url = f"https://www.scribd.com{match}"
        if full_url not in results:
            results.append(full_url)
        if len(results) >= limit:
            break
    return results


def extract_drive_id(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if parsed.query:
        query_match = re.search(r"(?:^|&)id=([a-zA-Z0-9_-]+)", parsed.query)
        if query_match:
            return query_match.group(1)
    path_match = re.search(r"/d/([a-zA-Z0-9_-]+)/", parsed.path)
    if path_match:
        return path_match.group(1)
    return None


def check_drive_link(url: str) -> Tuple[str, bool, str]:
    drive_id = extract_drive_id(url)
    if not drive_id:
        return url, False, "Unable to extract Google Drive ID."
    download_url = f"https://drive.google.com/uc?export=download&id={drive_id}"
    response = request_with_backoff("GET", download_url, headers=DEFAULT_HEADERS)
    if not response:
        return url, False, "Request failed."
    if response.status_code in {200, 302}:
        content_type = response.headers.get("Content-Type", "unknown")
        return url, True, f"Accessible (status {response.status_code}, type {content_type})."
    return url, False, f"Not accessible (status {response.status_code})."


def fetch_wayback_urls(domain: str, limit: int = 500) -> List[str]:
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    data = request_json(url)
    if not data or not isinstance(data, list):
        return []
    results = []
    for entry in data[1:]:
        if isinstance(entry, list) and entry:
            results.append(entry[0])
    return results


def fetch_virustotal_urls(domain: str, api_key: str) -> List[str]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}
    response = request_with_backoff("GET", url, headers=headers)
    if not response:
        return []
    if response.status_code != 200:
        return []
    data = response.json()
    urls = []
    for item in data.get("data", []):
        subdomain = item.get("id")
        if subdomain:
            urls.append(f"https://{subdomain}")
    return urls


def fetch_alienvault_urls(domain: str, api_key: str) -> List[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    headers = {"X-OTX-API-KEY": api_key}
    response = request_with_backoff("GET", url, headers=headers)
    if not response:
        return []
    if response.status_code != 200:
        return []
    data = response.json()
    return [item["url"] for item in data.get("url_list", []) if "url" in item]


def run_katana(domain: str) -> List[str]:
    result = run_external_tool(["katana", "-u", domain, "-silent"])
    if not result.success:
        return []
    return [line.strip() for line in result.output.splitlines() if line.strip()]


def run_host_scan(tool: str, targets: Sequence[str], ports: str) -> ToolResult:
    if tool == "nmap":
        return run_external_tool(["nmap", "-sV", "-p", ports, *targets])
    if tool == "naabu":
        return run_external_tool(["naabu", "-p", ports, *targets])
    return ToolResult(tool, False, "Unsupported scan tool.")


def authz_test(
    base_url: str,
    endpoints: Sequence[str],
    auth_header: Optional[str],
    auth_cookie: Optional[str],
    method: str = "GET",
) -> List[Tuple[str, int, int]]:
    results = []
    for endpoint in endpoints:
        url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        unauth_status = send_request(url, method=method, headers=None)
        auth_status = None
        headers = {}
        if auth_header and ":" in auth_header:
            key, value = auth_header.split(":", 1)
            headers[key.strip()] = value.strip()
        if auth_cookie:
            headers["Cookie"] = auth_cookie
        if headers:
            auth_status = send_request(url, method=method, headers=headers)
        results.append((endpoint, unauth_status, auth_status or 0))
    return results


def send_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, str]] = None,
) -> int:
    response = request_with_backoff(method, url, headers=headers, data=data)
    if not response:
        return 0
    return response.status_code


def identify_public_api_paths(base_url: str, paths: Sequence[str]) -> List[str]:
    public_paths = []
    for path in paths:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        response = request_with_backoff("GET", url, headers=DEFAULT_HEADERS)
        if not response:
            continue
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type or response.text.strip().startswith("{"):
                public_paths.append(path)
    return public_paths


def random_token(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def web_cache_poison_check(url: str) -> Dict[str, str]:
    token = random_token()
    headers = {
        "X-Forwarded-Host": f"{token}.example.com",
        "X-Host": f"{token}.example.com",
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Proto": "http",
    }
    first = request_with_backoff("GET", url, headers=headers)
    second = request_with_backoff("GET", url, headers=headers)
    if not first or not second:
        return {"status": "error", "details": "Request failed."}
    if first.text != second.text or first.status_code != second.status_code:
        return {"status": "possible", "details": "Response changed between identical cache-poison headers."}
    if token in first.text:
        return {"status": "possible", "details": "Injected host value reflected in response."}
    return {"status": "unknown", "details": "No obvious cache poisoning signal detected."}


def npm_audit(project_root: Path) -> Tuple[bool, str]:
    if not (project_root / "package.json").exists():
        return False, "No package.json found."
    if not shutil_which("npm"):
        return False, "npm not found in PATH."
    result = run_external_tool(["npm", "audit", "--json"])
    return result.success, result.output


def scan_js_files(project_root: Path) -> List[str]:
    patterns = [
        re.compile(r"\beval\("),
        re.compile(r"innerHTML\s*="),
        re.compile(r"document\.write\("),
    ]
    findings = []
    for path in project_root.rglob("*.js"):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in patterns:
            if pattern.search(content):
                findings.append(f"{path}: matched {pattern.pattern}")
    return findings


def email_html_injection_test(url: str, email: str, first_name: str, last_name: str) -> Dict[str, str]:
    payload = "<img src=x onerror=alert(1)>"
    data = {"email": email, "first_name": payload + first_name, "last_name": payload + last_name}
    response = request_with_backoff("POST", url, headers=DEFAULT_HEADERS, data=data)
    if not response:
        return {"status": "error", "details": "Request failed."}
    if payload in response.text:
        return {"status": "possible", "details": "Payload reflected in response."}
    return {"status": "unknown", "details": f"Status {response.status_code}."}


def intelx_search(domain: str, api_key: str) -> ToolResult:
    url = "https://2.intelx.io/intelligent/search"
    headers = {"x-key": api_key, "User-Agent": DEFAULT_HEADERS["User-Agent"]}
    payload = {"term": domain, "maxresults": 20, "media": 0, "target": 0, "timeout": 10}
    response = request_with_backoff("POST", url, headers=headers, data=json.dumps(payload))
    if not response:
        return ToolResult("intelx", False, "Request failed.")
    if response.status_code != 200:
        return ToolResult("intelx", False, f"Status {response.status_code}: {response.text}")
    return ToolResult("intelx", True, response.text)


def subdomain_takeover_check(urls: Sequence[str]) -> List[str]:
    fingerprints = {
        "NoSuchBucket": "Amazon S3",
        "There isn't a GitHub Pages site here.": "GitHub Pages",
        "Fastly error: unknown domain": "Fastly",
        "The specified bucket does not exist": "Google Cloud Storage",
    }
    vulnerable = []
    for url in urls:
        response = request_with_backoff("GET", url, headers=DEFAULT_HEADERS)
        if not response:
            continue
        for marker, provider in fingerprints.items():
            if marker in response.text:
                vulnerable.append(f"{url} ({provider})")
                break
    return vulnerable


def normalize_urls(urls: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    normalized = []
    for url in urls:
        clean = url.strip()
        if not clean:
            continue
        if clean not in seen:
            seen.add(clean)
            normalized.append(clean)
    return normalized


def discover_openapi_paths(base_url: str) -> List[str]:
    candidates = ["openapi.json", "swagger.json", "v2/api-docs", "swagger/v1/swagger.json"]
    discovered = []
    for candidate in candidates:
        url = f"{base_url.rstrip('/')}/{candidate}"
        data = request_json(url)
        if isinstance(data, dict):
            paths = data.get("paths")
            if isinstance(paths, dict):
                discovered.extend(paths.keys())
    return normalize_urls(discovered)


def run_nuclei(urls: Sequence[str], templates: Optional[str], severity: Optional[str]) -> ToolResult:
    if not urls:
        return ToolResult("nuclei", False, "No URLs provided.")
    if not shutil_which("nuclei"):
        return ToolResult("nuclei", False, "nuclei not found in PATH.")
    command = ["nuclei", "-silent"]
    if templates:
        command.extend(["-t", templates])
    if severity:
        command.extend(["-severity", severity])
    try:
        process = subprocess.run(
            command,
            input="\n".join(urls),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as exc:
        return ToolResult("nuclei", False, f"Failed to run nuclei: {exc}")
    return ToolResult("nuclei", process.returncode == 0, process.stdout.strip())


def load_list_from_file(path: Optional[str]) -> List[str]:
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError:
        return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security automation helpers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scribd_parser = subparsers.add_parser("scribd", help="Search Scribd for sensitive docs")
    scribd_parser.add_argument("query")
    scribd_parser.add_argument("--limit", type=int, default=20)

    gdrive_parser = subparsers.add_parser("gdrive", help="Check Google Drive links for exposure")
    gdrive_parser.add_argument("links", nargs="+")

    urls_parser = subparsers.add_parser("urls", help="Collect URLs from sources")
    urls_parser.add_argument("domain")
    urls_parser.add_argument("--wayback", action="store_true")
    urls_parser.add_argument("--katana", action="store_true")
    urls_parser.add_argument("--virustotal", action="store_true")
    urls_parser.add_argument("--alienvault", action="store_true")
    urls_parser.add_argument("--nuclei", action="store_true")
    urls_parser.add_argument("--nuclei-templates")
    urls_parser.add_argument("--nuclei-severity")

    hosts_parser = subparsers.add_parser("scan-hosts", help="Run host scanning tools")
    hosts_parser.add_argument("tool", choices=["nmap", "naabu"])
    hosts_parser.add_argument("targets", nargs="+")
    hosts_parser.add_argument("--ports", default="1-1024")

    authz_parser = subparsers.add_parser("authz", help="Authorization test cases")
    authz_parser.add_argument("base_url")
    authz_parser.add_argument("--endpoints-file")
    authz_parser.add_argument("--auth-header")
    authz_parser.add_argument("--auth-cookie")
    authz_parser.add_argument("--method", default="GET")

    api_parser = subparsers.add_parser("api-paths", help="Identify unauthenticated API paths")
    api_parser.add_argument("base_url")
    api_parser.add_argument("--paths-file")
    api_parser.add_argument("--openapi", action="store_true")

    cache_parser = subparsers.add_parser("cache-poison", help="Web cache poisoning checks")
    cache_parser.add_argument("url")

    npm_parser = subparsers.add_parser("npm-audit", help="Run npm audit + JS scanning")
    npm_parser.add_argument("--root", default=".")

    email_parser = subparsers.add_parser("email-injection", help="HTML injection signup test")
    email_parser.add_argument("url")
    email_parser.add_argument("--email", default="test@example.com")
    email_parser.add_argument("--first-name", default="Test")
    email_parser.add_argument("--last-name", default="User")

    intelx_parser = subparsers.add_parser("intelx", help="IntelX credentials leak search")
    intelx_parser.add_argument("domain")
    intelx_parser.add_argument("--api-key")

    takeover_parser = subparsers.add_parser("takeover", help="Subdomain takeover fingerprints")
    takeover_parser.add_argument("urls", nargs="+")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scribd":
        results = search_scribd(args.query, args.limit)
        print("\n".join(results) if results else "No results found.")
        return
    if args.command == "gdrive":
        for link in args.links:
            url, exposed, detail = check_drive_link(link)
            status = "EXPOSED" if exposed else "SAFE"
            print(f"{status}: {url} -> {detail}")
        return
    if args.command == "urls":
        collected = []
        if args.wayback:
            collected.extend(fetch_wayback_urls(args.domain))
        if args.katana:
            collected.extend(run_katana(args.domain))
        if args.virustotal:
            api_key = os.environ.get("VT_API_KEY")
            if api_key:
                collected.extend(fetch_virustotal_urls(args.domain, api_key))
            else:
                print("VT_API_KEY not set; skipping VirusTotal.")
        if args.alienvault:
            api_key = os.environ.get("OTX_API_KEY")
            if api_key:
                collected.extend(fetch_alienvault_urls(args.domain, api_key))
            else:
                print("OTX_API_KEY not set; skipping AlienVault.")
        normalized = normalize_urls(collected)
        for url in normalized:
            print(url)
        if args.nuclei:
            result = run_nuclei(
                normalized, templates=args.nuclei_templates, severity=args.nuclei_severity
            )
            print(result.output or result.name)
        return
    if args.command == "scan-hosts":
        result = run_host_scan(args.tool, args.targets, args.ports)
        print(result.output)
        return
    if args.command == "authz":
        endpoints = load_list_from_file(args.endpoints_file) or DEFAULT_AUTHZ_ENDPOINTS
        results = authz_test(
            args.base_url,
            endpoints,
            args.auth_header,
            args.auth_cookie,
            args.method,
        )
        for endpoint, unauth, auth in results:
            print(f"{endpoint}: unauth={unauth} auth={auth}")
        return
    if args.command == "api-paths":
        paths = load_list_from_file(args.paths_file) or DEFAULT_API_PATHS
        if args.openapi:
            paths = normalize_urls(list(paths) + discover_openapi_paths(args.base_url))
        findings = identify_public_api_paths(args.base_url, paths)
        if findings:
            for path in findings:
                print(f"Unauthenticated access: {path}")
        else:
            print("No public API paths detected.")
        return
    if args.command == "cache-poison":
        result = web_cache_poison_check(args.url)
        print(f"{result['status']}: {result['details']}")
        return
    if args.command == "npm-audit":
        root = Path(args.root)
        success, output = npm_audit(root)
        print(output)
        js_findings = scan_js_files(root)
        if js_findings:
            print("JS findings:")
            print("\n".join(js_findings))
        return
    if args.command == "email-injection":
        result = email_html_injection_test(args.url, args.email, args.first_name, args.last_name)
        print(f"{result['status']}: {result['details']}")
        return
    if args.command == "intelx":
        api_key = args.api_key or os.environ.get("INTELX_API_KEY")
        if not api_key:
            print("INTELX_API_KEY not set; cannot query IntelX.")
            return
        result = intelx_search(args.domain, api_key)
        print(result.output)
        return
    if args.command == "takeover":
        findings = subdomain_takeover_check(args.urls)
        if findings:
            print("Potential takeover signatures:")
            print("\n".join(findings))
        else:
            print("No takeover signatures detected.")


if __name__ == "__main__":
    main()
