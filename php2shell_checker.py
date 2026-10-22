#!/usr/bin/env python3
"""
PHP2Shell Checker — passive PHP fingerprinting and version-based exposure assessment.

Only sends ordinary HTTP GET requests to the targets explicitly supplied by the user.
It does not exploit PHP2Shell or attempt code execution. Use only on systems you are
authorized to assess.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import html
import json
import logging
import random
import re
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    Console = None

TOOL_NAME = "PHP2Shell Checker"
VERSION = "1.1.0"
AUTHOR = "er4pwn"
DEFAULT_UA = f"PHP2Shell-Checker/{VERSION} (authorized defensive assessment)"
PHP_BRANCHES = {
    "8.2": {"last_vulnerable": (8, 2, 34), "fixed": (8, 2, 35)},
    "8.3": {"last_vulnerable": (8, 3, 35), "fixed": (8, 3, 36)},
    "8.4": {"last_vulnerable": (8, 4, 26), "fixed": (8, 4, 27)},
    "8.5": {"last_vulnerable": (8, 5, 11), "fixed": (8, 5, 12)},
}
VERSION_RE = re.compile(r"\bPHP[/\s-]?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", re.I)
PHP_ERROR_RE = re.compile(
    r"(Fatal error|Parse error|Uncaught\s+\w+Error|PHP Warning|PHP Notice|"
    r"Stack trace:|Undefined (?:variable|array key)|Call to undefined function)",
    re.I,
)
FRAMEWORKS = {
    "WordPress": [
        re.compile(r"/wp-content/", re.I), re.compile(r"/wp-includes/", re.I),
        re.compile(r"content=[\"\']WordPress", re.I),
    ],
    "Drupal": [
        re.compile(r"/sites/(?:default|all)/", re.I), re.compile(r"/core/misc/drupal", re.I),
        re.compile(r"drupalSettings", re.I),
    ],
    "Joomla": [
        re.compile(r"/media/system/", re.I), re.compile(r"/administrator/templates/", re.I),
        re.compile(r"content=[\"\']Joomla", re.I),
    ],
    "Laravel": [
        re.compile(r"laravel_session", re.I), re.compile(r"laravel", re.I),
    ],
    "CodeIgniter": [re.compile(r"ci_session", re.I), re.compile(r"CodeIgniter", re.I)],
    "Symfony": [re.compile(r"symfony", re.I), re.compile(r"_profiler", re.I)],
    "Magento": [re.compile(r"Magento_", re.I), re.compile(r"/static/version\d+/", re.I)],
    "TYPO3": [re.compile(r"typo3", re.I)],
    "Moodle": [re.compile(r"moodle", re.I), re.compile(r"/theme/yui_combo\.php", re.I)],
}
COMMON_PHP_PATHS = [
    "/index.php", "/login.php", "/wp-login.php", "/user/login",
    "/administrator/", "/phpinfo.php", "/info.php", "/test.php",
]
DISCOVERY_PATHS = ["/phpinfo.php", "/info.php"]  # special reporting; no broad brute force
SAFE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
]

@dataclass
class Finding:
    category: str
    evidence: str
    url: str = ""
    confidence: str = "low"
    details: dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    target: str
    scanned_at: str
    final_url: str = ""
    http_status: int | None = None
    title: str = ""
    server_header: str = ""
    x_powered_by: str = ""
    php_detected: bool = False
    php_version: str | None = None
    version_assessment: str = "Unknown"
    framework_cms: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    php_pages: list[dict[str, Any]] = field(default_factory=list)
    phpinfo: list[dict[str, Any]] = field(default_factory=list)
    php_error_signatures: list[dict[str, Any]] = field(default_factory=list)
    indicators: list[Finding] = field(default_factory=list)
    confidence_score: int = 0
    confidence: str = "None"
    assessment: str = "No PHP Evidence"
    errors: list[str] = field(default_factory=list)
    requests_made: int = 0
    duration_seconds: float = 0.0

def parse_version(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not m:
        return None
    return tuple(map(int, m.groups()))

def assess_version(version: str | None) -> str:
    """Return a decisive version-threshold verdict when a supported PHP version is disclosed."""
    parsed = parse_version(version)
    if not parsed:
        return "INCONCLUSIVE — PHP version not confirmed"
    major, minor, patch = parsed
    branch = f"{major}.{minor}"
    if branch not in PHP_BRANCHES:
        return "INCONCLUSIVE — no configured threshold for this PHP branch"
    if parsed <= PHP_BRANCHES[branch]["last_vulnerable"]:
        return "VULNERABLE VERSION — disclosed version is in the supplied affected range"
    if parsed >= PHP_BRANCHES[branch]["fixed"]:
        return "NOT VULNERABLE BY VERSION — disclosed version meets the supplied fixed threshold"
    return "INCONCLUSIVE — version falls between configured thresholds"

def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Empty target")
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    p = urlparse(target)
    if not p.hostname or p.scheme not in ("http", "https"):
        raise ValueError(f"Invalid HTTP(S) target: {target}")
    return target.rstrip("/")

def confidence_label(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"

class Scanner:
    def __init__(self, timeout: float = 8.0, delay: float = 0.15,
                 verify_tls: bool = True, max_body: int = 1_000_000,
                 user_agent: str = DEFAULT_UA, rotate_ua: bool = False,
                 proxy: str | None = None, retries: int = 1, progress: bool = False):
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.verify_tls = verify_tls
        self.max_body = max_body
        self.user_agent = user_agent
        self.rotate_ua = rotate_ua
        self.proxy = proxy
        self.retries = retries
        self.progress = progress

    def _step(self, message: str) -> None:
        if self.progress:
            print(f"[*] {message}", flush=True)

    def _session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=self.retries, connect=self.retries, read=0, status=0,
                      backoff_factor=0.3, allowed_methods=frozenset(["GET"]),
                      raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        if self.proxy:
            s.proxies.update({"http": self.proxy, "https": self.proxy})
        return s

    def _get(self, session: requests.Session, url: str, result: ScanResult,
             allow_redirects: bool = True) -> tuple[requests.Response | None, str]:
        if self.delay:
            time.sleep(self.delay)
        if self.rotate_ua:
            session.headers["User-Agent"] = random.choice(SAFE_USER_AGENTS)
        try:
            with session.get(url, timeout=self.timeout, verify=self.verify_tls,
                             allow_redirects=allow_redirects, stream=True) as response:
                result.requests_made += 1
                chunks, size = [], 0
                try:
                    for chunk in response.iter_content(16384):
                        if not chunk:
                            continue
                        remaining = self.max_body - size
                        if remaining <= 0:
                            break
                        chunks.append(chunk[:remaining])
                        size += min(len(chunk), remaining)
                        if size >= self.max_body:
                            break
                    response._content = b"".join(chunks)
                    response._content_consumed = True
                except requests.RequestException:
                    response._content = b""
                    response._content_consumed = True
                return response, response.text[:self.max_body]
        except requests.RequestException as exc:
            result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            return None, ""

    def scan(self, raw_target: str) -> ScanResult:
        started = time.monotonic()
        target = normalize_target(raw_target)
        result = ScanResult(target=target, scanned_at=datetime.now(timezone.utc).isoformat())
        session = self._session()
        seen: set[str] = set()
        try:
            self._step(f"Getting homepage and HTTP response headers: {target}")
            response, body = self._get(session, target, result)
            if response is None and target.startswith("https://"):
                # Explicit fallback is useful for misconfigured TLS endpoints; no fallback unless opted in.
                result.errors.append("HTTPS request failed; HTTP fallback was not attempted. Supply an http:// target if appropriate.")
                return self._finish(result, started)
            if response is None:
                return self._finish(result, started)

            result.final_url = response.url
            result.http_status = response.status_code
            result.server_header = response.headers.get("Server", "")
            result.x_powered_by = response.headers.get("X-Powered-By", "")
            title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            result.title = re.sub(r"\s+", " ", html.unescape(title.group(1))).strip()[:200] if title else ""
            self._step("Inspecting Server and X-Powered-By headers for PHP/version disclosure...")
            self._header_indicators(result, response)
            self._step("Checking Set-Cookie headers for PHP and common framework session cookies...")
            self._cookie_indicators(result, response)
            self._step("Fingerprinting homepage HTML for PHP frameworks/CMS and .php references...")
            self._body_indicators(result, body, response.url)
            seen.add(response.url)

            # A deliberately small, fixed list of ordinary pages; not a wordlist/fuzzer.
            base = f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"
            self._step("Testing a small fixed list of common .php and CMS login paths...")
            for path in COMMON_PHP_PATHS:
                url = urljoin(base + "/", path.lstrip("/"))
                if url in seen:
                    continue
                seen.add(url)
                r, text_body = self._get(session, url, result)
                if r is None:
                    continue
                self._header_indicators(result, r)
                self._cookie_indicators(result, r)
                if path in DISCOVERY_PATHS:
                    self._step(f"Checking {path} for exposed PHP configuration output...")
                if path.lower().endswith(".php") and r.status_code not in (404, 410):
                    if r.status_code < 500 or r.status_code in (500, 503):
                        result.php_pages.append({"path": path, "status": r.status_code,
                                                 "content_type": r.headers.get("Content-Type", "")})
                        if path in DISCOVERY_PATHS and self._looks_like_phpinfo(text_body):
                            result.phpinfo.append({"path": path, "status": r.status_code,
                                                   "evidence": "PHP configuration output signature"})
                            self._add(result, "phpinfo", f"PHP configuration output signature at {path}", r.url, "high")
                self._body_indicators(result, text_body, r.url)
                if PHP_ERROR_RE.search(text_body):
                    result.php_error_signatures.append({"url": r.url, "status": r.status_code,
                                                        "signature": PHP_ERROR_RE.search(text_body).group(0)[:100]})
            # Randomized nonexistent PHP path to detect informative error templates.
            self._step("Checking a randomized nonexistent .php URL for PHP-specific error disclosure...")
            error_path = "/__php2shell_checker_" + uuid.uuid4().hex[:10] + ".php"
            r, text_body = self._get(session, urljoin(base + "/", error_path.lstrip("/")), result)
            if r is not None:
                self._body_indicators(result, text_body, r.url)
                match = PHP_ERROR_RE.search(text_body)
                if match:
                    result.php_error_signatures.append({"url": r.url, "status": r.status_code,
                                                        "signature": match.group(0)[:100]})
                    self._add(result, "php_error", f"PHP-like error signature: {match.group(0)[:80]}", r.url, "medium")
            self._step("Calculating evidence confidence and comparing any disclosed PHP version with configured thresholds...")
            versions = []
            for finding in result.indicators:
                v = finding.details.get("php_version")
                if v:
                    versions.append(v)
            result.php_version = versions[0] if versions else None
            result.version_assessment = assess_version(result.php_version)
            result.php_detected = bool(result.indicators or result.php_version)
            result.framework_cms = sorted({f.details["framework"] for f in result.indicators if "framework" in f.details})
            result.cookies = sorted({f.details["cookie"] for f in result.indicators if "cookie" in f.details})
            result.confidence_score = min(100, sum(self._weight(f) for f in result.indicators))
            result.confidence = confidence_label(result.confidence_score)
            if result.version_assessment.startswith("VULNERABLE VERSION"):
                result.assessment = "VULNERABLE VERSION DETECTED — disclosed PHP version is within the supplied affected range"
            elif result.version_assessment.startswith("NOT VULNERABLE BY VERSION"):
                result.assessment = "NOT VULNERABLE BY VERSION — disclosed PHP version meets the supplied fixed threshold"
            elif result.php_detected:
                result.assessment = "INCONCLUSIVE — PHP indicators found, but version-based status cannot be determined"
            else:
                result.assessment = "INCONCLUSIVE — no PHP indicators found; this does not prove PHP is absent"
            return self._finish(result, started)
        finally:
            session.close()

    def _finish(self, result: ScanResult, started: float) -> ScanResult:
        result.duration_seconds = round(time.monotonic() - started, 2)
        return result

    @staticmethod
    def _add(result: ScanResult, category: str, evidence: str, url: str = "",
             confidence: str = "low", details: dict[str, Any] | None = None) -> None:
        item = Finding(category, evidence, url, confidence, details or {})
        if item not in result.indicators:
            result.indicators.append(item)

    def _header_indicators(self, result: ScanResult, response: requests.Response) -> None:
        for header, value in response.headers.items():
            if header.lower() == "x-powered-by":
                m = VERSION_RE.search(value)
                if m:
                    version = m.group(1)
                    self._add(result, "php_version", f"{header}: {value}", response.url, "high", {"php_version": version})
                elif re.search(r"\bphp\b", value, re.I):
                    self._add(result, "php_header", f"{header}: {value}", response.url, "high")
            if header.lower() == "server" and re.search(r"\bphp\b", value, re.I):
                self._add(result, "php_server_header", f"{header}: {value}", response.url, "medium")

    def _cookie_indicators(self, result: ScanResult, response: requests.Response) -> None:
        try:
            cookies = response.headers.get("Set-Cookie", "")
            for cookie in response.raw.headers.getlist("Set-Cookie"):
                cookies += "; " + cookie
        except Exception:
            pass
        patterns = {
            "PHPSESSID": r"\bPHPSESSID\b",
            "Laravel": r"\blaravel_session\b",
            "CodeIgniter": r"\bci_session\b",
            "Symfony": r"\b(?:sf_session|symfony)\b",
        }
        for name, pattern in patterns.items():
            if re.search(pattern, cookies, re.I):
                self._add(result, "session_cookie", f"Session cookie indicator: {name}", response.url,
                          "medium" if name == "PHPSESSID" else "low", {"cookie": name})

    def _body_indicators(self, result: ScanResult, body: str, url: str) -> None:
        for framework, patterns in FRAMEWORKS.items():
            if any(p.search(body) for p in patterns):
                self._add(result, "framework", f"Possible {framework} indicator in page content", url,
                          "medium", {"framework": framework})
        if re.search(r"\.php(?:[?#\"'\s]|$)", body, re.I):
            self._add(result, "php_extension_reference", "HTML contains a .php URL/reference", url, "low")
        m = PHP_ERROR_RE.search(body)
        if m:
            self._add(result, "php_error", f"PHP-like error signature: {m.group(0)[:80]}", url, "medium")

    @staticmethod
    def _looks_like_phpinfo(body: str) -> bool:
        return bool(re.search(r"PHP Version\s+\d+\.\d+\.\d+", body, re.I) and
                    re.search(r"(?:phpinfo\(\)|Configuration|Loaded Configuration File)", body, re.I))

    @staticmethod
    def _weight(f: Finding) -> int:
        return {
            "php_version": 50, "phpinfo": 45, "php_header": 35, "php_server_header": 20,
            "session_cookie": 15, "php_extension_reference": 10, "php_error": 15,
            "framework": 10,
        }.get(f.category, 5)

def result_dict(result: ScanResult) -> dict[str, Any]:
    d = asdict(result)
    d["indicators"] = [asdict(x) for x in result.indicators]
    return d

def write_json(results: list[ScanResult], path: str) -> None:
    Path(path).write_text(json.dumps([result_dict(r) for r in results], indent=2), encoding="utf-8")

def write_csv(results: list[ScanResult], path: str) -> None:
    fields = ["target", "final_url", "http_status", "php_detected", "php_version",
              "version_assessment", "framework_cms", "cookies", "confidence_score",
              "confidence", "assessment", "requests_made", "duration_seconds", "errors"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            d = result_dict(r)
            for k in ("framework_cms", "cookies", "errors"):
                d[k] = "; ".join(d[k])
            writer.writerow({k: d.get(k, "") for k in fields})

def write_html(results: list[ScanResult], path: str) -> None:
    rows = []
    for r in results:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in [
            r.target, r.http_status, r.php_version or "Unknown", r.version_assessment,
            ", ".join(r.framework_cms) or "—", f"{r.confidence} ({r.confidence_score}/100)", r.assessment
        ]) + "</tr>")
    doc = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>PHP2Shell Checker Report</title>
<style>body{font:15px system-ui,sans-serif;margin:2rem;color:#182230}h1{margin-bottom:.2rem}
.note{color:#526174}table{border-collapse:collapse;width:100%;margin-top:1.5rem}
th,td{border:1px solid #d7dde5;padding:.65rem;text-align:left;vertical-align:top}
th{background:#edf2f7}tr:nth-child(even){background:#f8fafc}code{overflow-wrap:anywhere}</style></head><body>
<h1>PHP2Shell Checker</h1><p class="note">Passive PHP fingerprinting and version-based exposure assessment. This report does not prove exploitability.</p>
<p>Generated: """ + html.escape(datetime.now(timezone.utc).isoformat()) + """</p>
<table><thead><tr><th>Target</th><th>Status</th><th>PHP version</th><th>Version assessment</th><th>Framework/CMS</th><th>Confidence</th><th>Overall assessment</th></tr></thead><tbody>
""" + "".join(rows) + """</tbody></table><h2>Evidence</h2>"""
    for r in results:
        doc += f"<h3>{html.escape(r.target)}</h3><ul>"
        for f in r.indicators:
            doc += f"<li><b>{html.escape(f.category)}</b>: {html.escape(f.evidence)} — <code>{html.escape(f.url)}</code></li>"
        for e in r.errors:
            doc += f"<li>Error: {html.escape(e)}</li>"
        doc += "</ul>"
    doc += "</body></html>"
    Path(path).write_text(doc, encoding="utf-8")

def print_result(r: ScanResult, console: Any = None) -> None:
    if console:
        console.print(Panel.fit(f"[bold]{r.target}[/bold]\n"
            f"HTTP: {r.http_status} | PHP: {r.php_version or 'Unknown'}\n"
            f"Assessment: {r.assessment}\nConfidence: {r.confidence} ({r.confidence_score}/100)",
            title=TOOL_NAME))
        if r.indicators:
            table = Table("Type", "Evidence", "Confidence")
            for f in r.indicators:
                table.add_row(f.category, f.evidence, f.confidence)
            console.print(table)
        if r.errors:
            for e in r.errors:
                console.print(f"[yellow]Warning:[/yellow] {e}")
    else:
        print(f"\n[{r.assessment}] {r.target}")
        print(f"  HTTP={r.http_status} PHP={r.php_version or 'unknown'} confidence={r.confidence} ({r.confidence_score}/100)")
        for f in r.indicators:
            print(f"  - {f.category}: {f.evidence}")
        for e in r.errors:
            print(f"  ! {e}")

def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.targets or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    # Preserve order and remove duplicates.
    return list(dict.fromkeys(targets))


def print_banner(console: Any = None) -> None:
    art = r"""
  _____  _    _ _____ ___   _____ _    _ ______ _      _         _____ _    _ ______ _____ _  ________ _____  
 |  __ \| |  | |  __ \__ \ / ____| |  | |  ____| |    | |       / ____| |  | |  ____/ ____| |/ /  ____|  __ \ 
 | |__) | |__| | |__) | ) | (___ | |__| | |__  | |    | |      | |    | |__| | |__ | |    | ' /| |__  | |__) |
 |  ___/|  __  |  ___/ / / \___ \|  __  |  __| | |    | |      | |    |  __  |  __|| |    |  < |  __| |  _  / 
 | |    | |  | | |    / /_ ____) | |  | | |____| |____| |____  | |____| |  | | |___| |____| . \| |____| | \ \ 
 |_|    |_|  |_|_|   |____|_____/|_|  |_|______|______|______|  \_____|_|  |_|______\_____|_|\_\______|_|  \_\
                                                                                                                                                                                                                    
"""
    if console:
        console.print(f"[bold bright_cyan]{art}[/bold bright_cyan]")
        console.print("[bold bright_cyan]PHP2SHELL CHECKER[/bold bright_cyan] [dim]v" + VERSION + "[/dim]")
        console.print("[dim]made by er4pwn[/dim]")
        console.print("[dim]Passive HTTP fingerprinting • No exploitation • Authorized testing only[/dim]")
    else:
        print(art)
        print(f"PHP2SHELL CHECKER v{VERSION}")
        print("made by er4pwn")
        print("Passive HTTP fingerprinting • No exploitation • Authorized testing only")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Passive PHP fingerprinting and PHP2Shell version-based exposure checker.",
        epilog="Use only on systems you own or are authorized to assess.")
    parser.add_argument("targets", nargs="*", help="Target hostnames or HTTP(S) URLs")
    parser.add_argument("-i", "--input", help="File containing one target per line")
    parser.add_argument("-o", "--json", dest="json_out", help="Write JSON report")
    parser.add_argument("--csv", dest="csv_out", help="Write CSV report")
    parser.add_argument("--html", dest="html_out", help="Write HTML report")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Concurrent targets (default: 4)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout seconds")
    parser.add_argument("--delay", type=float, default=0.15, help="Delay between requests per worker seconds")
    parser.add_argument("--retries", type=int, default=1, help="Connection retries (default: 1)")
    parser.add_argument("--max-body", type=int, default=1_000_000, help="Maximum response body bytes to inspect")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    parser.add_argument("--rotate-user-agent", action="store_true", help="Rotate ordinary browser User-Agent strings")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (not recommended)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")
    try:
        targets = [normalize_target(t) for t in load_targets(args)]
    except (OSError, ValueError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        parser.error("Provide at least one target or use -i/--input")
    if args.workers < 1 or args.workers > 32:
        parser.error("--workers must be between 1 and 32")
    if args.timeout <= 0 or args.max_body < 1024:
        parser.error("--timeout must be positive and --max-body at least 1024")

    console = Console() if Console else None
    print_banner(console)

    scanner_args = dict(timeout=args.timeout, delay=args.delay, verify_tls=not args.no_verify_tls,
                        max_body=args.max_body, user_agent=args.user_agent,
                        rotate_ua=args.rotate_user_agent, proxy=args.proxy, retries=args.retries,
                        progress=True)
    results: list[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(Scanner(**scanner_args).scan, target): target for target in targets}
        if console:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
                          TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                          console=console) as progress:
                task = progress.add_task("Scanning targets", total=len(futures))
                for future in concurrent.futures.as_completed(futures):
                    try:
                        r = future.result()
                    except Exception as exc:
                        target = futures[future]
                        r = ScanResult(target=target, scanned_at=datetime.now(timezone.utc).isoformat(),
                                       errors=[f"Unhandled scan error: {type(exc).__name__}: {exc}"])
                    results.append(r)
                    progress.advance(task)
                    print_result(r, console)
        else:
            for future in concurrent.futures.as_completed(futures):
                try:
                    r = future.result()
                except Exception as exc:
                    target = futures[future]
                    r = ScanResult(target=target, scanned_at=datetime.now(timezone.utc).isoformat(),
                                   errors=[f"Unhandled scan error: {type(exc).__name__}: {exc}"])
                results.append(r)
                print_result(r)

    # Output reports in input order for easier comparison.
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.target, 999999))
    for fmt, path, writer in (("JSON", args.json_out, write_json),
                              ("CSV", args.csv_out, write_csv),
                              ("HTML", args.html_out, write_html)):
        if path:
            writer(results, path)
            print(f"[+] {fmt} report written: {path}")
    print(f"\nCompleted: {len(results)} target(s). No exploitation was attempted.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
