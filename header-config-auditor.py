import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Dict, List
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections and prevents SSL stripping.",
    "Content-Security-Policy": "Restricts sources of content (scripts, styles, images) to mitigate XSS.",
    "X-Frame-Options": "Prevents clickjacking by restricting frame/iframe embedding.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (should be set to 'nosniff').",
    "Referrer-Policy": "Controls how much referrer information is sent with requests.",
    "Permissions-Policy": "Restricts access to browser features (camera, microphone, geolocation).",
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


@dataclass
class HeaderCheckResult:
    url: str
    status_code: int
    present_headers: Dict[str, str]
    missing_headers: Dict[str, str]
    leaked_info: Dict[str, str]
    cookie_warnings: List[str]


def audit_headers(url: str, timeout: float = 8.0) -> HeaderCheckResult:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "HeaderAuditor/1.0"},
    )

    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    present = {}
    missing = {}

    for header, description in SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            present[header] = response.headers[header]
        else:
            missing[header] = description

    leaks = {}
    for leak_header in LEAK_HEADERS:
        if leak_header.lower() in headers_lower:
            leaks[leak_header] = response.headers[leak_header]

    cookie_warnings = []
    if "Set-Cookie" in response.headers:
        for cookie in response.cookies:
            if not cookie.secure:
                cookie_warnings.append(
                    f"Cookie '{cookie.name}' is missing the 'Secure' flag."
                )
            if not getattr(cookie, "httponly", False):
                cookie_warnings.append(
                    f"Cookie '{cookie.name}' is missing the 'HttpOnly' flag."
                )

    return HeaderCheckResult(
        url=response.url,
        status_code=response.status_code,
        present_headers=present,
        missing_headers=missing,
        leaked_info=leaks,
        cookie_warnings=cookie_warnings,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HTTP Security Header & Configuration Auditor"
    )
    parser.add_argument(
        "-u", "--url", required=True, help="Target URL to audit"
    )
    parser.add_argument(
        "--json", dest="json_file", help="Save audit results to a JSON file"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="HTTP request timeout in seconds",
    )

    args = parser.parse_args()

    try:
        result = audit_headers(args.url, timeout=args.timeout)
    except Exception as exc:
        print(f"[!] Audit failed: {exc}", file=sys.stderr)
        return 1

    print()
    print("=== Security Header Audit Report ===")
    print(f"Target URL  : {result.url}")
    print(f"Status Code : {result.status_code}")
    print()

    print("--- Present Security Headers ---")
    if result.present_headers:
        for k, v in result.present_headers.items():
            print(f"[+] {k}: {v}")
    else:
        print("[-] None detected.")

    print()
    print("--- Missing Security Headers ---")
    if result.missing_headers:
        for k, desc in result.missing_headers.items():
            print(f"[-] {k} -> {desc}")
    else:
        print("[+] All core security headers are present.")

    print()
    print("--- Information Disclosure Leaks ---")
    if result.leaked_info:
        for k, v in result.leaked_info.items():
            print(f"[!] Warning: Header '{k}' exposes technology stack: {v}")
    else:
        print("[+] No obvious technology disclosure headers found.")

    if result.cookie_warnings:
        print()
        print("--- Cookie Security Warnings ---")
        for warning in result.cookie_warnings:
            print(f"[!] {warning}")

    print()

    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as output:
            json.dump(asdict(result), output, indent=2)
        print(f"Results saved to {args.json_file}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
