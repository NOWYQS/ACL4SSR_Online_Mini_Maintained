#!/usr/bin/env python3
"""Convert Loyalsoldier Clash rule-provider payloads to classic ACL4SSR lists."""
from __future__ import annotations

import ast
import ipaddress
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "generated"
UPSTREAM_BASE = "https://github.com/Loyalsoldier/clash-rules/releases/latest/download"

# These are the categories used by the maintained Mini template.  The source
# files are provider YAML payloads; the generated files are classic Clash list
# rules so SubConverter's ruleset= syntax can consume them.
FULL_ASSETS = {
    "private": ("private.txt", "domain"),
    "reject": ("reject.txt", "domain"),
    "applications": ("applications.txt", "classic"),
    "proxy": ("proxy.txt", "domain"),
    "direct": ("direct.txt", "domain"),
    "gfw": ("gfw.txt", "domain"),
    "tld-not-cn": ("tld-not-cn.txt", "domain"),
    "lancidr": ("lancidr.txt", "cidr"),
    "cncidr": ("cncidr.txt", "cidr"),
    "telegramcidr": ("telegramcidr.txt", "cidr"),
}

# Lite intentionally omits the very large reject, direct, and proxy domain
# payloads.  FINAL is routed to DIRECT in the Lite INI, so these focused proxy
# categories act as a blacklist-style supplement instead of a full split list.
LITE_ASSETS = {
    "private": ("private.txt", "domain"),
    "applications": ("applications.txt", "classic"),
    "gfw": ("gfw.txt", "domain"),
    "tld-not-cn": ("tld-not-cn.txt", "domain"),
    "lancidr": ("lancidr.txt", "cidr"),
    "cncidr": ("cncidr.txt", "cidr"),
    "telegramcidr": ("telegramcidr.txt", "cidr"),
}

PROFILES = {
    "generated": FULL_ASSETS,
    "generated/lite": LITE_ASSETS,
}

VALID_PREFIXES = (
    "DOMAIN,",
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "IP-CIDR,",
    "IP-CIDR6,",
    "PROCESS-NAME,",
    "DST-PORT,",
    "SRC-PORT,",
)


def fetch(url: str, attempts: int = 3) -> bytes:
    """Fetch a public upstream asset with a small bounded retry."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = Request(
                url,
                headers={
                    "Accept": "application/octet-stream",
                    "User-Agent": "ACL4SSR-Online-Mini-Maintained/1.0",
                },
            )
            with urlopen(request, timeout=180) as response:
                data = response.read()
            if not data:
                raise RuntimeError(f"empty response from {url}")
            return data
        except (HTTPError, URLError, TimeoutError, RuntimeError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_error}") from last_error


def parse_payload(data: bytes) -> list[str]:
    """Extract scalar entries from the simple `payload:` YAML used upstream."""
    text = data.decode("utf-8")
    in_payload = False
    values: list[str] = []
    for line in text.splitlines():
        if line.strip() == "payload:":
            in_payload = True
            continue
        if not in_payload:
            continue
        match = re.match(r"^\s*-\s+(.*)\s*$", line)
        if not match:
            continue
        raw = match.group(1).strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            value = ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            value = raw
        if not isinstance(value, (str, int, float)):
            raise ValueError(f"unsupported provider value: {raw!r}")
        values.append(str(value))
    if not values:
        raise ValueError("provider payload contains no entries")
    return values


def domain_rule(value: str) -> str:
    value = value.strip()
    # Loyalsoldier uses +.domain to mean domain suffix.  Convert both that
    # notation and the common *.domain spelling to Clash classical syntax.
    for prefix in ("+.", "*.", "||"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    value = value.lstrip(".")
    if not value or any(char in value for char in "\t\r\n ,/"):
        raise ValueError(f"invalid domain value: {value!r}")
    return f"DOMAIN-SUFFIX,{value}"


def cidr_rule(value: str) -> str:
    network = ipaddress.ip_network(value.strip(), strict=False)
    prefix = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
    return f"{prefix},{network.with_prefixlen},no-resolve"


def convert_entries(values: list[str], kind: str) -> list[str]:
    converted: list[str] = []
    seen: set[str] = set()
    for value in values:
        if kind == "domain":
            rule = domain_rule(value)
        elif kind == "cidr":
            rule = cidr_rule(value)
        elif kind == "classic":
            rule = value.strip()
            if not rule or rule.startswith("#"):
                continue
            if not rule.startswith(VALID_PREFIXES):
                raise ValueError(f"unsupported classic rule: {rule!r}")
        else:
            raise ValueError(f"unknown conversion kind: {kind}")
        if rule not in seen:
            seen.add(rule)
            converted.append(rule)
    if not converted:
        raise ValueError(f"conversion produced no rules for {kind}")
    return converted


def render(asset: str, rules: list[str]) -> str:
    source = f"{UPSTREAM_BASE}/{asset}"
    lines = [
        "# Generated by ACL4SSR_Online_Mini_Maintained.",
        f"# Source: {source}",
        "# Provider payload converted to classic Clash/SubConverter rules.",
        f"# Entries: {len(rules)}",
        "",
        *rules,
        "",
    ]
    return "\n".join(lines)


def validate_file(path: Path) -> int:
    rules = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("payload:") or line.startswith("- "):
            raise ValueError(f"{path}: provider YAML leaked into classic list")
        if not line.startswith(VALID_PREFIXES):
            raise ValueError(f"{path}: unsupported generated rule: {line!r}")
        rules.append(line)
    if not rules:
        raise ValueError(f"{path}: no generated rules")
    if len(rules) != len(set(rules)):
        raise ValueError(f"{path}: duplicate generated rules")
    return len(rules)


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    changed = 0
    for output_relative, assets in PROFILES.items():
        profile_dir = ROOT / output_relative
        profile_dir.mkdir(parents=True, exist_ok=True)
        for output_name, (asset, kind) in assets.items():
            data = fetch(f"{UPSTREAM_BASE}/{asset}")
            rules = convert_entries(parse_payload(data), kind)
            path = profile_dir / f"{output_name}.list"
            content = render(asset, rules)
            old = path.read_text(encoding="utf-8") if path.exists() else None
            if old != content:
                path.write_text(content, encoding="utf-8")
                changed += 1
            print(f"{path.relative_to(ROOT)}: {len(rules)} rules")

    for path in sorted(OUTPUT_DIR.rglob("*.list")):
        validate_file(path)
    print(f"changed_files={changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
