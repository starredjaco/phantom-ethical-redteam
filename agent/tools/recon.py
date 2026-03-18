"""Passive subdomain reconnaissance — multi-source, with retry."""

import logging
from .scope_checker import scope_guard
from .http_utils import retry_request

logger = logging.getLogger(__name__)


def _fetch_crtsh(domain: str) -> set:
    r = retry_request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
    return {entry["name_value"].lower() for entry in r.json()}


def _fetch_hackertarget(domain: str) -> set:
    r = retry_request(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
    subs = set()
    for line in r.text.strip().splitlines():
        if "," in line:
            subs.add(line.split(",")[0].lower().strip())
    return subs


_SOURCES = {
    "crt.sh": _fetch_crtsh,
    "hackertarget": _fetch_hackertarget,
}


def run(domain: str) -> str:
    guard = scope_guard(domain)
    if guard:
        return guard

    all_subs: set = set()
    source_results = []

    for name, fetcher in _SOURCES.items():
        try:
            subs = fetcher(domain)
            all_subs |= subs
            source_results.append(f"{name}({len(subs)})")
            logger.info("Recon %s: %d subdomains for %s", name, len(subs), domain)
        except Exception as e:
            source_results.append(f"{name}(failed)")
            logger.warning("Recon %s failed for %s: %s", name, domain, e)

    if not all_subs:
        return f"Recon failed on all sources: {', '.join(source_results)}"

    sorted_subs = sorted(all_subs)
    summary = f"{len(all_subs)} unique subdomains [{', '.join(source_results)}]:\n"
    summary += "\n".join(f"  {s}" for s in sorted_subs[:25])
    if len(sorted_subs) > 25:
        summary += f"\n  ... +{len(sorted_subs) - 25} more"
    return summary


TOOL_SPEC = {
    "name": "run_recon",
    "description": "Passive subdomain reconnaissance \u2014 crt.sh + HackerTarget (multi-source, deduped, with retry)",
    "input_schema": {
        "type": "object",
        "properties": {"domain": {"type": "string"}},
        "required": ["domain"],
    },
}
