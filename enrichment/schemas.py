"""What every threat-intel provider lookup produces — the boundary type
between real external evidence (enrichment/providers.py) and everything
downstream (agent prompts, state, the vault report).
"""

from typing import Optional

from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    indicator: str = Field(max_length=300)
    indicator_type: str  # "ip" | "domain" | "hash" | "url" | "cve"
    # "abuseipdb" | "virustotal" | "shodan" | "alienvault_otx" |
    # "greynoise" | "malwarebazaar" | "threatfox" | "urlhaus" |
    # "ibm_xforce" | "metadefender" | "censys" | "pulsedive" |
    # "threatminer" | "hybrid_analysis" | "intezer" | "urlscan" |
    # "google_safebrowsing" | "securitytrails" | "blocklistde" | "nvd"
    source: str
    # "malicious" | "suspicious" | "harmless" | "unknown" | "error" — for
    # shodan/censys specifically this describes exposed-service *risk*,
    # not actor reputation: "suspicious"/"harmless" describe what's
    # exposed, not whether the IP itself is a known attacker. NVD
    # overloads it the same way: it's the underlying CVE's *severity*,
    # not "is this indicator malicious." securitytrails and urlscan have
    # no malicious/clean signal at all and always return "unknown" —
    # informational providers, not a missing verdict.
    verdict: str
    detail: str = Field(max_length=1000)
    link: Optional[str] = None
