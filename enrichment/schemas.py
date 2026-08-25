"""What every threat-intel provider lookup produces — the boundary type
between real external evidence (enrichment/providers.py) and everything
downstream (agent prompts, state, the vault report).
"""

from typing import Optional

from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    indicator: str = Field(max_length=300)
    indicator_type: str  # "ip" | "domain" | "hash" | "url"
    # "abuseipdb" | "virustotal" | "shodan" | "alienvault_otx" |
    # "greynoise" | "malwarebazaar" | "threatfox" | "urlhaus" |
    # "ibm_xforce" | "metadefender" | "censys"
    source: str
    # "malicious" | "suspicious" | "harmless" | "unknown" | "error" — for
    # shodan/censys specifically this describes exposed-service *risk*,
    # not actor reputation: "suspicious"/"harmless" describe what's
    # exposed, not whether the IP itself is a known attacker.
    verdict: str
    detail: str = Field(max_length=1000)
    link: Optional[str] = None
