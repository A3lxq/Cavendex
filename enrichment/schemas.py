"""What every threat-intel provider lookup produces — the boundary type
between real external evidence (enrichment/providers.py) and everything
downstream (agent prompts, state, the vault report).
"""

from typing import Optional

from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    indicator: str = Field(max_length=300)
    indicator_type: str  # "ip" | "domain" | "hash"
    source: str  # "abuseipdb" | "virustotal" | "shodan"
    # "malicious" | "suspicious" | "harmless" | "unknown" | "error" — for
    # shodan specifically this describes exposed-service *risk*, not
    # actor reputation: "suspicious" means a known CVE was found on an
    # exposed service, not that the IP itself is a known attacker.
    verdict: str
    detail: str = Field(max_length=1000)
    link: Optional[str] = None
