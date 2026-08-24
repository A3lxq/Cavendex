"""What every alert-source normalizer produces.

The whole point of the ingestion layer is that agents/schemas.py, the
graph, and the vault never need to know anything about Suricata, syslog,
or whatever SIEM you're pointing at SentinelOS — every source normalizer
in ingestion/normalizers.py converts its own vendor format into one of
these, and everything downstream (ingestion/pipeline.py onward) only
ever deals with NormalizedAlert.
"""

from typing import List, Optional

from pydantic import BaseModel, Field

from state import ShortStr, Severity


class NormalizedAlert(BaseModel):
    description: str = Field(max_length=4000)
    severity: Severity = "medium"
    source: ShortStr
    affected_assets: List[ShortStr] = Field(default_factory=list, max_length=50)
    iocs: List[ShortStr] = Field(default_factory=list, max_length=50)
    # Stable key for deduplication — e.g. "signature:src_ip" for a NIDS
    # alert. Two alerts with the same dedup_key within the dedup window
    # are treated as the same ongoing thing, not two new incidents.
    dedup_key: str = Field(max_length=300)
    # A short, bounded excerpt of the raw event for traceability — not the
    # full raw payload, which could be arbitrarily large/nested.
    raw_excerpt: Optional[str] = Field(default=None, max_length=2000)
