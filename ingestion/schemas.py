"""What every alert-source normalizer produces.

The whole point of the ingestion layer is that agents/schemas.py, the
graph, and the vault never need to know anything about Suricata, syslog,
or whatever SIEM you're pointing at Cavendex — every source normalizer
in ingestion/normalizers.py converts its own vendor format into one of
these, and everything downstream (ingestion/pipeline.py onward) only
ever deals with NormalizedAlert.
"""

from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

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

    # EDR-native indicators — process/command-line/parent-process context a
    # normalizer can supply when its source alert actually carries it (e.g.
    # Elastic Security, CrowdStrike, or any Sysmon-derived detection). A raw
    # process name or command line can't be reliably told apart from
    # arbitrary text the way an IP/domain/hash/CVE can (see
    # enrichment/ioc_classifier.py) — so these are explicit, normalizer-
    # supplied fields, not something inferred from a bare string. Folded
    # into `iocs` below with an unambiguous prefix at construction time,
    # so every existing consumer of NormalizedAlert.iocs/Incident.iocs
    # (correlation's exact-match tier, the dashboard's Strand Map, the
    # vault report) picks these up automatically with zero further changes
    # — they already treat it as a flat list of opaque strings.
    process_name: Optional[ShortStr] = None
    command_line: Optional[ShortStr] = None
    parent_process_name: Optional[ShortStr] = None

    @model_validator(mode="after")
    def _fold_process_context_into_iocs(self) -> "NormalizedAlert":
        extra = []
        if self.process_name:
            extra.append(f"process:{self.process_name}")
        if self.command_line:
            extra.append(f"cmdline:{self.command_line}")
        if self.parent_process_name:
            extra.append(f"parent:{self.parent_process_name}")
        if extra:
            # De-dup and re-apply the same 50-entry cap iocs itself carries
            # — folding these in must never silently let the list grow past
            # what the rest of the system already assumes is the ceiling.
            self.iocs = list(dict.fromkeys(list(self.iocs) + extra))[:50]
        return self
