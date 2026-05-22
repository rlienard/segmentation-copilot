"""Pluggable threat-intelligence layer.

Production deployments wire any subset of:

  - AbuseIPDB   (primary; free tier 1000 lookups/day)
  - AlienVault OTX
  - VirusTotal  (strict free-tier rate limit, hence the per-call timeout)
  - Cisco Talos (best-effort; opt-in, no free official API)

Each implements `ThreatIntelClient`. `ThreatAggregator` runs them in
parallel with a per-call timeout, normalises scores, and applies the
multi-source decision policy.
"""

from .aggregator import ThreatAggregator, ThreatDecision
from .base import ThreatIntelClient, ThreatVerdict
from .cache import ThreatLookupRepository, ThreatVerdictCache

__all__ = [
    "ThreatAggregator",
    "ThreatDecision",
    "ThreatIntelClient",
    "ThreatLookupRepository",
    "ThreatVerdict",
    "ThreatVerdictCache",
]
