"""Real-time threat daemon — reactive autonomy.

Tails the syslog stream, runs every observed destination IP through the
pluggable threat-intel layer, and on a malicious verdict publishes
`events.flow.unknown` with `trigger="threat"` so the same Phase-4
worker pipeline classifies the flow and turns it into a rule proposal.
"""
