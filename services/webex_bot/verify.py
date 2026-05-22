"""WebEx webhook signature verification.

WebEx delivers every webhook with an HMAC-SHA1 of the raw body in
`X-Spark-Signature`. The bot computes the same HMAC with the configured
secret; a mismatch means the call did not come from WebEx (or the body
has been tampered with) and the request must be rejected.

Constant-time comparison avoids timing oracles.
"""

from __future__ import annotations

import hashlib
import hmac


def compute_signature(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()


def verify_signature(body: bytes, signature: str | None, secret: str) -> bool:
    if not signature or not secret:
        return False
    expected = compute_signature(body, secret)
    return hmac.compare_digest(expected, signature)
