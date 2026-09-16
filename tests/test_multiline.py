"""
Tests for Multiline Log Assembly and Boundary Detection.
"""

from core.multiline import MultilineAssembler


def test_multiline_java_exception_stitching():
    assembler = MultilineAssembler()
    lines = [
        "2026-09-16 11:15:02,401 ERROR [auth-service] AuthenticationFailedException: Invalid JWT",
        "    at org.ntro.auth.TokenValidator.verify(TokenValidator.java:142)",
        "    at org.ntro.auth.SecurityFilter.doFilter(SecurityFilter.java:88)",
        "    Caused by: java.security.SignatureException: Signature length not correct",
        "    ... 24 more",
        "2026-09-16 11:15:03,000 INFO [audit] Next regular event arrived"
    ]

    records = list(assembler.process_stream(lines))
    assert len(records) == 2

    # Record 1 must contain all 5 lines stitched with newlines
    assert "AuthenticationFailedException" in records[0]
    assert "TokenValidator.java:142" in records[0]
    assert "Caused by: java.security.SignatureException" in records[0]
    assert "24 more" in records[0]

    # Record 2 is the next standalone event
    assert "Next regular event arrived" in records[1]

