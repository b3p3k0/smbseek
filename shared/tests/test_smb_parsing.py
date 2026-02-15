import pytest

from shared.rce_scanner.probes import SafeProbeRunner
from shared.rce_scanner.verdicts import Verdict
from shared.tests.fixtures.smb_responses import (
    SMB2_NEGOTIATE_WITH_COMPRESSION,
    SMB2_TRUNCATED,
    SMB2_INVALID_SIGNATURE,
    MS17_010_VULNERABLE_STATUS,
    MS17_010_PATCHED_ACCESS_DENIED,
    MS17_010_PATCHED_INVALID_HANDLE,
)


class MockConfig:
    def get_rce_safe_budget(self):
        return {"max_requests": 3, "per_host_timeout_seconds": 5, "retry_count": 0, "jitter_ms": 0}

    def is_ms17_010_enabled(self):
        return True

    def is_intrusive_mode_enabled(self):
        return False


class TestSMBParsing:
    def test_parse_smb2_negotiate_dialect(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=False)
        result = runner._parse_smb2_negotiate_response(SMB2_NEGOTIATE_WITH_COMPRESSION)
        assert result["smb_dialect"] == 0x0311
        assert result["signing_required"] is True

    def test_parse_truncated_response_graceful(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=False)
        result = runner._parse_smb2_negotiate_response(SMB2_TRUNCATED)
        assert result["smb_dialect"] is None

    def test_parse_invalid_signature(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=False)
        result = runner._parse_smb2_negotiate_response(SMB2_INVALID_SIGNATURE)
        assert result["smb_dialect"] is None

    def test_parse_compression_context(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=False)
        result = runner._parse_smb2_negotiate_response(SMB2_NEGOTIATE_WITH_COMPRESSION)
        assert len(result["compression_algos"]) > 0


class TestMS17010Classification:
    def test_classify_vulnerable_status(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=True)
        result = runner._classify_ms17_010_status(MS17_010_VULNERABLE_STATUS)
        assert result["verdict"] == Verdict.CONFIRMED

    def test_classify_patched_access_denied(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=True)
        result = runner._classify_ms17_010_status(MS17_010_PATCHED_ACCESS_DENIED)
        assert result["verdict"] == Verdict.NOT_VULNERABLE

    def test_classify_patched_invalid_handle(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=True)
        result = runner._classify_ms17_010_status(MS17_010_PATCHED_INVALID_HANDLE)
        assert result["verdict"] == Verdict.NOT_VULNERABLE

    def test_classify_none_insufficient_data(self):
        runner = SafeProbeRunner(MockConfig(), legacy_mode=True)
        result = runner._classify_ms17_010_status(None)
        assert result["verdict"] == Verdict.INSUFFICIENT_DATA
