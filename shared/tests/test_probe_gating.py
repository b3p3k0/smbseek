from shared.rce_scanner.probes import SafeProbeRunner
from shared.rce_scanner.verdicts import Verdict


class MockConfig:
    def get_rce_safe_budget(self):
        return {"max_requests": 2, "per_host_timeout_seconds": 5, "retry_count": 0, "jitter_ms": 0}

    def is_ms17_010_enabled(self):
        return True

    def is_intrusive_mode_enabled(self):
        return False


def test_ms17_010_blocked_without_legacy():
    runner = SafeProbeRunner(MockConfig(), legacy_mode=False)
    result = runner.run_ms17_010_probe("192.0.2.1")
    assert result["verdict"] == Verdict.NOT_ASSESSABLE
    assert "requires --legacy" in result.get("reason", "")


def test_smb1_probe_blocked_without_legacy():
    runner = SafeProbeRunner(MockConfig(), legacy_mode=False)
    result = runner.run_negotiate_probe("192.0.2.1")
    assert result.get("smb1_possible", False) is False
