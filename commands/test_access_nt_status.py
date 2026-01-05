import types

from commands.access import AccessOperation


class DummyOutput:
    """Minimal output stub to satisfy AccessOperation dependencies."""

    verbose = False

    def print_if_verbose(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def success(self, *args, **kwargs):
        pass

    def header(self, *args, **kwargs):
        pass

    def subheader(self, *args, **kwargs):
        pass

    def print_if_not_quiet(self, *args, **kwargs):
        pass


class DummyConfig:
    def get_connection_timeout(self):
        return 1

    def get_share_access_delay(self):
        return 0


class DummyDB:
    pass


class AccessOperationStub(AccessOperation):
    """Override helpers that would touch the system."""

    def check_smbclient_availability(self):
        return False


def _fake_result(returncode, stdout="", stderr=""):
    return types.SimpleNamespace(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_share_access_sets_auth_status_on_nt_status(monkeypatch):
    """Ensure NT_STATUS parsing uses the class helper instead of raising NameError."""
    op = AccessOperationStub(DummyConfig(), DummyOutput(), DummyDB(), session_id="test")

    fake = _fake_result(
        1,
        stdout="",
        stderr="NT_STATUS_ACCESS_DENIED tree connect failed",
    )
    op._execute_with_fallback = lambda *args, **kwargs: fake

    result = op.test_share_access("1.2.3.4", "MUZIKA", "user", "pass")

    assert result["auth_status"] == "NT_STATUS_ACCESS_DENIED"
    assert result["accessible"] is False
    assert "NT_STATUS_ACCESS_DENIED" in result["error"]
